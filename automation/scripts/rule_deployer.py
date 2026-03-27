#!/usr/bin/env python3
"""
rule_deployer.py
================
Deploy Sigma rules to Elastic Security via the Kibana Detection Engine API.
Converts Sigma YAML to Elastic KQL/EQL rules and pushes them to the SIEM.

Author: Chandra Sekhar Chakraborty
Project: Enterprise Detection Engineering Lab
References:
  - https://www.elastic.co/guide/en/security/current/rules-api-create.html
  - https://github.com/SigmaHQ/sigma
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from pathlib import Path
from typing import Optional

import requests
import yaml


# ─────────────────────────────────────────────────────────────────────────────
# Logging configuration
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("automation/reports/deploy_log.txt"),
    ],
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_SIGMA_DIR = Path("detection-rules/sigma")
DEFAULT_KQL_DIR   = Path("detection-rules/kql")


class ElasticRuleDeployer:
    """Deploy detection rules to an Elastic Security instance."""

    def __init__(self, kibana_url: str, api_key: str):
        """
        Args:
            kibana_url: Base URL of the Kibana instance
                        e.g. https://my-kibana.example.com:5601
            api_key: Elastic API key with Security rules write permission.
                     Format: <id>:<api_key> (base64 encoded internally)
        """
        self.kibana_url = kibana_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"ApiKey {api_key}",
                "Content-Type": "application/json",
                "kbn-xsrf": "true",
            }
        )
        self.rules_endpoint = (
            f"{self.kibana_url}/api/detection_engine/rules"
        )

    # ── Rule Conversion ───────────────────────────────────────────────────────

    def sigma_to_kql(self, sigma_file: Path) -> Optional[str]:
        """
        Convert a Sigma rule file to KQL using sigma-cli.

        Requires: pip install sigma-cli pysigma-backend-elasticsearch
        """
        try:
            result = subprocess.run(
                [
                    "sigma", "convert",
                    "-t", "lucene",
                    "-p", "ecs_windows",
                    str(sigma_file),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            log.warning(
                "sigma-cli conversion failed for %s: %s",
                sigma_file.name, result.stderr
            )
            return None
        except FileNotFoundError:
            log.warning(
                "sigma-cli not found. Install with: pip install sigma-cli"
            )
            return None

    def load_sigma_metadata(self, sigma_file: Path) -> dict:
        """Load Sigma rule YAML and extract metadata for the Elastic rule."""
        with open(sigma_file) as f:
            data = yaml.safe_load(f)

        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "low",
        }
        tags = data.get("tags", [])

        return {
            "name": data.get("title", sigma_file.stem),
            "description": data.get("description", "").strip(),
            "severity": severity_map.get(
                data.get("level", "medium"), "medium"
            ),
            "tags": tags,
            "rule_id": data.get("id", ""),
            "references": data.get("references", []),
            "false_positives": data.get("falsepositives", []),
            "author": data.get("author", "Unknown"),
        }

    # ── Elastic API ───────────────────────────────────────────────────────────

    def build_elastic_rule(
        self,
        metadata: dict,
        kql_query: str,
        index_patterns: list[str] | None = None,
    ) -> dict:
        """Build an Elastic Security rule payload from Sigma metadata."""
        if index_patterns is None:
            index_patterns = [
                "logs-endpoint.events.*",
                "winlogbeat-*",
                "logs-windows.*",
            ]

        return {
            "type": "query",
            "language": "kuery",
            "query": kql_query,
            "index": index_patterns,
            "name": metadata["name"],
            "description": metadata["description"],
            "severity": metadata["severity"],
            "risk_score": self._severity_to_risk(metadata["severity"]),
            "tags": metadata["tags"],
            "rule_id": metadata["rule_id"],
            "references": metadata["references"],
            "false_positives": metadata["false_positives"],
            "author": [metadata["author"]],
            "enabled": True,
            "interval": "5m",
            "from": "now-6m",
            "max_signals": 100,
        }

    def _severity_to_risk(self, severity: str) -> int:
        return {"critical": 99, "high": 73, "medium": 47, "low": 21}.get(
            severity, 47
        )

    def deploy_rule(self, rule_payload: dict) -> bool:
        """Push a single rule to Elastic Security API."""
        try:
            response = self.session.post(
                self.rules_endpoint, json=rule_payload, timeout=30
            )
            if response.status_code in (200, 201):
                log.info("✅ Deployed rule: %s", rule_payload["name"])
                return True
            elif response.status_code == 409:
                log.info(
                    "⚠️  Rule already exists (updating): %s", rule_payload["name"]
                )
                return self.update_rule(rule_payload)
            else:
                log.error(
                    "❌ Failed to deploy %s: HTTP %d – %s",
                    rule_payload["name"],
                    response.status_code,
                    response.text[:200],
                )
                return False
        except requests.RequestException as exc:
            log.error("Connection error deploying %s: %s", rule_payload["name"], exc)
            return False

    def update_rule(self, rule_payload: dict) -> bool:
        """Update an existing rule using PUT."""
        try:
            response = self.session.put(
                self.rules_endpoint, json=rule_payload, timeout=30
            )
            if response.status_code == 200:
                log.info("✅ Updated rule: %s", rule_payload["name"])
                return True
            log.error(
                "❌ Update failed for %s: %s", rule_payload["name"], response.text[:200]
            )
            return False
        except requests.RequestException as exc:
            log.error("Connection error updating rule: %s", exc)
            return False

    # ── Batch Deployment ──────────────────────────────────────────────────────

    def deploy_all(self, sigma_dir: Path) -> dict:
        """Deploy all Sigma rules from a directory."""
        sigma_files = list(sigma_dir.glob("*.yml"))
        if not sigma_files:
            log.warning("No .yml Sigma rules found in %s", sigma_dir)
            return {"deployed": 0, "failed": 0, "skipped": 0}

        results = {"deployed": 0, "failed": 0, "skipped": 0}
        log.info("Starting deployment of %d rules from %s", len(sigma_files), sigma_dir)

        for sigma_file in sorted(sigma_files):
            log.info("Processing: %s", sigma_file.name)
            metadata = self.load_sigma_metadata(sigma_file)
            kql_file = DEFAULT_KQL_DIR / f"{sigma_file.stem}.kql"

            if kql_file.exists():
                kql_query = kql_file.read_text().strip()
                # Strip comments (lines starting with //)
                kql_lines = [l for l in kql_query.splitlines() if not l.startswith("//")]
                kql_query = "\n".join(kql_lines).strip()
            else:
                kql_query = self.sigma_to_kql(sigma_file)

            if not kql_query:
                log.warning("Skipping %s — no KQL available", sigma_file.name)
                results["skipped"] += 1
                continue

            payload = self.build_elastic_rule(metadata, kql_query)
            if self.deploy_rule(payload):
                results["deployed"] += 1
            else:
                results["failed"] += 1

        log.info(
            "Deployment complete: %d deployed, %d failed, %d skipped",
            results["deployed"], results["failed"], results["skipped"],
        )
        return results


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Deploy Sigma detection rules to Elastic Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rule_deployer.py --kibana-url https://localhost:5601 --api-key <id>:<key>
  python rule_deployer.py --kibana-url https://localhost:5601 --api-key <id>:<key> \\
    --sigma-dir detection-rules/sigma
        """,
    )
    parser.add_argument("--kibana-url", required=True, help="Kibana base URL")
    parser.add_argument(
        "--api-key",
        default=os.getenv("ELASTIC_API_KEY"),
        help="Elastic API key (or set ELASTIC_API_KEY env var)",
    )
    parser.add_argument(
        "--sigma-dir",
        type=Path,
        default=DEFAULT_SIGMA_DIR,
        help=f"Directory containing Sigma rules (default: {DEFAULT_SIGMA_DIR})",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.api_key:
        log.error("API key required. Use --api-key or set ELASTIC_API_KEY env var.")
        sys.exit(1)

    deployer = ElasticRuleDeployer(args.kibana_url, args.api_key)
    results = deployer.deploy_all(args.sigma_dir)

    if results["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
