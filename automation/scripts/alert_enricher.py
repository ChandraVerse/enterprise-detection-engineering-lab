#!/usr/bin/env python3
"""
alert_enricher.py
=================
Ingest Elastic SIEM alerts and enrich Indicators of Compromise (IOCs)
via VirusTotal, AbuseIPDB, and Shodan APIs. Outputs enriched JSON
artifacts for downstream NIST 800-61 incident response reporting.

Author: Chandra Sekhar Chakraborty
Project: Enterprise Detection Engineering Lab
References:
  - https://developers.virustotal.com/reference/overview
  - https://docs.abuseipdb.com/
  - https://developer.shodan.io/api
"""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

REPORTS_DIR = Path("automation/reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# IOC Enrichment Clients
# ─────────────────────────────────────────────────────────────────────────────

class VirusTotalClient:
    """Query VirusTotal v3 API for file hashes, IPs, and domains."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key})

    def lookup_ip(self, ip: str) -> dict:
        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        return self._get(url, f"VT IP {ip}")

    def lookup_hash(self, file_hash: str) -> dict:
        url = f"{self.BASE_URL}/files/{file_hash}"
        return self._get(url, f"VT hash {file_hash}")

    def lookup_domain(self, domain: str) -> dict:
        url = f"{self.BASE_URL}/domains/{domain}"
        return self._get(url, f"VT domain {domain}")

    def _get(self, url: str, label: str) -> dict:
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "source": "VirusTotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation", "N/A"),
                    "country": data.get("country", "N/A"),
                    "as_owner": data.get("as_owner", "N/A"),
                    "tags": data.get("tags", []),
                    "verdict": "MALICIOUS" if stats.get("malicious", 0) >= 5 else "CLEAN",
                }
            elif resp.status_code == 404:
                return {"source": "VirusTotal", "verdict": "NOT_FOUND"}
            else:
                log.warning("VT %s returned HTTP %d", label, resp.status_code)
                return {"source": "VirusTotal", "verdict": "ERROR", "status_code": resp.status_code}
        except requests.RequestException as e:
            log.error("VT request error for %s: %s", label, e)
            return {"source": "VirusTotal", "verdict": "ERROR", "error": str(e)}


class AbuseIPDBClient:
    """Query AbuseIPDB for IP reputation and abuse reports."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers.update(
            {"Key": api_key, "Accept": "application/json"}
        )

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/check",
                params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True},
                timeout=15,
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                return {
                    "source": "AbuseIPDB",
                    "ip": d.get("ipAddress"),
                    "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "domain": d.get("domain"),
                    "total_reports": d.get("totalReports", 0),
                    "is_whitelisted": d.get("isWhitelisted", False),
                    "usage_type": d.get("usageType"),
                    "verdict": (
                        "MALICIOUS"
                        if d.get("abuseConfidenceScore", 0) >= 50
                        else "SUSPICIOUS"
                        if d.get("abuseConfidenceScore", 0) >= 20
                        else "CLEAN"
                    ),
                }
            return {"source": "AbuseIPDB", "verdict": "ERROR", "status_code": resp.status_code}
        except requests.RequestException as e:
            return {"source": "AbuseIPDB", "verdict": "ERROR", "error": str(e)}


class ShodanClient:
    """Query Shodan for internet-facing host information."""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup_host(self, ip: str) -> dict:
        try:
            resp = requests.get(
                f"{self.BASE_URL}/shodan/host/{ip}",
                params={"key": self.api_key},
                timeout=15,
            )
            if resp.status_code == 200:
                d = resp.json()
                return {
                    "source": "Shodan",
                    "ip": d.get("ip_str"),
                    "org": d.get("org"),
                    "isp": d.get("isp"),
                    "country": d.get("country_name"),
                    "city": d.get("city"),
                    "open_ports": d.get("ports", []),
                    "hostnames": d.get("hostnames", []),
                    "os": d.get("os"),
                    "tags": d.get("tags", []),
                    "vulns": list(d.get("vulns", {}).keys()),
                    "last_update": d.get("last_update"),
                }
            elif resp.status_code == 404:
                return {"source": "Shodan", "verdict": "NOT_FOUND"}
            return {"source": "Shodan", "verdict": "ERROR", "status_code": resp.status_code}
        except requests.RequestException as e:
            return {"source": "Shodan", "verdict": "ERROR", "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Alert Enricher
# ─────────────────────────────────────────────────────────────────────────────

class AlertEnricher:
    """Orchestrate multi-source IOC enrichment for a set of SIEM alerts."""

    RATE_LIMIT_DELAY = 0.5  # seconds between API calls

    def __init__(self, vt_key: str, abuseipdb_key: str, shodan_key: str):
        self.vt     = VirusTotalClient(vt_key)
        self.abuse  = AbuseIPDBClient(abuseipdb_key)
        self.shodan = ShodanClient(shodan_key)

    def enrich_ip(self, ip: str) -> dict:
        """Run IP through all three intelligence sources."""
        log.info("Enriching IP: %s", ip)
        enrichment = {
            "ioc_type": "ip",
            "value": ip,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "virustotal": self.vt.lookup_ip(ip),
        }
        time.sleep(self.RATE_LIMIT_DELAY)
        enrichment["abuseipdb"] = self.abuse.check_ip(ip)
        time.sleep(self.RATE_LIMIT_DELAY)
        enrichment["shodan"] = self.shodan.lookup_host(ip)

        # Composite verdict
        verdicts = [
            enrichment["virustotal"].get("verdict", "UNKNOWN"),
            enrichment["abuseipdb"].get("verdict", "UNKNOWN"),
        ]
        enrichment["composite_verdict"] = (
            "MALICIOUS" if "MALICIOUS" in verdicts
            else "SUSPICIOUS" if "SUSPICIOUS" in verdicts
            else "CLEAN"
        )
        return enrichment

    def enrich_hash(self, file_hash: str) -> dict:
        """Enrich a file hash via VirusTotal."""
        log.info("Enriching hash: %s", file_hash)
        return {
            "ioc_type": "hash",
            "value": file_hash,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "virustotal": self.vt.lookup_hash(file_hash),
        }

    def enrich_alert(self, alert: dict) -> dict:
        """Enrich a single SIEM alert by extracting and enriching IOCs."""
        enriched = {
            "alert_id": alert.get("id", "unknown"),
            "rule_name": alert.get("rule", {}).get("name", "unknown"),
            "severity": alert.get("rule", {}).get("severity", "unknown"),
            "timestamp": alert.get("@timestamp", "unknown"),
            "host": alert.get("host", {}).get("name", "unknown"),
            "user": alert.get("user", {}).get("name", "unknown"),
            "iocs": [],
        }

        # Extract IPs from alert fields
        for ip_field in ["source.ip", "destination.ip", "client.ip"]:
            ip = self._get_nested(alert, ip_field)
            if ip and self._is_routable(ip):
                enriched["iocs"].append(self.enrich_ip(ip))

        # Extract file hashes
        for hash_field in ["file.hash.sha256", "file.hash.md5", "process.hash.sha256"]:
            h = self._get_nested(alert, hash_field)
            if h:
                enriched["iocs"].append(self.enrich_hash(h))

        return enriched

    def enrich_alerts_batch(self, alerts: list[dict]) -> list[dict]:
        """Enrich a list of alerts."""
        return [self.enrich_alert(a) for a in alerts]

    @staticmethod
    def _get_nested(d: dict, key: str) -> Optional[str]:
        for k in key.split("."):
            if not isinstance(d, dict):
                return None
            d = d.get(k)
        return d

    @staticmethod
    def _is_routable(ip: str) -> bool:
        """Exclude RFC1918 private addresses from external enrichment."""
        private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                            "172.2", "172.3", "192.168.", "127.", "169.254.")
        return not any(ip.startswith(p) for p in private_prefixes)

    def save_report(self, enriched_alerts: list[dict], output_file: Optional[Path] = None) -> Path:
        """Save enriched alert data to JSON."""
        if output_file is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = REPORTS_DIR / f"enriched_alerts_{ts}.json"

        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(enriched_alerts, f, indent=2)

        log.info("Enriched alerts saved to %s", output_file)
        return output_file


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Enrich SIEM alerts with VirusTotal, AbuseIPDB, and Shodan"
    )
    parser.add_argument(
        "--alerts-file",
        type=Path,
        required=True,
        help="JSON file containing raw Elastic SIEM alerts",
    )
    parser.add_argument(
        "--vt-key",
        default=os.getenv("VT_API_KEY"),
        help="VirusTotal API key (or VT_API_KEY env var)",
    )
    parser.add_argument(
        "--abuseipdb-key",
        default=os.getenv("ABUSEIPDB_API_KEY"),
        help="AbuseIPDB API key (or ABUSEIPDB_API_KEY env var)",
    )
    parser.add_argument(
        "--shodan-key",
        default=os.getenv("SHODAN_API_KEY"),
        help="Shodan API key (or SHODAN_API_KEY env var)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output JSON file path (default: auto-named in automation/reports/)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    missing = [k for k, v in {
        "VT": args.vt_key,
        "AbuseIPDB": args.abuseipdb_key,
        "Shodan": args.shodan_key,
    }.items() if not v]
    if missing:
        log.error("Missing API keys: %s", ", ".join(missing))
        sys.exit(1)

    if not args.alerts_file.exists():
        log.error("Alerts file not found: %s", args.alerts_file)
        sys.exit(1)

    with open(args.alerts_file) as f:
        alerts = json.load(f)

    enricher = AlertEnricher(args.vt_key, args.abuseipdb_key, args.shodan_key)
    enriched = enricher.enrich_alerts_batch(alerts)
    enricher.save_report(enriched, args.output)


if __name__ == "__main__":
    main()
