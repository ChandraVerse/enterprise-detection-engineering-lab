#!/usr/bin/env python3
"""
sigma_converter.py
==================
Batch convert all Sigma rules in this lab to KQL (Elastic) and SPL (Splunk)
using sigma-cli. Validates output and writes converted queries to the
detection-rules/kql/ and detection-rules/spl/ directories.

Author: Chandra Sekhar Chakraborty
Project: Enterprise Detection Engineering Lab
"""

import sys
import subprocess
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

SIGMA_DIR = Path("detection-rules/sigma")
KQL_DIR   = Path("detection-rules/kql")
SPL_DIR   = Path("detection-rules/spl")

BACKENDS = {
    "kql": {"target": "lucene",  "pipeline": "ecs_windows", "out_dir": KQL_DIR, "ext": ".kql"},
    "spl": {"target": "splunk",  "pipeline": "splunk_windows", "out_dir": SPL_DIR, "ext": ".spl"},
}


def convert_rule(sigma_file: Path, target: str, pipeline: str, out_dir: Path, ext: str) -> bool:
    out_file = out_dir / f"{sigma_file.stem}{ext}"
    cmd = ["sigma", "convert", "-t", target]
    if pipeline:
        cmd += ["-p", pipeline]
    cmd.append(str(sigma_file))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            out_file.write_text(
                f"// Auto-converted from {sigma_file.name} via sigma-cli\n"
                f"// Backend: {target} | Pipeline: {pipeline}\n\n"
                + result.stdout.strip()
            )
            log.info("✅ %s → %s", sigma_file.name, out_file.name)
            return True
        else:
            log.warning("⚠️  %s [%s]: %s", sigma_file.name, target, result.stderr[:200])
            return False
    except subprocess.TimeoutExpired:
        log.error("Timeout converting %s", sigma_file.name)
        return False
    except FileNotFoundError:
        log.error("sigma-cli not found. Install: pip install sigma-cli pysigma-backend-elasticsearch pysigma-backend-splunk")
        sys.exit(1)


def main():
    sigma_files = sorted(SIGMA_DIR.glob("*.yml"))
    if not sigma_files:
        log.error("No Sigma rules found in %s", SIGMA_DIR)
        sys.exit(1)

    log.info("Converting %d Sigma rules...", len(sigma_files))
    stats = {b: {"ok": 0, "fail": 0} for b in BACKENDS}

    for sigma_file in sigma_files:
        for backend, cfg in BACKENDS.items():
            cfg["out_dir"].mkdir(parents=True, exist_ok=True)
            ok = convert_rule(sigma_file, cfg["target"], cfg["pipeline"],
                              cfg["out_dir"], cfg["ext"])
            stats[backend]["ok" if ok else "fail"] += 1

    print("\n── Conversion Summary ──────────────────────────")
    for backend, s in stats.items():
        print(f"  {backend.upper():5s}: {s['ok']} converted, {s['fail']} failed")
    print("────────────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
