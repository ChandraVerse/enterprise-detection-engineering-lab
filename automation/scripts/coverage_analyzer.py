#!/usr/bin/env python3
"""
coverage_analyzer.py
====================
Analyze detection coverage gaps against MITRE ATT&CK by comparing
the lab's current rule mappings against all Windows-platform techniques.
Outputs a coverage gap report to stdout and optionally to a JSON file.

Author: Chandra Sekhar Chakraborty
Project: Enterprise Detection Engineering Lab
"""

import json
import sys
import argparse
from pathlib import Path

MAPPINGS_FILE = Path("mitre-attack/mappings/rule_technique_mapping.json")

# All Windows ATT&CK techniques targeted by this lab scope
ALL_SCOPED_TECHNIQUES = {
    "TA0001": ["T1566", "T1566.001", "T1566.002"],
    "TA0002": ["T1047", "T1059.001", "T1059.003", "T1059.005", "T1204"],
    "TA0003": ["T1053.005", "T1547.001", "T1543.003", "T1098"],
    "TA0004": ["T1078", "T1134", "T1134.001"],
    "TA0005": ["T1027.010", "T1140", "T1218", "T1036", "T1112"],
    "TA0006": ["T1003.001", "T1003.002", "T1550.002", "T1555"],
    "TA0007": ["T1087.001", "T1069", "T1082", "T1016", "T1049"],
    "TA0008": ["T1021.002", "T1550.002", "T1021.001"],
    "TA0009": ["T1560", "T1005"],
    "TA0010": ["T1041", "T1071"],
}

TACTIC_NAMES = {
    "TA0001": "Initial Access",       "TA0002": "Execution",
    "TA0003": "Persistence",          "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",      "TA0006": "Credential Access",
    "TA0007": "Discovery",            "TA0008": "Lateral Movement",
    "TA0009": "Collection",           "TA0010": "Exfiltration",
}


def load_covered_techniques() -> set:
    if not MAPPINGS_FILE.exists():
        print(f"ERROR: Mappings file not found: {MAPPINGS_FILE}", file=sys.stderr)
        sys.exit(1)
    with open(MAPPINGS_FILE) as f:
        data = json.load(f)
    return {m["technique_id"] for m in data["mappings"]}


def analyze_coverage(covered: set) -> dict:
    report = {"summary": {}, "by_tactic": {}}
    total_scoped = sum(len(v) for v in ALL_SCOPED_TECHNIQUES.values())
    total_covered = 0

    for tactic_id, techniques in ALL_SCOPED_TECHNIQUES.items():
        covered_here = [t for t in techniques if t in covered]
        gap = [t for t in techniques if t not in covered]
        total_covered += len(covered_here)

        report["by_tactic"][tactic_id] = {
            "tactic_name": TACTIC_NAMES.get(tactic_id, tactic_id),
            "scoped_techniques": len(techniques),
            "covered": covered_here,
            "gap": gap,
            "coverage_pct": round(len(covered_here) / len(techniques) * 100, 1),
        }

    report["summary"] = {
        "total_scoped_techniques": total_scoped,
        "covered": total_covered,
        "gap": total_scoped - total_covered,
        "overall_coverage_pct": round(total_covered / total_scoped * 100, 1),
    }
    return report


def print_report(report: dict):
    print("\n" + "═" * 62)
    print("  MITRE ATT&CK COVERAGE GAP ANALYSIS")
    print("  Enterprise Detection Engineering Lab")
    print("═" * 62)

    s = report["summary"]
    print(f"\n  Overall Coverage: {s['covered']}/{s['total_scoped_techniques']} "
          f"techniques ({s['overall_coverage_pct']}%)")
    print(f"  Coverage Gaps:    {s['gap']} techniques need detection rules\n")

    print("─" * 62)
    print(f"  {'Tactic':<25} {'Covered':>8} {'Scoped':>8} {'Pct':>8}")
    print("─" * 62)

    for tactic_id, td in sorted(report["by_tactic"].items()):
        bar = "█" * int(td["coverage_pct"] / 10) + "░" * (10 - int(td["coverage_pct"] / 10))
        print(f"  {td['tactic_name']:<25} {len(td['covered']):>8} {td['scoped_techniques']:>8} "
              f"  {td['coverage_pct']:>5.1f}% {bar}")

    print("─" * 62)
    print("\n  GAPS BY TACTIC:")
    for tactic_id, td in sorted(report["by_tactic"].items()):
        if td["gap"]:
            print(f"\n  {td['tactic_name']} ({tactic_id}):")
            for t in td["gap"]:
                print(f"    ✗ {t}  ← Missing detection rule")
    print()


def main():
    parser = argparse.ArgumentParser(description="Analyze ATT&CK detection coverage gaps")
    parser.add_argument("--output", type=Path, help="Save report to JSON file")
    args = parser.parse_args()

    covered = load_covered_techniques()
    report = analyze_coverage(covered)
    print_report(report)

    if args.output:
        args.output.write_text(json.dumps(report, indent=2))
        print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
