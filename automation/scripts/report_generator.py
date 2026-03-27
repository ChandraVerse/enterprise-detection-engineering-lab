#!/usr/bin/env python3
"""
report_generator.py
===================
Auto-generate NIST 800-61 compliant incident response PDF reports
from enriched SIEM alert data. Follows the four NIST IR phases:
Preparation → Detection & Analysis → Containment → Post-Incident.

Author: Chandra Sekhar Chakraborty
Project: Enterprise Detection Engineering Lab
References:
  - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
"""

import json
import sys
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

REPORTS_DIR = Path("automation/reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Colour palette
DARK_BLUE   = colors.HexColor("#1a2a4a")
ACCENT_RED  = colors.HexColor("#c0392b")
ACCENT_BLUE = colors.HexColor("#2980b9")
LIGHT_GREY  = colors.HexColor("#f4f6f8")
MID_GREY    = colors.HexColor("#bdc3c7")
WHITE       = colors.white
BLACK       = colors.black


class NISTIncidentReport:
    """Generate a NIST 800-61 structured incident response PDF report."""

    SEVERITY_COLORS = {
        "critical": colors.HexColor("#c0392b"),
        "high":     colors.HexColor("#e67e22"),
        "medium":   colors.HexColor("#f1c40f"),
        "low":      colors.HexColor("#27ae60"),
    }

    def __init__(self, incident_data: dict):
        self.data = incident_data
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        self.h1 = ParagraphStyle(
            "h1", parent=self.styles["Title"],
            fontSize=22, textColor=WHITE, alignment=TA_CENTER,
            spaceAfter=6, fontName="Helvetica-Bold"
        )
        self.h2 = ParagraphStyle(
            "h2", parent=self.styles["Heading1"],
            fontSize=14, textColor=DARK_BLUE, spaceBefore=14, spaceAfter=6,
            fontName="Helvetica-Bold", borderPad=4
        )
        self.h3 = ParagraphStyle(
            "h3", parent=self.styles["Heading2"],
            fontSize=11, textColor=ACCENT_BLUE, spaceBefore=8, spaceAfter=4,
            fontName="Helvetica-Bold"
        )
        self.body = ParagraphStyle(
            "body", parent=self.styles["Normal"],
            fontSize=10, leading=15, spaceAfter=6, fontName="Helvetica"
        )
        self.mono = ParagraphStyle(
            "mono", parent=self.styles["Code"],
            fontSize=8, leading=12, fontName="Courier",
            backColor=LIGHT_GREY, leftIndent=10, rightIndent=10,
            borderPad=4
        )
        self.label = ParagraphStyle(
            "label", parent=self.styles["Normal"],
            fontSize=9, textColor=MID_GREY, fontName="Helvetica-Oblique"
        )

    # ── Section Builders ──────────────────────────────────────────────────────

    def _cover_page(self) -> list:
        elements = []
        incident = self.data.get("incident", {})

        # Header banner
        header_data = [[Paragraph("INCIDENT RESPONSE REPORT", self.h1)]]
        header_table = Table(header_data, colWidths=[17 * cm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_BLUE),
            ("TOPPADDING",    (0, 0), (-1, -1), 20),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 0.5 * cm))

        # Sub-heading
        elements.append(Paragraph(
            f"<b>{incident.get('title', 'Security Incident')}</b>",
            ParagraphStyle("sub", parent=self.styles["Title"], fontSize=16,
                           textColor=DARK_BLUE, alignment=TA_CENTER)
        ))
        elements.append(Spacer(1, 1 * cm))

        # Metadata table
        meta = [
            ["Incident ID",    incident.get("id", "INC-001")],
            ["Severity",       incident.get("severity", "High").upper()],
            ["Date/Time",      incident.get("timestamp", datetime.now(timezone.utc).isoformat())],
            ["Analyst",        incident.get("analyst", "Chandra Sekhar Chakraborty")],
            ["Affected Host",  incident.get("host", "Unknown")],
            ["Classification", incident.get("classification", "Malware / Credential Theft")],
            ["MITRE Technique", incident.get("technique", "T1003.001")],
            ["Report Status",  "FINAL"],
        ]
        t = Table(meta, colWidths=[5 * cm, 12 * cm])
        t.setStyle(TableStyle([
            ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 10),
            ("BACKGROUND",   (0, 0), (0, -1), LIGHT_GREY),
            ("GRID",         (0, 0), (-1, -1), 0.5, MID_GREY),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        elements.append(t)
        elements.append(PageBreak())
        return elements

    def _executive_summary(self) -> list:
        elements = [Paragraph("1. Executive Summary", self.h2)]
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_BLUE))
        elements.append(Spacer(1, 0.3 * cm))
        summary = self.data.get("executive_summary",
            "A security incident was detected and investigated following NIST SP 800-61r2 guidelines. "
            "This report documents the incident timeline, indicators of compromise, containment actions, "
            "and recommended remediation steps to prevent recurrence.")
        elements.append(Paragraph(summary, self.body))
        return elements

    def _detection_analysis(self) -> list:
        elements = [Paragraph("2. Detection & Analysis", self.h2)]
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_BLUE))
        elements.append(Spacer(1, 0.3 * cm))

        # IOC Table
        iocs = self.data.get("iocs", [])
        if iocs:
            elements.append(Paragraph("Indicators of Compromise", self.h3))
            ioc_rows = [["IOC Type", "Value", "Source", "Verdict"]]
            for ioc in iocs:
                vt = ioc.get("virustotal", {})
                ioc_rows.append([
                    ioc.get("ioc_type", "unknown").upper(),
                    ioc.get("value", ""),
                    "VirusTotal / AbuseIPDB",
                    ioc.get("composite_verdict", vt.get("verdict", "UNKNOWN")),
                ])
            t = Table(ioc_rows, colWidths=[3*cm, 6*cm, 4.5*cm, 3.5*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), DARK_BLUE),
                ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, -1), 9),
                ("GRID",         (0, 0), (-1, -1), 0.5, MID_GREY),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
                ("TOPPADDING",   (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
                ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 0.5 * cm))

        # Timeline
        timeline = self.data.get("timeline", [])
        if timeline:
            elements.append(Paragraph("Incident Timeline", self.h3))
            for event in timeline:
                elements.append(Paragraph(
                    f"<b>{event.get('time', '')}</b> — {event.get('event', '')}",
                    self.body
                ))

        return elements

    def _containment_eradication(self) -> list:
        elements = [Paragraph("3. Containment, Eradication & Recovery", self.h2)]
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_BLUE))
        elements.append(Spacer(1, 0.3 * cm))

        actions = self.data.get("containment_actions", [
            "Isolated affected host from network segment",
            "Revoked compromised user credentials and service accounts",
            "Terminated malicious processes and removed persistence mechanisms",
            "Collected memory dump and forensic disk image for analysis",
            "Restored system from last known-good backup",
            "Applied missing security patches and hardened configuration",
        ])
        for action in actions:
            elements.append(Paragraph(f"• {action}", self.body))

        return elements

    def _recommendations(self) -> list:
        elements = [Paragraph("4. Recommendations", self.h2)]
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_BLUE))
        elements.append(Spacer(1, 0.3 * cm))

        recs = self.data.get("recommendations", [
            "Enable Credential Guard on all Windows Server endpoints",
            "Deploy LAPS (Local Administrator Password Solution) across the domain",
            "Enforce PowerShell Constrained Language Mode via AppLocker or WDAC",
            "Enable LSA Protection (RunAsPPL) in the Windows registry",
            "Implement privileged access workstations (PAWs) for admin tasks",
            "Tune Sysmon configuration to capture additional GrantedAccess masks",
            "Review and rotate all service account credentials quarterly",
        ])
        for i, rec in enumerate(recs, 1):
            elements.append(Paragraph(f"<b>R{i:02d}.</b> {rec}", self.body))

        return elements

    def _appendix(self) -> list:
        elements = [Paragraph("Appendix: Raw Enrichment Data", self.h2)]
        elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT_BLUE))
        elements.append(Spacer(1, 0.3 * cm))
        raw = json.dumps(self.data.get("iocs", []), indent=2)
        for line in raw.splitlines()[:60]:
            elements.append(Paragraph(line or " ", self.mono))
        return elements

    # ── Main Build ────────────────────────────────────────────────────────────

    def build(self, output_path: Path) -> Path:
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
        )
        story = []
        story.extend(self._cover_page())
        story.extend(self._executive_summary())
        story.append(Spacer(1, 0.5*cm))
        story.extend(self._detection_analysis())
        story.append(Spacer(1, 0.5*cm))
        story.extend(self._containment_eradication())
        story.append(Spacer(1, 0.5*cm))
        story.extend(self._recommendations())
        story.append(PageBreak())
        story.extend(self._appendix())

        doc.build(story)
        log.info("PDF report generated: %s", output_path)
        return output_path


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate NIST 800-61 incident response PDF reports"
    )
    parser.add_argument(
        "--incident-file", type=Path, required=True,
        help="JSON file with incident data (enriched alerts output)"
    )
    parser.add_argument(
        "--output", type=Path,
        help="Output PDF path (default: auto-named in automation/reports/)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.incident_file.exists():
        log.error("Incident file not found: %s", args.incident_file)
        sys.exit(1)

    with open(args.incident_file) as f:
        incident_data = json.load(f)

    output = args.output or (
        REPORTS_DIR / f"IR_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    report = NISTIncidentReport(incident_data)
    report.build(output)


if __name__ == "__main__":
    main()
