"""
PDF report generator for VulnScan Pro.

Produces professional penetration test-style reports using ReportLab.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    Image,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from core.risk_calculator import RiskCalculator
from utils.logger import logger

# ── Colour palette ─────────────────────────────────────────────────────────────
C_BG_DARK = colors.HexColor("#ffffff")
C_BG_MID = colors.HexColor("#f0f0f0")
C_BORDER = colors.HexColor("#cccccc")
C_CYAN = colors.HexColor("#00d4ff")
C_GREEN = colors.HexColor("#00c853")
C_WHITE = colors.white
C_LIGHT = colors.HexColor("#111111")
C_MUTED = colors.HexColor("#555555")
C_CRITICAL = colors.HexColor("#ff0055")
C_HIGH = colors.HexColor("#ff4444")
C_MEDIUM = colors.HexColor("#ffb800")
C_LOW = colors.HexColor("#00c853")
C_INFO = colors.HexColor("#00d4ff")

SEV_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH": C_HIGH,
    "MEDIUM": C_MEDIUM,
    "LOW": C_LOW,
    "INFORMATIONAL": C_INFO,
}


def _sev_color(severity: str) -> colors.Color:
    return SEV_COLORS.get(severity.upper(), C_MUTED)


class _DocBuilder:
    """Internal helper that builds the ReportLab story (list of flowables)."""

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self._define_styles()

    def _define_styles(self) -> None:
        s = self.styles

        s.add(ParagraphStyle("VSTitle",
            parent=s["Normal"],
            fontSize=28, leading=34, textColor=C_CYAN,
            fontName="Helvetica-Bold", backColor=C_BG_DARK, spaceAfter=6))

        s.add(ParagraphStyle("VSSubtitle",
            parent=s["Normal"],
            fontSize=14, leading=18, textColor=C_MUTED,
            fontName="Helvetica", spaceAfter=4))

        s.add(ParagraphStyle("VSH1",
            parent=s["Normal"],
            fontSize=16, leading=20, textColor=C_CYAN,
            fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6))

        s.add(ParagraphStyle("VSH2",
            parent=s["Normal"],
            fontSize=13, leading=16, textColor=C_LIGHT,
            fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4))

        s.add(ParagraphStyle("VSBody",
            parent=s["Normal"],
            fontSize=10, leading=14, textColor=C_LIGHT,
            fontName="Helvetica", spaceAfter=4))

        s.add(ParagraphStyle("VSMono",
            parent=s["Normal"],
            fontSize=9, leading=12, textColor=C_CYAN,
            fontName="Courier", spaceAfter=2))

        s.add(ParagraphStyle("VSBullet",
            parent=s["Normal"],
            fontSize=10, leading=14, textColor=C_LIGHT,
            fontName="Helvetica", leftIndent=14, spaceAfter=2,
            bulletIndent=6, bulletText="•"))

        s.add(ParagraphStyle("VSLabel",
            parent=s["Normal"],
            fontSize=9, leading=12, textColor=C_MUTED,
            fontName="Helvetica-Bold", spaceAfter=1))

        s.add(ParagraphStyle("VSSmall",
            parent=s["Normal"],
            fontSize=8, leading=11, textColor=C_MUTED,
            fontName="Helvetica", spaceAfter=2))

    # ── Page builder ───────────────────────────────────────────────────────────

    def build_story(
        self,
        scan: dict,
        port_results: List[dict],
        vulnerabilities: List[dict],
        risk_score: float,
    ) -> list:
        st = []

        st += self._cover_page(scan, risk_score, vulnerabilities)
        st.append(PageBreak())
        st += self._toc_page()
        st.append(PageBreak())
        st += self._executive_summary(scan, port_results, vulnerabilities, risk_score)
        st.append(PageBreak())
        st += self._vulnerability_summary(vulnerabilities)
        st.append(PageBreak())
        st += self._detailed_findings(vulnerabilities)
        if port_results:
            st.append(PageBreak())
            st += self._port_scan_results(port_results)
        st.append(PageBreak())
        st += self._recommendations(vulnerabilities)

        return st

    # ── Sections ───────────────────────────────────────────────────────────────

    def _cover_page(self, scan: dict, risk_score: float, vulns: list) -> list:
        st = []
        st.append(Spacer(1, 60))
        st.append(Paragraph("VulnScan Pro", self.styles["VSTitle"]))
        st.append(Paragraph("Vulnerability Assessment Report", self.styles["VSSubtitle"]))
        st.append(HRFlowable(width="100%", thickness=1, color=C_CYAN, spaceAfter=20))
        st.append(Spacer(1, 20))

        meta_data = [
            ["Report Date", datetime.now().strftime("%Y-%m-%d %H:%M")],
            ["Scan Name", scan.get("name", "N/A")],
            ["Target", scan.get("target", "N/A")],
            ["Status", scan.get("status", "N/A").upper()],
        ]
        meta_table = Table(meta_data, colWidths=[5 * cm, 11 * cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), C_BG_MID),
            ("BACKGROUND", (1, 0), (1, -1), C_BG_DARK),
            ("TEXTCOLOR", (0, 0), (0, -1), C_MUTED),
            ("TEXTCOLOR", (1, 0), (1, -1), C_LIGHT),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_BG_MID, C_BG_DARK]),
            ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ]))
        st.append(meta_table)
        st.append(Spacer(1, 40))

        # Risk score badge
        label = RiskCalculator.severity_label(risk_score)
        badge_color = _sev_color(label)
        badge_data = [[f"Risk Score: {risk_score}/100  —  {label}"]]
        badge = Table(badge_data, colWidths=[16 * cm])
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), badge_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), C_WHITE),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 18),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 18),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
            ("ROUNDEDCORNERS", [6, 6, 6, 6]),
        ]))
        st.append(badge)
        st.append(Spacer(1, 30))

        sev_counts = RiskCalculator.severity_counts(vulns)
        counts_data = [
            [str(sev_counts.get("CRITICAL", 0)), str(sev_counts.get("HIGH", 0)),
             str(sev_counts.get("MEDIUM", 0)), str(sev_counts.get("LOW", 0))],
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        ]
        counts_table = Table(counts_data, colWidths=[4 * cm] * 4)
        counts_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 22),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, 1), 9),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TEXTCOLOR", (0, 0), (0, -1), C_CRITICAL),
            ("TEXTCOLOR", (1, 0), (1, -1), C_HIGH),
            ("TEXTCOLOR", (2, 0), (2, -1), C_MEDIUM),
            ("TEXTCOLOR", (3, 0), (3, -1), C_LOW),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        st.append(counts_table)
        st.append(Spacer(1, 30))
        st.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
        st.append(Spacer(1, 10))
        st.append(Paragraph(
            "⚠  This report is for authorised use only. "
            "Scan only systems you own or have explicit written permission to test.",
            self.styles["VSSmall"]
        ))
        return st

    def _toc_page(self) -> list:
        st = [Paragraph("Table of Contents", self.styles["VSH1"])]
        st.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=12))
        items = [
            "1.  Executive Summary",
            "2.  Vulnerability Summary",
            "3.  Detailed Findings",
            "4.  Port Scan Results",
            "5.  Recommendations",
        ]
        for item in items:
            st.append(Paragraph(item, self.styles["VSBody"]))
            st.append(Spacer(1, 4))
        return st

    def _executive_summary(
        self, scan: dict, ports: list, vulns: list, risk_score: float
    ) -> list:
        st = [Paragraph("1. Executive Summary", self.styles["VSH1"])]
        st.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

        open_ports = [p for p in ports if p.get("status") == "open"]
        sev = RiskCalculator.severity_counts(vulns)
        label = RiskCalculator.severity_label(risk_score)

        summary = (
            f"A vulnerability assessment was conducted against the target "
            f"<b>{scan.get('target', 'Unknown')}</b> on "
            f"{scan.get('scan_date', datetime.now().isoformat())[:10]}. "
            f"The assessment identified <b>{len(open_ports)}</b> open port(s) and "
            f"<b>{len(vulns)}</b> security finding(s). The overall risk score is "
            f"<b>{risk_score}/100</b> ({label})."
        )
        st.append(Paragraph(summary, self.styles["VSBody"]))
        st.append(Spacer(1, 10))

        stats = [
            ["Metric", "Value"],
            ["Target", scan.get("target", "N/A")],
            ["Open Ports", str(len(open_ports))],
            ["Total Findings", str(len(vulns))],
            ["Critical", str(sev.get("CRITICAL", 0))],
            ["High", str(sev.get("HIGH", 0))],
            ["Medium", str(sev.get("MEDIUM", 0))],
            ["Low", str(sev.get("LOW", 0))],
            ["Risk Score", f"{risk_score}/100 ({label})"],
        ]
        tbl = Table(stats, colWidths=[7 * cm, 9 * cm])
        tbl.setStyle(self._summary_table_style())
        st.append(tbl)
        return st

    def _vulnerability_summary(self, vulns: list) -> list:
        st = [Paragraph("2. Vulnerability Summary", self.styles["VSH1"])]
        st.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

        if not vulns:
            st.append(Paragraph("No vulnerabilities were detected.", self.styles["VSBody"]))
            return st

        rows = [["#", "CVE / ID", "Name", "Host:Port", "Severity", "CVSS"]]
        for i, v in enumerate(vulns, 1):
            rows.append([
                str(i),
                Paragraph(v.get("cve_id", "N/A"), self.styles["VSMono"]),
                Paragraph(v["name"][:60], self.styles["VSBody"]),
                f"{v['host']}:{v['port']}",
                v["severity"],
                f"{v.get('cvss_score', 0):.1f}",
            ])

        col_w = [1 * cm, 4 * cm, 6.5 * cm, 4 * cm, 2.5 * cm, 1.5 * cm]
        tbl = Table(rows, colWidths=col_w, repeatRows=1)
        tbl.setStyle(self._findings_table_style(vulns))
        st.append(tbl)
        return st

    def _detailed_findings(self, vulns: list) -> list:
        st = [Paragraph("3. Detailed Findings", self.styles["VSH1"])]
        st.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

        if not vulns:
            st.append(Paragraph("No vulnerabilities were detected.", self.styles["VSBody"]))
            return st

        for i, v in enumerate(vulns, 1):
            sev = v.get("severity", "INFO").upper()
            color = _sev_color(sev)

            # Finding header bar
            header_data = [[f"Finding {i}: {v['name']}"]]
            header_tbl = Table(header_data, colWidths=[19.5 * cm])
            header_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("TEXTCOLOR", (0, 0), (-1, -1), C_WHITE),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]))
            st.append(Spacer(1, 8))
            st.append(header_tbl)

            # Meta table
            meta = [
                ["CVE ID", v.get("cve_id", "N/A"), "Severity", sev],
                ["Host", v.get("host", "N/A"), "CVSS Score", f"{v.get('cvss_score', 0):.1f}"],
                ["Port", str(v.get("port", "")), "Service", v.get("service", "")],
                ["Detected Version", v.get("detected_version", "unknown"), "", ""],
            ]
            mtbl = Table(meta, colWidths=[4 * cm, 6.5 * cm, 3 * cm, 5.5 * cm])
            mtbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), C_BG_MID),
                ("BACKGROUND", (2, 0), (2, -1), C_BG_MID),
                ("BACKGROUND", (1, 0), (1, -1), C_BG_DARK),
                ("BACKGROUND", (3, 0), (3, -1), C_BG_DARK),
                ("TEXTCOLOR", (0, 0), (-1, -1), C_LIGHT),
                ("TEXTCOLOR", (0, 0), (0, -1), C_MUTED),
                ("TEXTCOLOR", (2, 0), (2, -1), C_MUTED),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ]))
            st.append(mtbl)
            st.append(Spacer(1, 6))

            st.append(Paragraph("Description", self.styles["VSLabel"]))
            st.append(Paragraph(v.get("description", ""), self.styles["VSBody"]))
            st.append(Spacer(1, 4))
            st.append(Paragraph("Remediation", self.styles["VSLabel"]))
            st.append(Paragraph(v.get("remediation", ""), self.styles["VSBody"]))

        return st

    def _port_scan_results(self, ports: list) -> list:
        st = [Paragraph("4. Port Scan Results", self.styles["VSH1"])]
        st.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

        open_ports = [p for p in ports if p.get("status") == "open"]
        if not open_ports:
            st.append(Paragraph("No open ports were detected.", self.styles["VSBody"]))
            return st

        rows = [["Host", "Port", "Service", "Product", "Version", "Response Time"]]
        for p in open_ports:
            rows.append([
                p.get("host", ""),
                str(p.get("port", "")),
                p.get("service", ""),
                p.get("product", ""),
                p.get("version", ""),
                f"{p.get('scan_time', 0):.3f}s",
            ])

        col_w = [4.5 * cm, 2 * cm, 3 * cm, 4 * cm, 3.5 * cm, 2.5 * cm]
        tbl = Table(rows, colWidths=col_w, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_BG_MID),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_CYAN),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("TEXTCOLOR", (0, 1), (-1, -1), C_LIGHT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG_DARK, C_BG_MID]),
            ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        st.append(tbl)
        return st

    def _recommendations(self, vulns: list) -> list:
        st = [Paragraph("5. Recommendations", self.styles["VSH1"])]
        st.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8))

        recs = RiskCalculator.recommendations(vulns)
        if not recs:
            st.append(Paragraph(
                "No specific remediation actions were identified. "
                "Continue monitoring and patching systems regularly.",
                self.styles["VSBody"]
            ))
            return st

        st.append(Paragraph(
            "The following remediation actions are recommended, ordered by priority:",
            self.styles["VSBody"]
        ))
        st.append(Spacer(1, 8))
        for i, rec in enumerate(recs, 1):
            st.append(Paragraph(f"{i}.  {rec}", self.styles["VSBullet"]))
            st.append(Spacer(1, 4))

        return st

    # ── Table styles ───────────────────────────────────────────────────────────

    @staticmethod
    def _summary_table_style() -> TableStyle:
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_BG_MID),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_CYAN),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("TEXTCOLOR", (0, 1), (-1, -1), C_LIGHT),
            ("BACKGROUND", (0, 1), (0, -1), C_BG_MID),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG_DARK, C_BG_MID]),
            ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("PADDING", (0, 0), (-1, -1), 7),
        ])

    @staticmethod
    def _findings_table_style(vulns: list) -> TableStyle:
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), C_BG_MID),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_CYAN),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("TEXTCOLOR", (0, 1), (-1, -1), C_LIGHT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG_DARK, C_BG_MID]),
            ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]
        for i, vuln in enumerate(vulns, 1):
            sev = vuln.get("severity", "LOW").upper()
            style.append(("TEXTCOLOR", (4, i), (4, i), _sev_color(sev)))
            style.append(("FONTNAME", (4, i), (4, i), "Helvetica-Bold"))
        return TableStyle(style)


# ── Public API ─────────────────────────────────────────────────────────────────

class PDFGenerator:
    """Generate a PDF report for a completed scan."""

    @staticmethod
    def generate(
        output_path: str | Path,
        scan: dict,
        port_results: List[dict],
        vulnerabilities: List[dict],
        risk_score: float,
    ) -> Path:
        """
        Build and save the PDF report.

        Parameters
        ----------
        output_path : destination file path (.pdf)
        scan        : scan metadata dict from db_manager.get_scan()
        port_results: list of port result dicts
        vulnerabilities: list of vulnerability dicts
        risk_score  : pre-calculated risk score

        Returns the resolved output path.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        def _header_footer(canvas, doc):
            canvas.saveState()
            w, h = A4
            # Header bar
            canvas.setFillColor(C_BG_MID)
            canvas.rect(0, h - 30, w, 30, fill=True, stroke=False)
            canvas.setFont("Helvetica-Bold", 9)
            canvas.setFillColor(C_CYAN)
            canvas.drawString(20, h - 19, "VulnScan Pro — Vulnerability Assessment Report")
            canvas.setFillColor(C_MUTED)
            canvas.drawRightString(w - 20, h - 19, scan.get("target", ""))
            # Footer
            canvas.setFillColor(C_BG_MID)
            canvas.rect(0, 0, w, 22, fill=True, stroke=False)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(C_MUTED)
            canvas.drawString(20, 7, "CONFIDENTIAL — Authorised use only")
            canvas.drawRightString(w - 20, 7, f"Page {doc.page}")
            canvas.restoreState()

        page_w, page_h = A4
        margin = 1.5 * cm
        frame = Frame(
            margin, margin + 22,
            page_w - 2 * margin, page_h - 2 * margin - 52,
            id="main",
        )
        template = PageTemplate(id="main", frames=[frame], onPage=_header_footer)
        doc = BaseDocTemplate(
            str(output_path),
            pagesize=A4,
            pageTemplates=[template],
        )

        builder = _DocBuilder()
        story = builder.build_story(scan, port_results, vulnerabilities, risk_score)
        doc.build(story)

        logger.info("PDF report saved to %s", output_path)
        return output_path
