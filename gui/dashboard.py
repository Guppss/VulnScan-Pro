"""
Dashboard page — overview of all historical scan statistics.
"""
from __future__ import annotations

from datetime import datetime
from typing import List

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from database import db_manager
from gui import (
    ACCENT, ACCENT_GREEN, BG_CARD, BG_SECONDARY, BORDER,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO,
    SEVERITY_COLORS, TEXT_PRIMARY, TEXT_SECONDARY,
)
from gui.widgets.charts import BarChart, DonutChart, LineChart
from gui.widgets.stat_card import StatCard
from gui.widgets.severity_badge import SeverityBadge


class DashboardPage(QWidget):
    """Dashboard with aggregated statistics, charts, and recent scans."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        scroll.setWidget(content)
        root.addWidget(scroll)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(20)

        # Page header
        hdr = QVBoxLayout()
        title = QLabel("Security Dashboard")
        title.setObjectName("pageTitle")
        sub = QLabel("Overview of all vulnerability assessments")
        sub.setObjectName("pageSubtitle")
        hdr.addWidget(title)
        hdr.addWidget(sub)
        layout.addLayout(hdr)

        # Stat cards row
        cards_layout = QGridLayout()
        cards_layout.setSpacing(14)
        self._card_scans = StatCard("Total Scans", "0", "🔍", ACCENT)
        self._card_ports = StatCard("Open Ports", "0", "🔌", ACCENT_GREEN)
        self._card_vulns = StatCard("Vulnerabilities", "0", "⚠", SEV_HIGH)
        self._card_risk = StatCard("Avg Risk Score", "0.0", "🛡", SEV_CRITICAL)
        cards_layout.addWidget(self._card_scans, 0, 0)
        cards_layout.addWidget(self._card_ports, 0, 1)
        cards_layout.addWidget(self._card_vulns, 0, 2)
        cards_layout.addWidget(self._card_risk, 0, 3)
        layout.addLayout(cards_layout)

        # Charts row
        charts_row = QHBoxLayout()
        charts_row.setSpacing(14)

        # Donut chart card
        donut_card = self._make_card("Severity Distribution")
        donut_body = QVBoxLayout(donut_card)
        donut_body.setContentsMargins(16, 44, 16, 16)
        self._donut = DonutChart()
        donut_body.addWidget(self._donut)
        charts_row.addWidget(donut_card, 2)

        # Bar chart card
        bar_card = self._make_card("Findings by Severity")
        bar_body = QVBoxLayout(bar_card)
        bar_body.setContentsMargins(16, 44, 16, 16)
        self._bar = BarChart()
        self._bar.setMinimumHeight(200)
        bar_body.addWidget(self._bar)
        charts_row.addWidget(bar_card, 3)

        layout.addLayout(charts_row)

        # Trend chart
        trend_card = self._make_card("Risk Score Trend (Recent Scans)")
        trend_body = QVBoxLayout(trend_card)
        trend_body.setContentsMargins(16, 44, 16, 16)
        self._trend = LineChart(title="Risk Score")
        self._trend.setMinimumHeight(160)
        trend_body.addWidget(self._trend)
        layout.addWidget(trend_card)

        # Recent scans table
        recent_card = self._make_card("Recent Scans")
        recent_body = QVBoxLayout(recent_card)
        recent_body.setContentsMargins(16, 44, 16, 16)
        self._recent_table = self._make_recent_table()
        recent_body.addWidget(self._recent_table)
        layout.addWidget(recent_card)

        layout.addStretch()

    def _make_card(self, title: str) -> QWidget:
        card = QWidget()
        card.setObjectName("card")
        # Title label placed manually so children can add their own layout
        lbl = QLabel(title, card)
        lbl.setObjectName("sectionTitle")
        lbl.move(16, 14)
        lbl.adjustSize()
        return card

    def _make_recent_table(self) -> QTableWidget:
        headers = ["Name", "Target", "Date", "Open Ports", "Vulns", "Risk", "Status"]
        tbl = QTableWidget(0, len(headers))
        tbl.setHorizontalHeaderLabels(headers)
        tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        tbl.setAlternatingRowColors(True)
        tbl.horizontalHeader().setStretchLastSection(True)
        tbl.verticalHeader().setVisible(False)
        tbl.setShowGrid(False)
        return tbl

    # ── Data refresh ───────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Reload statistics from the database and update all widgets."""
        stats = db_manager.get_dashboard_stats()

        self._card_scans.set_value(stats["total_scans"])
        self._card_ports.set_value(stats["total_open_ports"])
        self._card_vulns.set_value(stats["total_vulns"])
        self._card_risk.set_value(f"{stats['avg_risk_score']:.1f}")

        sev = stats["severity_counts"]
        donut_data = [
            ("Critical", sev.get("CRITICAL", 0), SEV_CRITICAL),
            ("High",     sev.get("HIGH", 0),     SEV_HIGH),
            ("Medium",   sev.get("MEDIUM", 0),   SEV_MEDIUM),
            ("Low",      sev.get("LOW", 0),       SEV_LOW),
            ("Info",     sev.get("INFORMATIONAL", 0), SEV_INFO),
        ]
        self._donut.set_data(donut_data)

        bar_data = [
            ("CRIT",  sev.get("CRITICAL", 0),     SEV_CRITICAL),
            ("HIGH",  sev.get("HIGH", 0),          SEV_HIGH),
            ("MED",   sev.get("MEDIUM", 0),        SEV_MEDIUM),
            ("LOW",   sev.get("LOW", 0),           SEV_LOW),
            ("INFO",  sev.get("INFORMATIONAL", 0), SEV_INFO),
        ]
        self._bar.set_data(bar_data, "Findings by Severity")

        recent = stats["recent_scans"]
        if recent:
            trend_data = [
                (r["scan_date"][:10], r["risk_score"]) for r in reversed(recent)
            ]
            self._trend.set_data(trend_data, "Risk Score Trend")

        self._populate_recent_table(recent)

    def _populate_recent_table(self, scans: list) -> None:
        tbl = self._recent_table
        tbl.setRowCount(0)
        for row_data in scans:
            row = tbl.rowCount()
            tbl.insertRow(row)

            name_item = QTableWidgetItem(row_data.get("name", ""))
            name_item.setForeground(Qt.GlobalColor.white)
            tbl.setItem(row, 0, name_item)

            tbl.setItem(row, 1, QTableWidgetItem(row_data.get("target", "")))
            date_str = row_data.get("scan_date", "")[:16].replace("T", " ")
            tbl.setItem(row, 2, QTableWidgetItem(date_str))
            tbl.setItem(row, 3, QTableWidgetItem(str(row_data.get("open_ports", 0))))
            tbl.setItem(row, 4, QTableWidgetItem(str(row_data.get("total_vulns", 0))))
            tbl.setItem(row, 5, QTableWidgetItem(f"{row_data.get('risk_score', 0):.1f}"))

            status = row_data.get("status", "").upper()
            status_item = QTableWidgetItem(status)
            if status == "COMPLETED":
                status_item.setForeground(Qt.GlobalColor.green)
            elif status == "FAILED":
                status_item.setForeground(Qt.GlobalColor.red)
            tbl.setItem(row, 6, status_item)

        tbl.resizeColumnsToContents()
