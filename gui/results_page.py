"""
Results page — displays findings from the most recent or selected scan.
"""
from __future__ import annotations

from typing import List

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui import (
    ACCENT, BG_CARD, BG_SECONDARY, BORDER, SEVERITY_COLORS,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO,
    TEXT_PRIMARY, TEXT_SECONDARY,
)
from gui.widgets.severity_badge import SeverityBadge


class ResultsPage(QWidget):
    """Shows vulnerability findings and port results for a scan."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._all_vulns: list[dict] = []
        self._all_ports: list[dict] = []
        self._current_scan_id: str = ""
        self._build_ui()

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        main = QVBoxLayout(self)
        main.setContentsMargins(28, 24, 28, 24)
        main.setSpacing(16)

        # Header
        hdr_row = QHBoxLayout()
        title = QLabel("Scan Results")
        title.setObjectName("pageTitle")
        self._scan_info = QLabel("")
        self._scan_info.setObjectName("pageSubtitle")
        hdr_row.addWidget(title)
        hdr_row.addStretch()
        hdr_row.addWidget(self._scan_info)
        main.addLayout(hdr_row)

        # Filters
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)
        filter_row.addWidget(QLabel("Filter:"))

        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])
        self._sev_filter.currentTextChanged.connect(self._apply_filters)
        filter_row.addWidget(self._sev_filter)

        self._host_filter = QLineEdit()
        self._host_filter.setPlaceholderText("Host…")
        self._host_filter.setMaximumWidth(150)
        self._host_filter.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self._host_filter)

        self._port_filter = QLineEdit()
        self._port_filter.setPlaceholderText("Port…")
        self._port_filter.setMaximumWidth(80)
        self._port_filter.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self._port_filter)

        self._service_filter = QLineEdit()
        self._service_filter.setPlaceholderText("Service…")
        self._service_filter.setMaximumWidth(120)
        self._service_filter.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self._service_filter)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear_filters)
        filter_row.addWidget(clear_btn)
        filter_row.addStretch()
        main.addLayout(filter_row)

        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: vulnerability tree
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        left_header = QLabel("Vulnerability Findings")
        left_header.setObjectName("sectionTitle")
        left_layout.addWidget(left_header)

        self._vuln_tree = QTreeWidget()
        self._vuln_tree.setHeaderLabels(
            ["CVE / ID", "Name", "Severity", "CVSS", "Host:Port"]
        )
        self._vuln_tree.setColumnWidth(0, 140)
        self._vuln_tree.setColumnWidth(1, 260)
        self._vuln_tree.setColumnWidth(2, 100)
        self._vuln_tree.setColumnWidth(3, 50)
        self._vuln_tree.setAlternatingRowColors(True)
        self._vuln_tree.itemClicked.connect(self._on_vuln_selected)
        left_layout.addWidget(self._vuln_tree)

        left_header2 = QLabel("Open Ports")
        left_header2.setObjectName("sectionTitle")
        left_layout.addWidget(left_header2)

        self._port_table = QTableWidget(0, 5)
        self._port_table.setHorizontalHeaderLabels(
            ["Host", "Port", "Service", "Product", "Version"]
        )
        self._port_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._port_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._port_table.setAlternatingRowColors(True)
        self._port_table.verticalHeader().setVisible(False)
        self._port_table.setMaximumHeight(180)
        left_layout.addWidget(self._port_table)

        splitter.addWidget(left)

        # Right: detail panel
        self._detail_panel = self._build_detail_panel()
        splitter.addWidget(self._detail_panel)
        splitter.setSizes([600, 380])

        main.addWidget(splitter)

    def _build_detail_panel(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("card")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        self._detail_title = QLabel("Select a finding to view details")
        self._detail_title.setWordWrap(True)
        f = QFont()
        f.setPointSize(13)
        f.setBold(True)
        self._detail_title.setFont(f)
        layout.addWidget(self._detail_title)

        self._detail_badge = SeverityBadge("LOW")
        layout.addWidget(self._detail_badge)

        meta_layout = QHBoxLayout()
        self._detail_cve = QLabel("")
        self._detail_cve.setStyleSheet(f"color: {ACCENT}; font-family: monospace;")
        self._detail_host = QLabel("")
        self._detail_host.setObjectName("mutedLabel")
        self._detail_cvss = QLabel("")
        self._detail_cvss.setObjectName("mutedLabel")
        meta_layout.addWidget(self._detail_cve)
        meta_layout.addWidget(self._detail_host)
        meta_layout.addWidget(self._detail_cvss)
        meta_layout.addStretch()
        layout.addLayout(meta_layout)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background-color: {BORDER};")
        sep.setFixedHeight(1)
        layout.addWidget(sep)

        desc_lbl = QLabel("DESCRIPTION")
        desc_lbl.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 10px; font-weight: bold; letter-spacing: 1px;"
        )
        layout.addWidget(desc_lbl)
        self._detail_desc = QTextEdit()
        self._detail_desc.setReadOnly(True)
        self._detail_desc.setMaximumHeight(150)
        layout.addWidget(self._detail_desc)

        rem_lbl = QLabel("REMEDIATION")
        rem_lbl.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 10px; font-weight: bold; letter-spacing: 1px;"
        )
        layout.addWidget(rem_lbl)
        self._detail_rem = QTextEdit()
        self._detail_rem.setReadOnly(True)
        self._detail_rem.setMaximumHeight(120)
        self._detail_rem.setStyleSheet(
            f"background-color: #0d2016; border: 1px solid #1a4a2a; border-radius: 6px;"
        )
        layout.addWidget(self._detail_rem)

        ver_lbl = QLabel("DETECTED VERSION")
        ver_lbl.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 10px; font-weight: bold; letter-spacing: 1px;"
        )
        layout.addWidget(ver_lbl)
        self._detail_ver = QLabel("")
        self._detail_ver.setStyleSheet(f"color: {ACCENT}; font-family: monospace;")
        layout.addWidget(self._detail_ver)

        layout.addStretch()
        return panel

    # ── Data loading ───────────────────────────────────────────────────────────

    def load_scan(
        self,
        scan_id: str,
        port_results: List[dict],
        vulnerabilities: List[dict],
    ) -> None:
        """Load and display results from a completed scan."""
        self._current_scan_id = scan_id
        self._all_vulns = vulnerabilities
        self._all_ports = [r for r in port_results if r.get("status") == "open"]

        from core.risk_calculator import RiskCalculator
        risk = RiskCalculator.calculate(vulnerabilities)
        sev_counts = RiskCalculator.severity_counts(vulnerabilities)
        self._scan_info.setText(
            f"Risk: {risk:.0f}/100 | "
            f"C:{sev_counts.get('CRITICAL',0)}  "
            f"H:{sev_counts.get('HIGH',0)}  "
            f"M:{sev_counts.get('MEDIUM',0)}  "
            f"L:{sev_counts.get('LOW',0)}"
        )

        self._apply_filters()
        self._populate_port_table(self._all_ports)

    def _populate_vuln_tree(self, vulns: List[dict]) -> None:
        tree = self._vuln_tree
        tree.clear()

        # Group by host
        by_host: dict[str, list] = {}
        for v in vulns:
            host = v.get("host", "unknown")
            by_host.setdefault(host, []).append(v)

        for host, host_vulns in sorted(by_host.items()):
            host_item = QTreeWidgetItem([host, "", "", "", ""])
            host_item.setForeground(0, QColor(ACCENT))
            f = QFont()
            f.setBold(True)
            host_item.setFont(0, f)
            tree.addTopLevelItem(host_item)

            for v in host_vulns:
                sev = v.get("severity", "LOW").upper()
                sev_color = SEVERITY_COLORS.get(sev, TEXT_SECONDARY)
                child = QTreeWidgetItem([
                    v.get("cve_id", ""),
                    v.get("name", ""),
                    sev,
                    f"{v.get('cvss_score', 0):.1f}",
                    f"{v.get('host', '')}:{v.get('port', '')}",
                ])
                child.setForeground(2, QColor(sev_color))
                child.setForeground(0, QColor(ACCENT))
                child.setData(0, Qt.ItemDataRole.UserRole, v)
                host_item.addChild(child)

            host_item.setExpanded(True)

    def _populate_port_table(self, ports: List[dict]) -> None:
        tbl = self._port_table
        tbl.setRowCount(0)
        for p in ports:
            row = tbl.rowCount()
            tbl.insertRow(row)
            for col, key in enumerate(["host", "port", "service", "product", "version"]):
                tbl.setItem(row, col, QTableWidgetItem(str(p.get(key, ""))))
        tbl.resizeColumnsToContents()

    # ── Filtering ──────────────────────────────────────────────────────────────

    def _apply_filters(self) -> None:
        sev_f = self._sev_filter.currentText()
        host_f = self._host_filter.text().strip().lower()
        port_f = self._port_filter.text().strip()
        svc_f = self._service_filter.text().strip().lower()

        filtered = []
        for v in self._all_vulns:
            if sev_f != "All Severities" and v.get("severity", "").upper() != sev_f:
                continue
            if host_f and host_f not in v.get("host", "").lower():
                continue
            if port_f and str(v.get("port", "")) != port_f:
                continue
            if svc_f and svc_f not in v.get("service", "").lower():
                continue
            filtered.append(v)

        self._populate_vuln_tree(filtered)

    def _clear_filters(self) -> None:
        self._sev_filter.setCurrentIndex(0)
        self._host_filter.clear()
        self._port_filter.clear()
        self._service_filter.clear()

    # ── Selection handler ──────────────────────────────────────────────────────

    def _on_vuln_selected(self, item: QTreeWidgetItem, col: int) -> None:
        vuln = item.data(0, Qt.ItemDataRole.UserRole)
        if not vuln:
            return
        self._detail_title.setText(vuln.get("name", ""))
        self._detail_badge.setSeverity(vuln.get("severity", "LOW"))
        self._detail_cve.setText(vuln.get("cve_id", ""))
        self._detail_host.setText(
            f"  {vuln.get('host', '')}:{vuln.get('port', '')}  "
        )
        self._detail_cvss.setText(f"  CVSS: {vuln.get('cvss_score', 0):.1f}")
        self._detail_desc.setPlainText(vuln.get("description", ""))
        self._detail_rem.setPlainText(vuln.get("remediation", ""))
        ver = vuln.get("detected_version", "")
        self._detail_ver.setText(ver if ver else "Unknown")
