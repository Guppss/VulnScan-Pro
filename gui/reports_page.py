"""
Reports page — generate and manage PDF vulnerability reports.
"""
from __future__ import annotations

import os
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from database import db_manager
from reports.pdf_generator import PDFGenerator
from utils.logger import logger

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports_output"


class _PDFWorker(QThread):
    """Background thread for PDF generation to keep GUI responsive."""

    finished = pyqtSignal(str)   # output path
    failed = pyqtSignal(str)     # error message

    def __init__(self, scan_id: str, output_path: str, parent=None):
        super().__init__(parent)
        self._scan_id = scan_id
        self._output_path = output_path

    def run(self) -> None:
        try:
            scan = db_manager.get_scan(self._scan_id)
            if not scan:
                self.failed.emit(f"Scan {self._scan_id} not found.")
                return
            ports = db_manager.get_port_results(self._scan_id)
            vulns = db_manager.get_vulnerabilities(self._scan_id)
            from core.risk_calculator import RiskCalculator
            risk = RiskCalculator.calculate(vulns)
            PDFGenerator.generate(self._output_path, scan, ports, vulns, risk)
            self.finished.emit(self._output_path)
        except Exception as exc:
            logger.exception("PDF generation failed")
            self.failed.emit(str(exc))


class ReportsPage(QWidget):
    """UI for selecting scans and generating PDF reports."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: _PDFWorker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # Header
        title = QLabel("Reports")
        title.setObjectName("pageTitle")
        sub = QLabel("Generate professional PDF vulnerability assessment reports")
        sub.setObjectName("pageSubtitle")
        layout.addWidget(title)
        layout.addWidget(sub)

        # Scan selection table
        sel_lbl = QLabel("Select a scan to generate a report:")
        sel_lbl.setObjectName("sectionTitle")
        layout.addWidget(sel_lbl)

        self._scan_table = QTableWidget(0, 6)
        self._scan_table.setHorizontalHeaderLabels(
            ["Name", "Target", "Date", "Vulns", "Risk", "Status"]
        )
        self._scan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._scan_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._scan_table.setAlternatingRowColors(True)
        self._scan_table.verticalHeader().setVisible(False)
        self._scan_table.horizontalHeader().setStretchLastSection(True)
        self._scan_table.setShowGrid(False)
        layout.addWidget(self._scan_table)

        # Actions
        btn_row = QHBoxLayout()
        self._gen_btn = QPushButton("📋  Generate PDF Report")
        self._gen_btn.setObjectName("primaryBtn")
        self._gen_btn.clicked.connect(self._generate_pdf)
        btn_row.addWidget(self._gen_btn)

        self._open_btn = QPushButton("📂  Open Reports Folder")
        self._open_btn.clicked.connect(self._open_reports_folder)
        btn_row.addWidget(self._open_btn)

        refresh_btn = QPushButton("⟳ Refresh")
        refresh_btn.clicked.connect(self.refresh)
        btn_row.addWidget(refresh_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Progress
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # indeterminate
        self._progress.setVisible(False)
        layout.addWidget(self._progress)

        self._status_label = QLabel("")
        self._status_label.setObjectName("mutedLabel")
        layout.addWidget(self._status_label)

        layout.addStretch()

    def refresh(self) -> None:
        """Reload the scan list from the database."""
        scans = db_manager.get_all_scans()
        tbl = self._scan_table
        tbl.setRowCount(0)
        for scan in scans:
            if scan.get("status") != "completed":
                continue
            row = tbl.rowCount()
            tbl.insertRow(row)
            name_item = QTableWidgetItem(scan.get("name", ""))
            name_item.setData(0x0100, scan["id"])  # Qt.UserRole
            tbl.setItem(row, 0, name_item)
            tbl.setItem(row, 1, QTableWidgetItem(scan.get("target", "")))
            tbl.setItem(row, 2, QTableWidgetItem(
                scan.get("scan_date", "")[:16].replace("T", " ")
            ))
            tbl.setItem(row, 3, QTableWidgetItem(str(scan.get("total_vulns", 0))))
            tbl.setItem(row, 4, QTableWidgetItem(f"{scan.get('risk_score', 0):.1f}"))
            tbl.setItem(row, 5, QTableWidgetItem("COMPLETED"))
        tbl.resizeColumnsToContents()

    def _get_selected_scan_id(self) -> str | None:
        rows = self._scan_table.selectedItems()
        if not rows:
            return None
        row = self._scan_table.currentRow()
        item = self._scan_table.item(row, 0)
        return item.data(0x0100) if item else None

    def _generate_pdf(self) -> None:
        scan_id = self._get_selected_scan_id()
        if not scan_id:
            QMessageBox.information(self, "No Selection", "Please select a scan first.")
            return

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        scan = db_manager.get_scan(scan_id)
        scan_date = (scan.get("scan_date", "")[:10] if scan else "")
        safe_name = (scan.get("name", scan_id[:8]) if scan else scan_id[:8])
        safe_name = safe_name.replace(" ", "_").replace(":", "-")
        default_name = str(REPORTS_DIR / f"VulnScan_{safe_name}_{scan_date}.pdf")

        path, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Report", default_name, "PDF Files (*.pdf)"
        )
        if not path:
            return

        self._gen_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._status_label.setText("Generating PDF report…")

        self._worker = _PDFWorker(scan_id, path)
        self._worker.finished.connect(self._on_pdf_done)
        self._worker.failed.connect(self._on_pdf_failed)
        self._worker.start()

    def _on_pdf_done(self, path: str) -> None:
        self._gen_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._status_label.setText(f"Report saved: {path}")
        reply = QMessageBox.question(
            self,
            "Report Generated",
            f"PDF report saved to:\n{path}\n\nOpen it now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            os.startfile(path) if os.name == "nt" else os.system(f'open "{path}"')

    def _on_pdf_failed(self, msg: str) -> None:
        self._gen_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._status_label.setText("Report generation failed.")
        QMessageBox.critical(self, "Report Failed", msg)

    def _open_reports_folder(self) -> None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        path = str(REPORTS_DIR)
        if os.name == "nt":
            os.startfile(path)
        else:
            os.system(f'open "{path}"')
