"""
Scan history page — browse, load, export, and delete past scans.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from database import db_manager
from gui import ACCENT, SEVERITY_COLORS, TEXT_SECONDARY
from utils.logger import logger
import csv
from pathlib import Path


class HistoryPage(QWidget):
    """Lists all historical scans and provides controls to manage them."""

    load_scan_requested = pyqtSignal(str)  # scan_id

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # Header
        hdr_row = QHBoxLayout()
        title = QLabel("Scan History")
        title.setObjectName("pageTitle")
        sub = QLabel("Review and manage all past vulnerability scans")
        sub.setObjectName("pageSubtitle")
        hdr_col = QVBoxLayout()
        hdr_col.addWidget(title)
        hdr_col.addWidget(sub)
        hdr_row.addLayout(hdr_col)
        hdr_row.addStretch()

        refresh_btn = QPushButton("⟳ Refresh")
        refresh_btn.clicked.connect(self.refresh)
        hdr_row.addWidget(refresh_btn)
        layout.addLayout(hdr_row)

        # Table
        self._table = QTableWidget(0, 8)
        self._table.setHorizontalHeaderLabels(
            ["Name", "Target", "Date", "Hosts", "Open Ports", "Vulns", "Risk", "Status"]
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setShowGrid(False)
        self._table.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self._table)

        # Action buttons
        btn_row = QHBoxLayout()
        load_btn = QPushButton("📂  Load Selected Scan")
        load_btn.setObjectName("primaryBtn")
        load_btn.clicked.connect(self._load_selected)
        btn_row.addWidget(load_btn)

        export_btn = QPushButton("📄  Export to CSV")
        export_btn.clicked.connect(self._export_csv)
        btn_row.addWidget(export_btn)

        btn_row.addStretch()

        delete_btn = QPushButton("🗑  Delete Selected")
        delete_btn.setObjectName("dangerBtn")
        delete_btn.clicked.connect(self._delete_selected)
        btn_row.addWidget(delete_btn)

        layout.addLayout(btn_row)

    def refresh(self) -> None:
        """Reload scan history from the database."""
        scans = db_manager.get_all_scans()
        tbl = self._table
        tbl.setRowCount(0)
        for scan in scans:
            row = tbl.rowCount()
            tbl.insertRow(row)

            name_item = QTableWidgetItem(scan.get("name", ""))
            name_item.setData(Qt.ItemDataRole.UserRole, scan["id"])
            tbl.setItem(row, 0, name_item)
            tbl.setItem(row, 1, QTableWidgetItem(scan.get("target", "")))
            tbl.setItem(row, 2, QTableWidgetItem(
                scan.get("scan_date", "")[:16].replace("T", " ")
            ))
            tbl.setItem(row, 3, QTableWidgetItem(str(scan.get("total_hosts", 0))))
            tbl.setItem(row, 4, QTableWidgetItem(str(scan.get("open_ports", 0))))
            tbl.setItem(row, 5, QTableWidgetItem(str(scan.get("total_vulns", 0))))
            tbl.setItem(row, 6, QTableWidgetItem(f"{scan.get('risk_score', 0):.1f}"))

            status = scan.get("status", "").upper()
            status_item = QTableWidgetItem(status)
            if status == "COMPLETED":
                status_item.setForeground(Qt.GlobalColor.green)
            elif status == "FAILED":
                status_item.setForeground(Qt.GlobalColor.red)
            elif status == "RUNNING":
                status_item.setForeground(Qt.GlobalColor.yellow)
            tbl.setItem(row, 7, status_item)

        tbl.resizeColumnsToContents()

    def _get_selected_scan_id(self) -> str | None:
        rows = self._table.selectedItems()
        if not rows:
            return None
        row = self._table.currentRow()
        item = self._table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _load_selected(self) -> None:
        scan_id = self._get_selected_scan_id()
        if scan_id:
            self.load_scan_requested.emit(scan_id)

    def _on_double_click(self) -> None:
        self._load_selected()

    def _delete_selected(self) -> None:
        scan_id = self._get_selected_scan_id()
        if not scan_id:
            return
        row = self._table.currentRow()
        name = self._table.item(row, 0)
        name_str = name.text() if name else "this scan"
        reply = QMessageBox.question(
            self,
            "Delete Scan",
            f"Permanently delete '{name_str}' and all its results?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            db_manager.delete_scan(scan_id)
            self.refresh()

    def _export_csv(self) -> None:
        """Export all scan history to a CSV file."""
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Scan History", "vulnscan_history.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        scans = db_manager.get_all_scans()
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "id", "name", "target", "scan_date", "status",
                        "total_hosts", "open_ports", "total_vulns", "risk_score",
                    ],
                )
                writer.writeheader()
                for scan in scans:
                    writer.writerow({k: scan.get(k, "") for k in writer.fieldnames})
            QMessageBox.information(self, "Export Complete", f"History exported to:\n{path}")
        except OSError as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))
