"""
Settings page — application preferences and configuration.
"""
from __future__ import annotations

import json
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QFrame,
    QSlider,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from gui import ACCENT, BG_CARD, BORDER, TEXT_SECONDARY
from utils.logger import logger

SETTINGS_FILE = Path(__file__).resolve().parent.parent / "settings.json"

DEFAULT_SETTINGS = {
    "default_threads": 150,
    "default_timeout": 1.0,
    "default_port_preset": "Common Ports (32)",
    "detect_services": True,
    "detect_vulns": True,
    "max_targets_per_scan": 256,
    "report_company": "",
    "report_author": "",
    "theme": "dark",
    "auto_save_results": True,
    "show_closed_ports": False,
}


def load_settings() -> dict:
    """Load settings from disk, falling back to defaults for missing keys."""
    if not SETTINGS_FILE.exists():
        return dict(DEFAULT_SETTINGS)
    try:
        loaded = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        return {**DEFAULT_SETTINGS, **loaded}
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_SETTINGS)


def save_settings(settings: dict) -> None:
    """Persist settings to disk."""
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")


class SettingsPage(QWidget):
    """Application settings with save/reset controls."""

    settings_changed = pyqtSignal(dict)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._settings = load_settings()
        self._build_ui()
        self._populate()

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

        title = QLabel("Settings")
        title.setObjectName("pageTitle")
        sub = QLabel("Configure scan defaults, appearance, and report metadata")
        sub.setObjectName("pageSubtitle")
        layout.addWidget(title)
        layout.addWidget(sub)

        # Scan defaults
        scan_grp = QGroupBox("Scan Defaults")
        scan_form = QFormLayout(scan_grp)
        scan_form.setSpacing(12)

        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 1000)
        scan_form.addRow("Default Thread Count:", self._threads_spin)

        self._timeout_spin = QDoubleSpinBox()
        self._timeout_spin.setRange(0.1, 30.0)
        self._timeout_spin.setSingleStep(0.1)
        self._timeout_spin.setSuffix(" s")
        scan_form.addRow("Default Timeout:", self._timeout_spin)

        self._preset_combo = QComboBox()
        for p in ["Common Ports (32)", "Well-Known (1–1023)", "Top 1000",
                  "All Ports (1–65535)"]:
            self._preset_combo.addItem(p)
        scan_form.addRow("Default Port Preset:", self._preset_combo)

        self._svc_detect = QCheckBox("Enable service detection by default")
        scan_form.addRow("", self._svc_detect)

        self._vuln_detect = QCheckBox("Enable vulnerability analysis by default")
        scan_form.addRow("", self._vuln_detect)

        self._max_targets = QSpinBox()
        self._max_targets.setRange(1, 4096)
        scan_form.addRow("Max Targets per Scan:", self._max_targets)

        layout.addWidget(scan_grp)

        # Display
        disp_grp = QGroupBox("Display")
        disp_form = QFormLayout(disp_grp)
        disp_form.setSpacing(12)

        self._show_closed = QCheckBox("Show closed/filtered ports in results")
        disp_form.addRow("", self._show_closed)

        self._auto_save = QCheckBox("Auto-save scan results to database")
        disp_form.addRow("", self._auto_save)

        layout.addWidget(disp_grp)

        # Report metadata
        report_grp = QGroupBox("Report Metadata")
        report_form = QFormLayout(report_grp)
        report_form.setSpacing(12)

        from PyQt6.QtWidgets import QLineEdit
        self._company_input = QLineEdit()
        self._company_input.setPlaceholderText("e.g. Acme Security Consulting")
        report_form.addRow("Organisation:", self._company_input)

        self._author_input = QLineEdit()
        self._author_input.setPlaceholderText("e.g. Jane Smith")
        report_form.addRow("Report Author:", self._author_input)

        layout.addWidget(report_grp)

        # Database
        db_grp = QGroupBox("Database")
        db_layout = QVBoxLayout(db_grp)

        from database.db_manager import DB_PATH
        db_path_lbl = QLabel(f"Database: {DB_PATH}")
        db_path_lbl.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        db_layout.addWidget(db_path_lbl)

        db_btn_row = QHBoxLayout()
        clear_btn = QPushButton("Clear All Scan History")
        clear_btn.setObjectName("dangerBtn")
        clear_btn.clicked.connect(self._clear_history)
        db_btn_row.addWidget(clear_btn)
        db_btn_row.addStretch()
        db_layout.addLayout(db_btn_row)
        layout.addWidget(db_grp)

        # About
        about_grp = QGroupBox("About VulnScan Pro")
        about_layout = QVBoxLayout(about_grp)
        about_txt = QLabel(
            "<b style='color: #00d4ff;'>VulnScan Pro v1.0</b><br>"
            "Professional vulnerability scanner for authorised security assessments.<br>"
            "Built with Python 3.13 · PyQt6 · SQLite · ReportLab<br><br>"
            "<span style='color: #ff4444;'>⚠ For use only on systems you own or have "
            "explicit written authorisation to test.</span>"
        )
        about_txt.setTextFormat(Qt.TextFormat.RichText)
        about_txt.setWordWrap(True)
        about_layout.addWidget(about_txt)
        layout.addWidget(about_grp)

        # Save / reset buttons
        btn_row = QHBoxLayout()
        save_btn = QPushButton("💾  Save Settings")
        save_btn.setObjectName("primaryBtn")
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(save_btn)

        reset_btn = QPushButton("↺  Reset to Defaults")
        reset_btn.clicked.connect(self._reset)
        btn_row.addWidget(reset_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        layout.addStretch()

    def _populate(self) -> None:
        s = self._settings
        self._threads_spin.setValue(s.get("default_threads", 150))
        self._timeout_spin.setValue(s.get("default_timeout", 1.0))
        idx = self._preset_combo.findText(s.get("default_port_preset", "Common Ports (32)"))
        self._preset_combo.setCurrentIndex(max(idx, 0))
        self._svc_detect.setChecked(s.get("detect_services", True))
        self._vuln_detect.setChecked(s.get("detect_vulns", True))
        self._max_targets.setValue(s.get("max_targets_per_scan", 256))
        self._show_closed.setChecked(s.get("show_closed_ports", False))
        self._auto_save.setChecked(s.get("auto_save_results", True))

        from PyQt6.QtWidgets import QLineEdit
        for child in self.findChildren(QLineEdit):
            obj_name = child.objectName()
            if "company" in obj_name or not obj_name:
                pass
        self._company_input.setText(s.get("report_company", ""))
        self._author_input.setText(s.get("report_author", ""))

    def _collect(self) -> dict:
        return {
            "default_threads": self._threads_spin.value(),
            "default_timeout": self._timeout_spin.value(),
            "default_port_preset": self._preset_combo.currentText(),
            "detect_services": self._svc_detect.isChecked(),
            "detect_vulns": self._vuln_detect.isChecked(),
            "max_targets_per_scan": self._max_targets.value(),
            "show_closed_ports": self._show_closed.isChecked(),
            "auto_save_results": self._auto_save.isChecked(),
            "report_company": self._company_input.text(),
            "report_author": self._author_input.text(),
            "theme": "dark",
        }

    def _save(self) -> None:
        self._settings = self._collect()
        save_settings(self._settings)
        self.settings_changed.emit(self._settings)
        QMessageBox.information(self, "Saved", "Settings saved successfully.")

    def _reset(self) -> None:
        reply = QMessageBox.question(
            self, "Reset Settings",
            "Reset all settings to defaults?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._settings = dict(DEFAULT_SETTINGS)
            self._populate()

    def _clear_history(self) -> None:
        reply = QMessageBox.question(
            self, "Clear History",
            "Delete ALL scan history, ports, and vulnerabilities from the database?\n"
            "This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            import sqlite3
            from database.db_manager import DB_PATH
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute("DELETE FROM vulnerabilities")
            conn.execute("DELETE FROM port_results")
            conn.execute("DELETE FROM scans")
            conn.commit()
            conn.close()
            QMessageBox.information(self, "Done", "All scan history has been cleared.")

    def get_settings(self) -> dict:
        return dict(self._settings)
