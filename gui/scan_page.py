"""
Scan configuration and execution page for VulnScan Pro.
"""
from __future__ import annotations

from datetime import datetime
from typing import List

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSlider,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.scanner import PortScanWorker, ScanConfig
from core.vuln_engine import VulnerabilityEngine
from core.risk_calculator import RiskCalculator
from database import db_manager
from gui import ACCENT, ACCENT_GREEN, SEV_HIGH, SEV_MEDIUM, SEVERITY_COLORS, TEXT_SECONDARY
from gui.widgets.severity_badge import SeverityBadge
from utils.validators import parse_port_range, parse_targets
from utils.network_utils import COMMON_PORTS, WELL_KNOWN_PORTS, TOP_1000_PORTS
from utils.logger import logger


PORT_PRESETS = {
    "Common Ports (32)": COMMON_PORTS,
    "Well-Known (1–1023)": WELL_KNOWN_PORTS,
    "Top 1000": TOP_1000_PORTS,
    "All Ports (1–65535)": list(range(1, 65536)),
    "Custom": [],
}


class ScanPage(QWidget):
    """Full scan configuration + real-time execution view."""

    scan_started = pyqtSignal(str)           # scan_id
    scan_finished = pyqtSignal(str, list, list)  # scan_id, port_results, vulns

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: PortScanWorker | None = None
        self._current_scan_id = ""
        self._all_port_results: list[dict] = []
        self._build_ui()

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        main = QVBoxLayout(self)
        main.setContentsMargins(28, 24, 28, 24)
        main.setSpacing(16)

        # Header
        hdr = QVBoxLayout()
        title = QLabel("New Vulnerability Scan")
        title.setObjectName("pageTitle")
        sub = QLabel("Configure and launch a scan against authorised targets only")
        sub.setObjectName("pageSubtitle")
        hdr.addWidget(title)
        hdr.addWidget(sub)
        main.addLayout(hdr)

        # Main splitter: config left / log right
        splitter = QSplitter(Qt.Orientation.Vertical)

        # ── Top: config + live results
        top_widget = QWidget()
        top_layout = QHBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(14)

        top_layout.addWidget(self._build_config_panel(), 2)
        top_layout.addWidget(self._build_live_results_panel(), 3)
        splitter.addWidget(top_widget)

        # ── Bottom: console log
        splitter.addWidget(self._build_console_panel())
        splitter.setSizes([340, 200])
        main.addWidget(splitter)

    def _build_config_panel(self) -> QWidget:
        box = QGroupBox("Scan Configuration")
        layout = QVBoxLayout(box)
        layout.setSpacing(10)

        # Target
        layout.addWidget(QLabel("Target (IP / CIDR / Hostname / Range):"))
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("e.g. 192.168.1.1 or 10.0.0.0/24")
        layout.addWidget(self._target_input)

        # Port preset
        layout.addWidget(QLabel("Port Range:"))
        self._port_preset = QComboBox()
        for name in PORT_PRESETS:
            self._port_preset.addItem(name)
        self._port_preset.currentTextChanged.connect(self._on_preset_changed)
        layout.addWidget(self._port_preset)

        self._custom_ports = QLineEdit()
        self._custom_ports.setPlaceholderText("e.g. 80,443,8080-8090")
        self._custom_ports.setVisible(False)
        layout.addWidget(self._custom_ports)

        # Threads
        thread_row = QHBoxLayout()
        thread_row.addWidget(QLabel("Threads:"))
        self._thread_label = QLabel("150")
        self._thread_label.setStyleSheet(f"color: {ACCENT}; font-weight: bold;")
        thread_row.addWidget(self._thread_label)
        thread_row.addStretch()
        layout.addLayout(thread_row)
        self._thread_slider = QSlider(Qt.Orientation.Horizontal)
        self._thread_slider.setRange(10, 500)
        self._thread_slider.setValue(150)
        self._thread_slider.setTickInterval(50)
        self._thread_slider.valueChanged.connect(
            lambda v: self._thread_label.setText(str(v))
        )
        layout.addWidget(self._thread_slider)

        # Timeout
        timeout_row = QHBoxLayout()
        timeout_row.addWidget(QLabel("Timeout (s):"))
        self._timeout_spin = QDoubleSpinBox()
        self._timeout_spin.setRange(0.1, 10.0)
        self._timeout_spin.setValue(1.0)
        self._timeout_spin.setSingleStep(0.1)
        timeout_row.addWidget(self._timeout_spin)
        timeout_row.addStretch()
        layout.addLayout(timeout_row)

        # Options
        self._detect_services = QCheckBox("Service detection & banner grabbing")
        self._detect_services.setChecked(True)
        self._detect_vulns = QCheckBox("Vulnerability analysis")
        self._detect_vulns.setChecked(True)
        layout.addWidget(self._detect_services)
        layout.addWidget(self._detect_vulns)

        layout.addStretch()

        # Action buttons
        btn_row = QHBoxLayout()
        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setObjectName("primaryBtn")
        self._start_btn.clicked.connect(self._start_scan)
        self._stop_btn = QPushButton("■  Stop")
        self._stop_btn.setObjectName("dangerBtn")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_scan)
        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        layout.addLayout(btn_row)

        # Progress
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        layout.addWidget(self._progress)

        self._status_label = QLabel("Ready")
        self._status_label.setObjectName("mutedLabel")
        layout.addWidget(self._status_label)

        return box

    def _build_live_results_panel(self) -> QWidget:
        box = QGroupBox("Live Results — Open Ports")
        layout = QVBoxLayout(box)

        self._results_table = QTableWidget(0, 6)
        self._results_table.setHorizontalHeaderLabels(
            ["Host", "Port", "Service", "Product", "Version", "Banner"]
        )
        self._results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._results_table.setAlternatingRowColors(True)
        self._results_table.verticalHeader().setVisible(False)
        self._results_table.horizontalHeader().setStretchLastSection(True)
        self._results_table.setShowGrid(False)
        layout.addWidget(self._results_table)

        return box

    def _build_console_panel(self) -> QWidget:
        box = QGroupBox("Scan Console")
        layout = QVBoxLayout(box)

        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        f = QFont("Cascadia Code", 10) if True else QFont("Courier New", 10)
        self._console.setFont(f)
        self._console.setStyleSheet(
            "background-color: #080c14; color: #00d4ff; border: none;"
        )
        layout.addWidget(self._console)

        btn_row = QHBoxLayout()
        clear_btn = QPushButton("Clear Console")
        clear_btn.clicked.connect(self._console.clear)
        btn_row.addWidget(clear_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return box

    # ── Signal handlers ────────────────────────────────────────────────────────

    def _on_preset_changed(self, text: str) -> None:
        self._custom_ports.setVisible(text == "Custom")

    def _start_scan(self) -> None:
        target_text = self._target_input.text().strip()
        if not target_text:
            self._console_log("[!] Please enter a target.")
            return

        targets, err = parse_targets(target_text)
        if err:
            self._console_log(f"[!] Invalid target: {err}")
            return

        preset_name = self._port_preset.currentText()
        if preset_name == "Custom":
            port_str = self._custom_ports.text().strip()
            if not port_str:
                self._console_log("[!] Please enter custom ports.")
                return
            try:
                ports = parse_port_range(port_str)
            except ValueError as exc:
                self._console_log(f"[!] Invalid port range: {exc}")
                return
        else:
            ports = PORT_PRESETS[preset_name]

        config = ScanConfig(
            targets=targets,
            ports=ports,
            thread_count=self._thread_slider.value(),
            timeout=self._timeout_spin.value(),
            detect_services=self._detect_services.isChecked(),
            scan_name=f"Scan {datetime.now().strftime('%H:%M:%S')}",
        )

        scan_cfg = {
            "port_preset": preset_name,
            "thread_count": config.thread_count,
            "timeout": config.timeout,
            "detect_services": config.detect_services,
        }
        self._current_scan_id = db_manager.create_scan(
            target=target_text, config=scan_cfg, name=config.scan_name
        )

        self._all_port_results.clear()
        self._results_table.setRowCount(0)
        self._console.clear()
        self._progress.setValue(0)

        self._worker = PortScanWorker(config)
        self._worker.progress_updated.connect(self._on_progress)
        self._worker.port_found.connect(self._on_port_found)
        self._worker.scan_finished.connect(self._on_scan_finished)
        self._worker.log_message.connect(self._console_log)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.start()

        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._status_label.setText("Scanning…")
        self.scan_started.emit(self._current_scan_id)

    def _stop_scan(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.stop()
        self._stop_btn.setEnabled(False)
        self._status_label.setText("Stopping…")

    def _on_progress(self, completed: int, total: int) -> None:
        pct = int(completed / total * 100) if total else 0
        self._progress.setValue(pct)
        self._status_label.setText(f"Progress: {completed:,}/{total:,} probes ({pct}%)")

    def _on_port_found(self, result: dict) -> None:
        self._all_port_results.append(result)
        tbl = self._results_table
        row = tbl.rowCount()
        tbl.insertRow(row)
        for col, key in enumerate(["host", "port", "service", "product", "version", "banner"]):
            val = str(result.get(key, ""))
            item = QTableWidgetItem(val[:80] if key == "banner" else val)
            tbl.setItem(row, col, item)
        tbl.scrollToBottom()

    def _on_scan_finished(self, open_results: list) -> None:
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._progress.setValue(100)
        self._status_label.setText(
            f"Done — {len(open_results)} open port(s) found"
        )
        self._console_log(f"\n[*] Saving results to database...")

        # Save port results
        db_manager.save_port_results(self._current_scan_id, open_results)

        # Run vulnerability analysis
        vulns: list[dict] = []
        if self._detect_vulns.isChecked() and open_results:
            self._console_log("[*] Running vulnerability analysis...")
            engine = VulnerabilityEngine()
            vulns = engine.analyze(open_results)
            self._console_log(f"[*] Found {len(vulns)} vulnerability finding(s).")
            db_manager.save_vulnerabilities(self._current_scan_id, vulns)

        risk_score = RiskCalculator.calculate(vulns)
        unique_hosts = len({r["host"] for r in open_results})
        db_manager.finish_scan(
            self._current_scan_id,
            total_hosts=unique_hosts,
            open_ports=len(open_results),
            total_vulns=len(vulns),
            risk_score=risk_score,
        )
        self._console_log(
            f"[✓] Scan saved (ID: {self._current_scan_id[:8]}…) | "
            f"Risk score: {risk_score:.1f}/100"
        )
        self.scan_finished.emit(self._current_scan_id, open_results, vulns)

    def _on_error(self, msg: str) -> None:
        self._console_log(f"[ERROR] {msg}")
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_label.setText("Error")
        db_manager.fail_scan(self._current_scan_id, msg)

    def _console_log(self, text: str) -> None:
        self._console.appendPlainText(text)
