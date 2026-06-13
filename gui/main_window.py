"""
Main application window for VulnScan Pro.

Implements the sidebar navigation and QStackedWidget page management.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from database import db_manager
from gui import ACCENT, BG_CARD, BG_PRIMARY, BG_SECONDARY, BORDER, DARK_STYLESHEET, TEXT_SECONDARY
from gui.dashboard import DashboardPage
from gui.history_page import HistoryPage
from gui.reports_page import ReportsPage
from gui.results_page import ResultsPage
from gui.scan_page import ScanPage
from gui.settings_page import SettingsPage
from utils.logger import logger


# Sidebar navigation items: (icon, label, page_index)
NAV_ITEMS = [
    ("📊", "Dashboard",     0),
    ("🔍", "New Scan",      1),
    ("🛡", "Results",       2),
    ("📋", "Reports",       3),
    ("🕒", "Scan History",  4),
    ("⚙", "Settings",      5),
]


class NavButton(QPushButton):
    """Sidebar navigation button with active-state styling."""

    def __init__(self, icon: str, label: str, parent=None) -> None:
        super().__init__(f"  {icon}  {label}", parent)
        self.setObjectName("navBtn")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setCheckable(False)
        self._active = False

    def set_active(self, active: bool) -> None:
        self._active = active
        self.setProperty("active", str(active).lower())
        self.style().unpolish(self)
        self.style().polish(self)


class Sidebar(QWidget):
    """Left navigation panel."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self._nav_buttons: list[NavButton] = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo / title area
        logo_widget = QWidget()
        logo_widget.setFixedHeight(80)
        logo_layout = QVBoxLayout(logo_widget)
        logo_layout.setContentsMargins(18, 16, 18, 8)
        logo_layout.setSpacing(2)

        logo_lbl = QLabel("⚡ VulnScan Pro")
        logo_lbl.setObjectName("sidebarTitle")
        f = QFont("Segoe UI", 14)
        f.setBold(True)
        logo_lbl.setFont(f)

        ver_lbl = QLabel("v1.0  —  Defensive Security Tool")
        ver_lbl.setObjectName("sidebarVersion")

        logo_layout.addWidget(logo_lbl)
        logo_layout.addWidget(ver_lbl)
        layout.addWidget(logo_widget)

        # Divider
        divider = QWidget()
        divider.setFixedHeight(1)
        divider.setStyleSheet(f"background-color: {BORDER};")
        layout.addWidget(divider)
        layout.addSpacing(10)

        # Nav section label
        nav_lbl = QLabel("  NAVIGATION")
        nav_lbl.setStyleSheet(
            f"color: {TEXT_SECONDARY}; font-size: 10px; font-weight: bold; "
            f"letter-spacing: 1px; padding: 0 18px;"
        )
        layout.addWidget(nav_lbl)
        layout.addSpacing(4)

        # Navigation buttons
        for icon, label, idx in NAV_ITEMS:
            btn = NavButton(icon, label)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            btn.setFixedHeight(42)
            layout.addWidget(btn)
            self._nav_buttons.append(btn)

        layout.addStretch()

        # Footer
        footer_divider = QWidget()
        footer_divider.setFixedHeight(1)
        footer_divider.setStyleSheet(f"background-color: {BORDER};")
        layout.addWidget(footer_divider)

        footer = QLabel("  ⚠  Authorised use only")
        footer.setStyleSheet(
            "color: #ff8c00; font-size: 10px; padding: 10px 4px;"
        )
        footer.setWordWrap(True)
        layout.addWidget(footer)

    def nav_buttons(self) -> list[NavButton]:
        return self._nav_buttons

    def set_active(self, index: int) -> None:
        for i, btn in enumerate(self._nav_buttons):
            btn.set_active(i == index)


class MainWindow(QMainWindow):
    """
    Top-level application window.

    Hosts the sidebar, stacked pages, and status bar.
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("VulnScan Pro — Vulnerability Scanner")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 900)
        self.setStyleSheet(DARK_STYLESHEET)
        self._current_scan_id = ""
        self._build_ui()
        self._connect_signals()
        self._navigate(0)
        # Refresh dashboard on startup
        QTimer.singleShot(200, self._dashboard.refresh)

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        self._sidebar = Sidebar()
        main_layout.addWidget(self._sidebar)

        # Pages
        self._stack = QStackedWidget()
        self._dashboard = DashboardPage()
        self._scan_page = ScanPage()
        self._results_page = ResultsPage()
        self._reports_page = ReportsPage()
        self._history_page = HistoryPage()
        self._settings_page = SettingsPage()

        for page in [
            self._dashboard,
            self._scan_page,
            self._results_page,
            self._reports_page,
            self._history_page,
            self._settings_page,
        ]:
            self._stack.addWidget(page)

        main_layout.addWidget(self._stack)

        # Status bar
        status = QStatusBar()
        status.setFixedHeight(26)
        self.setStatusBar(status)
        self._status_lbl = QLabel("Ready")
        self._clock_lbl = QLabel()
        status.addWidget(self._status_lbl)
        status.addPermanentWidget(self._clock_lbl)

        self._clock_timer = QTimer()
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start(1000)
        self._update_clock()

    def _connect_signals(self) -> None:
        # Sidebar navigation
        for i, btn in enumerate(self._sidebar.nav_buttons()):
            btn.clicked.connect(lambda checked, idx=i: self._navigate(idx))

        # Scan page signals
        self._scan_page.scan_started.connect(self._on_scan_started)
        self._scan_page.scan_finished.connect(self._on_scan_finished)

        # History page load request
        self._history_page.load_scan_requested.connect(self._load_scan_from_history)

    # ── Navigation ─────────────────────────────────────────────────────────────

    def _navigate(self, index: int) -> None:
        self._stack.setCurrentIndex(index)
        self._sidebar.set_active(index)

        # Refresh data-driven pages on navigation
        if index == 0:
            self._dashboard.refresh()
        elif index == 3:
            self._reports_page.refresh()
        elif index == 4:
            self._history_page.refresh()

    # ── Scan lifecycle ─────────────────────────────────────────────────────────

    def _on_scan_started(self, scan_id: str) -> None:
        self._current_scan_id = scan_id
        self._status_lbl.setText(f"Scan running… [{scan_id[:8]}]")
        logger.info("Scan started: %s", scan_id)

    def _on_scan_finished(
        self, scan_id: str, port_results: list, vulnerabilities: list
    ) -> None:
        self._status_lbl.setText(
            f"Scan complete — {len(port_results)} ports | "
            f"{len(vulnerabilities)} findings [{scan_id[:8]}]"
        )
        # Load results into results page and navigate there
        self._results_page.load_scan(scan_id, port_results, vulnerabilities)
        self._navigate(2)
        logger.info("Scan %s finished with %d vulns", scan_id, len(vulnerabilities))

    def _load_scan_from_history(self, scan_id: str) -> None:
        """Load a historical scan into the results page and show it."""
        ports = db_manager.get_port_results(scan_id)
        vulns = db_manager.get_vulnerabilities(scan_id)
        self._results_page.load_scan(scan_id, ports, vulns)
        self._navigate(2)

    # ── Clock ──────────────────────────────────────────────────────────────────

    def _update_clock(self) -> None:
        from datetime import datetime
        self._clock_lbl.setText(datetime.now().strftime("  %Y-%m-%d  %H:%M:%S  "))
