"""
VulnScan Pro — Professional Vulnerability Scanner
Entry point for the desktop application.

IMPORTANT NOTICE:
  This tool is for authorised security testing, educational research,
  and defensive cybersecurity purposes only.
  Only scan systems you own or have explicit written permission to test.
  Unauthorised scanning may be illegal in your jurisdiction.
"""
from __future__ import annotations

import sys
import os

# Ensure the project root is on sys.path regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _check_dependencies() -> None:
    """Verify required packages are installed and give helpful error messages."""
    missing = []
    try:
        import PyQt6
    except ImportError:
        missing.append("PyQt6")
    try:
        import reportlab
    except ImportError:
        missing.append("reportlab")

    if missing:
        print("=" * 60)
        print("VulnScan Pro — Missing Dependencies")
        print("=" * 60)
        print(f"\nThe following packages are required:\n  {', '.join(missing)}")
        print("\nInstall them with:")
        print(f"  pip install {' '.join(missing)}")
        print("\nOr install all at once:")
        print("  pip install -r requirements.txt")
        print("=" * 60)
        sys.exit(1)


def main() -> None:
    """Application entry point."""
    _check_dependencies()

    from PyQt6.QtWidgets import QApplication, QSplashScreen
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QColor, QPixmap, QPainter, QFont

    app = QApplication(sys.argv)
    app.setApplicationName("VulnScan Pro")
    app.setApplicationVersion("1.0")
    app.setOrganizationName("VulnScan")
    app.setStyle("Fusion")

    # Splash screen
    splash_pix = QPixmap(500, 300)
    splash_pix.fill(QColor("#0a0e1a"))
    painter = QPainter(splash_pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Accent bar
    painter.fillRect(0, 0, 500, 4, QColor("#00d4ff"))

    # Title
    f_big = QFont("Segoe UI", 28)
    f_big.setBold(True)
    painter.setFont(f_big)
    painter.setPen(QColor("#00d4ff"))
    painter.drawText(40, 80, "⚡ VulnScan Pro")

    painter.setFont(QFont("Segoe UI", 12))
    painter.setPen(QColor("#8b949e"))
    painter.drawText(44, 108, "Professional Vulnerability Scanner v1.0")

    # Warning notice
    painter.fillRect(20, 130, 460, 60, QColor("#1a0505"))
    painter.setPen(QColor("#ff4444"))
    painter.setFont(QFont("Segoe UI", 9))
    painter.drawText(
        30, 152,
        "⚠  Authorised use only. Scan only systems you own or"
    )
    painter.drawText(
        30, 172,
        "     have explicit written permission to test."
    )

    painter.setPen(QColor("#484f58"))
    painter.setFont(QFont("Segoe UI", 9))
    painter.drawText(40, 240, "Initialising…")
    painter.drawText(40, 268, "Python  ·  PyQt6  ·  SQLite  ·  ReportLab")
    painter.end()

    splash = QSplashScreen(splash_pix, Qt.WindowType.WindowStaysOnTopHint)
    splash.show()
    app.processEvents()

    # Initialise database
    from database.db_manager import init_db
    init_db()

    # Build main window
    from gui.main_window import MainWindow
    window = MainWindow()

    def _show_main():
        splash.finish(window)
        window.show()

    QTimer.singleShot(1500, _show_main)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
