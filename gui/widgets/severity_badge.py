"""
SeverityBadge — a coloured pill label for vulnerability severity levels.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QLabel, QSizePolicy

from gui import SEVERITY_COLORS

_BADGE_BG: dict[str, str] = {
    "CRITICAL": "#3d0015",
    "HIGH":     "#3d0f0f",
    "MEDIUM":   "#3d2d00",
    "LOW":      "#0d2d16",
    "INFORMATIONAL": "#003340",
}


class SeverityBadge(QLabel):
    """
    Coloured pill badge that displays a severity string.

    Usage::

        badge = SeverityBadge("CRITICAL")
        layout.addWidget(badge)
    """

    def __init__(self, severity: str = "LOW", parent=None) -> None:
        super().__init__(parent)
        self.setSeverity(severity)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(9)
        font.setBold(True)
        self.setFont(font)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def setSeverity(self, severity: str) -> None:
        """Set the displayed severity and re-style the badge."""
        sev = severity.upper()
        fg = SEVERITY_COLORS.get(sev, "#8b949e")
        bg = _BADGE_BG.get(sev, "#1a1a2e")
        self._severity = sev
        self.setText(sev)
        self.setStyleSheet(
            f"color: {fg}; background-color: {bg}; border: 1px solid {fg};"
            f"border-radius: 10px; padding: 2px 10px;"
        )

    def severity(self) -> str:
        return self._severity
