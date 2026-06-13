"""
StatCard widget — a dashboard summary card showing a single metric.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QSizePolicy, QVBoxLayout, QWidget, QLabel

from gui import BG_CARD, BORDER, ACCENT, TEXT_PRIMARY, TEXT_SECONDARY


class StatCard(QWidget):
    """
    A metric card that displays an icon, label and numeric value.

    Parameters
    ----------
    title   : metric label text
    value   : initial display value (str or int)
    icon    : Unicode emoji / symbol shown at the top
    color   : hex accent colour for the icon and value
    """

    def __init__(
        self,
        title: str,
        value: str | int = "0",
        icon: str = "●",
        color: str = ACCENT,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._color = color
        self.setObjectName("card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(120)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(6)

        self._icon_label = QLabel(icon)
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        icon_font = QFont()
        icon_font.setPointSize(22)
        self._icon_label.setFont(icon_font)
        self._icon_label.setStyleSheet(f"color: {color}; background: transparent;")
        layout.addWidget(self._icon_label)

        self._value_label = QLabel(str(value))
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        val_font = QFont()
        val_font.setPointSize(26)
        val_font.setBold(True)
        self._value_label.setFont(val_font)
        self._value_label.setStyleSheet(f"color: {color}; background: transparent;")
        layout.addWidget(self._value_label)

        self._title_label = QLabel(title.upper())
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        title_font = QFont()
        title_font.setPointSize(9)
        title_font.setBold(True)
        self._title_label.setFont(title_font)
        self._title_label.setStyleSheet(
            f"color: {TEXT_SECONDARY}; letter-spacing: 1px; background: transparent;"
        )
        layout.addWidget(self._title_label)

    def set_value(self, value: str | int) -> None:
        """Update the displayed metric value."""
        self._value_label.setText(str(value))

    def paintEvent(self, event) -> None:
        """Draw the card background and accent border."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        painter.setBrush(QColor(BG_CARD))
        painter.setPen(QPen(QColor(BORDER), 1))
        painter.drawRoundedRect(self.rect().adjusted(0, 0, -1, -1), 10, 10)

        # Top accent line
        painter.setPen(QPen(QColor(self._color), 3))
        painter.drawLine(12, 2, self.width() - 12, 2)

        painter.end()
