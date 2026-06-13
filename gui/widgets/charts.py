"""
Custom chart widgets drawn with QPainter.

No external charting library required — all rendering is done on a QWidget
canvas, keeping the dependency list minimal and the visual style consistent
with the dark cybersecurity theme.
"""
from __future__ import annotations

import math
from typing import List, Tuple

from PyQt6.QtCore import QPoint, QRect, QSize, Qt
from PyQt6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QPainterPath,
    QPen,
    QLinearGradient,
    QBrush,
)
from PyQt6.QtWidgets import QSizePolicy, QWidget

from gui import (
    BG_CARD, BG_PRIMARY, BORDER, ACCENT,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO,
    TEXT_PRIMARY, TEXT_SECONDARY,
)

SEVERITY_PALETTE = [SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO]


class DonutChart(QWidget):
    """
    Animated donut chart for displaying severity distribution.

    Parameters
    ----------
    data : list of (label, value, hex_color) tuples
    """

    def __init__(self, data: List[Tuple[str, int, str]] | None = None, parent=None):
        super().__init__(parent)
        self._data: List[Tuple[str, int, str]] = data or []
        self.setMinimumSize(220, 220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_data(self, data: List[Tuple[str, int, str]]) -> None:
        """Update chart data. Each item: (label, value, '#rrggbb')."""
        self._data = [(lbl, val, col) for lbl, val, col in data if val > 0]
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        size = min(w, h) - 20
        cx, cy = w // 2, h // 2
        outer_r = size // 2
        inner_r = int(outer_r * 0.58)

        rect = QRect(cx - outer_r, cy - outer_r, outer_r * 2, outer_r * 2)
        total = sum(v for _, v, _ in self._data)

        if total == 0:
            # Empty state
            painter.setPen(QPen(QColor(BORDER), 2))
            painter.setBrush(QColor(BG_CARD))
            painter.drawEllipse(rect)
            painter.setPen(QColor(TEXT_SECONDARY))
            painter.setFont(QFont("Segoe UI", 10))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "No data")
            return

        start_angle = 90 * 16  # 12-o'clock position, in 1/16ths of a degree
        for label, value, color in self._data:
            span = int(360 * 16 * value / total)
            painter.setBrush(QColor(color))
            painter.setPen(QPen(QColor(BG_PRIMARY), 2))
            painter.drawPie(rect, start_angle, -span)
            start_angle -= span

        # Donut hole
        painter.setBrush(QColor(BG_CARD))
        painter.setPen(Qt.PenStyle.NoPen)
        hole_rect = QRect(cx - inner_r, cy - inner_r, inner_r * 2, inner_r * 2)
        painter.drawEllipse(hole_rect)

        # Centre text
        painter.setPen(QColor(TEXT_PRIMARY))
        f = QFont("Segoe UI", 20)
        f.setBold(True)
        painter.setFont(f)
        painter.drawText(hole_rect.adjusted(0, -8, 0, -8), Qt.AlignmentFlag.AlignCenter, str(total))
        f2 = QFont("Segoe UI", 8)
        painter.setFont(f2)
        painter.setPen(QColor(TEXT_SECONDARY))
        painter.drawText(hole_rect.adjusted(0, 14, 0, 14), Qt.AlignmentFlag.AlignCenter, "FINDINGS")

        # Legend at the bottom
        legend_y = cy + outer_r + 14
        if legend_y + 20 < h:
            legend_x = max(4, cx - len(self._data) * 54 // 2)
            for label, value, color in self._data:
                painter.setBrush(QColor(color))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawRoundedRect(legend_x, legend_y, 10, 10, 2, 2)
                painter.setPen(QColor(TEXT_SECONDARY))
                painter.setFont(QFont("Segoe UI", 8))
                painter.drawText(legend_x + 13, legend_y + 9, f"{label[:4]} {value}")
                legend_x += 60


class BarChart(QWidget):
    """
    Vertical bar chart for displaying port/service counts.

    Parameters
    ----------
    data : list of (label, value, hex_color) tuples
    """

    def __init__(self, data: List[Tuple[str, int, str]] | None = None, parent=None):
        super().__init__(parent)
        self._data: List[Tuple[str, int, str]] = data or []
        self._title = ""
        self.setMinimumSize(280, 180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_data(self, data: List[Tuple[str, int, str]], title: str = "") -> None:
        self._data = data
        self._title = title
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        pad_l, pad_r, pad_t, pad_b = 40, 16, 30, 36
        chart_w = w - pad_l - pad_r
        chart_h = h - pad_t - pad_b

        # Background
        painter.fillRect(self.rect(), QColor(BG_CARD))

        # Title
        if self._title:
            painter.setPen(QColor(TEXT_SECONDARY))
            painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            painter.drawText(pad_l, 16, self._title)

        if not self._data:
            painter.setPen(QColor(TEXT_SECONDARY))
            painter.setFont(QFont("Segoe UI", 10))
            painter.drawText(
                QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "No data"
            )
            return

        max_val = max(v for _, v, _ in self._data) or 1
        n = len(self._data)
        bar_spacing = 6
        bar_w = max(8, (chart_w - bar_spacing * (n + 1)) // n)

        # Grid lines
        painter.setPen(QPen(QColor(BORDER), 1, Qt.PenStyle.DotLine))
        for i in range(1, 5):
            y = pad_t + chart_h - int(chart_h * i / 4)
            painter.drawLine(pad_l, y, pad_l + chart_w, y)
            val_label = str(int(max_val * i / 4))
            painter.setPen(QColor(TEXT_MUTED if i < 4 else TEXT_SECONDARY))
            painter.setFont(QFont("Segoe UI", 7))
            painter.drawText(2, y + 4, val_label)
            painter.setPen(QPen(QColor(BORDER), 1, Qt.PenStyle.DotLine))

        # Bars
        x = pad_l + bar_spacing
        for label, value, color in self._data:
            if max_val > 0:
                bar_h = int(chart_h * value / max_val)
            else:
                bar_h = 0
            bar_y = pad_t + chart_h - bar_h

            # Gradient fill
            grad = QLinearGradient(x, bar_y, x, bar_y + bar_h)
            grad.setColorAt(0.0, QColor(color))
            grad.setColorAt(1.0, QColor(color).darker(180))
            painter.setBrush(grad)
            painter.setPen(Qt.PenStyle.NoPen)
            if bar_h > 0:
                painter.drawRoundedRect(x, bar_y, bar_w, bar_h, 3, 3)

            # Value label above bar
            if value > 0:
                painter.setPen(QColor(color))
                painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
                painter.drawText(
                    QRect(x, bar_y - 16, bar_w, 14),
                    Qt.AlignmentFlag.AlignCenter,
                    str(value),
                )

            # X-axis label
            painter.setPen(QColor(TEXT_SECONDARY))
            painter.setFont(QFont("Segoe UI", 7))
            painter.drawText(
                QRect(x - 4, h - pad_b + 4, bar_w + 8, pad_b - 4),
                Qt.AlignmentFlag.AlignCenter,
                label[:6],
            )
            x += bar_w + bar_spacing

        # X-axis line
        painter.setPen(QPen(QColor(BORDER), 1))
        painter.drawLine(pad_l, pad_t + chart_h, pad_l + chart_w, pad_t + chart_h)


TEXT_MUTED = "#484f58"


class LineChart(QWidget):
    """
    Simple line chart for showing scan trends over time.

    Parameters
    ----------
    data   : list of (x_label, y_value) tuples
    title  : chart title
    color  : line colour hex string
    """

    def __init__(
        self,
        data: List[Tuple[str, float]] | None = None,
        title: str = "",
        color: str = ACCENT,
        parent=None,
    ):
        super().__init__(parent)
        self._data = data or []
        self._title = title
        self._color = color
        self.setMinimumSize(280, 160)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_data(self, data: List[Tuple[str, float]], title: str = "") -> None:
        self._data = data
        if title:
            self._title = title
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        pad_l, pad_r, pad_t, pad_b = 42, 16, 28, 32
        chart_w = w - pad_l - pad_r
        chart_h = h - pad_t - pad_b

        painter.fillRect(self.rect(), QColor(BG_CARD))

        if self._title:
            painter.setPen(QColor(TEXT_SECONDARY))
            painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            painter.drawText(pad_l, 16, self._title)

        if len(self._data) < 2:
            painter.setPen(QColor(TEXT_SECONDARY))
            painter.setFont(QFont("Segoe UI", 10))
            painter.drawText(
                QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter,
                "Not enough data"
            )
            return

        max_val = max(v for _, v in self._data) or 1
        n = len(self._data)

        # Grid
        painter.setPen(QPen(QColor(BORDER), 1, Qt.PenStyle.DotLine))
        for i in range(1, 5):
            y = pad_t + chart_h - int(chart_h * i / 4)
            painter.drawLine(pad_l, y, pad_l + chart_w, y)
            painter.setPen(QColor(TEXT_MUTED))
            painter.setFont(QFont("Segoe UI", 7))
            painter.drawText(2, y + 4, str(int(max_val * i / 4)))
            painter.setPen(QPen(QColor(BORDER), 1, Qt.PenStyle.DotLine))

        # Build point list
        step = chart_w / (n - 1) if n > 1 else chart_w
        points = []
        for i, (lbl, val) in enumerate(self._data):
            px = int(pad_l + i * step)
            py = int(pad_t + chart_h - (chart_h * val / max_val))
            points.append((px, py, lbl))

        # Gradient fill under line
        path = QPainterPath()
        path.moveTo(points[0][0], pad_t + chart_h)
        path.lineTo(points[0][0], points[0][1])
        for px, py, _ in points[1:]:
            path.lineTo(px, py)
        path.lineTo(points[-1][0], pad_t + chart_h)
        path.closeSubpath()
        grad = QLinearGradient(0, pad_t, 0, pad_t + chart_h)
        c = QColor(self._color)
        c.setAlpha(80)
        grad.setColorAt(0, c)
        c2 = QColor(self._color)
        c2.setAlpha(0)
        grad.setColorAt(1, c2)
        painter.fillPath(path, grad)

        # Line
        painter.setPen(QPen(QColor(self._color), 2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        line_path = QPainterPath()
        line_path.moveTo(points[0][0], points[0][1])
        for px, py, _ in points[1:]:
            line_path.lineTo(px, py)
        painter.drawPath(line_path)

        # Data points
        painter.setBrush(QColor(self._color))
        painter.setPen(QPen(QColor(BG_CARD), 2))
        for px, py, _ in points:
            painter.drawEllipse(px - 4, py - 4, 8, 8)

        # X labels
        painter.setPen(QColor(TEXT_SECONDARY))
        painter.setFont(QFont("Segoe UI", 7))
        for px, py, lbl in points[::max(1, n // 6)]:
            painter.drawText(
                QRect(px - 20, h - pad_b + 4, 40, pad_b - 4),
                Qt.AlignmentFlag.AlignCenter,
                lbl[:8],
            )

        # Axes
        painter.setPen(QPen(QColor(BORDER), 1))
        painter.drawLine(pad_l, pad_t, pad_l, pad_t + chart_h)
        painter.drawLine(pad_l, pad_t + chart_h, pad_l + chart_w, pad_t + chart_h)
