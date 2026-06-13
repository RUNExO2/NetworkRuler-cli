from __future__ import annotations

from collections import deque

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPalette, QPen
from PySide6.QtWidgets import QWidget


class LineChart(QWidget):
    def __init__(self, parent: QWidget | None = None, *, color: str | None = None) -> None:
        super().__init__(parent)
        self._values: deque[float] = deque(maxlen=80)
        self._color = QColor(color) if color else None
        self.setMinimumHeight(180)

    def set_color(self, color: str) -> None:
        self._color = QColor(color)
        self.update()

    def append_value(self, value: float) -> None:
        self._values.append(max(0.0, value))
        self.update()

    def clear(self) -> None:
        self._values.clear()
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(14, 14, -14, -14)
        grid_color = self.palette().color(QPalette.ColorRole.Mid)
        text_color = self.palette().color(QPalette.ColorRole.PlaceholderText)
        line_color = self._color or self.palette().color(QPalette.ColorRole.Highlight)
        painter.setPen(QPen(grid_color, 1, Qt.PenStyle.DotLine))
        for step in range(1, 4):
            y = rect.top() + rect.height() * step / 4
            painter.drawLine(rect.left(), int(y), rect.right(), int(y))

        if len(self._values) < 2:
            painter.setPen(text_color)
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "Waiting for samples")
            return

        maximum = max(max(self._values), 1.0)
        points = []
        count = len(self._values)
        for index, value in enumerate(self._values):
            x = rect.left() + rect.width() * index / max(count - 1, 1)
            y = rect.bottom() - rect.height() * (value / maximum)
            points.append(QPointF(x, y))

        painter.setPen(QPen(line_color, 3))
        for start, end in zip(points, points[1:], strict=False):
            painter.drawLine(start, end)
