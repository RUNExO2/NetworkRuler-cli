from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QMessageBox, QScrollArea, QVBoxLayout, QWidget

from networkruler_gui.workers import CoreWorker, run_worker


class Screen(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._workers: list[CoreWorker] = []

    def run_task(
        self,
        task: Callable[[], Any],
        on_result: Callable[[Any], None],
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        worker = run_worker(
            task,
            on_result=on_result,
            on_error=on_error or self.show_error,
        )
        self._workers.append(worker)

    def show_error(self, message: str) -> None:
        QMessageBox.warning(self, "Network Ruler", message)


def scroll_page(content: QWidget) -> QScrollArea:
    scroll = QScrollArea()
    scroll.setObjectName("ContentViewport")
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QScrollArea.Shape.NoFrame)
    scroll.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
    scroll.setWidget(content)
    return scroll


def muted_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("MutedLabel")
    label.setWordWrap(True)
    return label


def page_layout(widget: QWidget) -> QVBoxLayout:
    widget.setObjectName(widget.objectName() or "PageContent")
    widget.setMaximumWidth(1240)
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(32, 30, 32, 34)
    layout.setSpacing(20)
    return layout

