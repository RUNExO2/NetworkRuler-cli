from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QLabel,
    QWidget,
)

from networkruler_core.config.paths import get_user_paths
from networkruler_gui.screens.base import Screen, page_layout
from networkruler_gui.widgets import (
    Card,
    EmptyState,
    LogEntryCard,
    SearchField,
    SecondaryButton,
    SectionHeader,
    Toolbar,
)


class LogsScreen(Screen):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = page_layout(self)
        layout.addWidget(
            SectionHeader(
                "Logs",
                "Recent Network Ruler activity from the platform log location.",
            )
        )

        path_card = Card()
        path_card.layout.addWidget(_title("Log file"))
        self.path_label = QLabel(str(get_user_paths().log_file))
        self.path_label.setObjectName("MutedLabel")
        self.path_label.setWordWrap(True)
        path_card.layout.addWidget(self.path_label)
        layout.addWidget(path_card)

        toolbar = Toolbar()
        self.search = SearchField("Search logs")
        self.severity = QComboBox()
        self.severity.addItems(["All", "ERROR", "WARNING", "INFO", "DEBUG"])
        refresh = SecondaryButton("Refresh")
        refresh.clicked.connect(self.refresh)
        self.search.textChanged.connect(self.refresh)
        self.severity.currentTextChanged.connect(lambda _text: self.refresh())
        toolbar.add_widget(self.search, 1)
        toolbar.add_widget(self.severity)
        toolbar.add_widget(refresh)
        layout.addWidget(toolbar)

        self.feed = Card()
        self.feed.layout.setSpacing(10)
        layout.addWidget(self.feed, 1)
        self.refresh()

    def refresh(self) -> None:
        query = self.search.text().casefold()
        severity = self.severity.currentText()
        self.run_task(
            lambda: _read_logs(get_user_paths().log_file, query=query, severity=severity),
            self._render_logs,
        )

    def _render_logs(self, entries: list[tuple[str, str]]) -> None:
        while self.feed.layout.count():
            item = self.feed.layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if not entries:
            self.feed.layout.addWidget(
                EmptyState("No log entries", "No matching activity was found.")
            )
            return
        for level, message in entries[:40]:
            self.feed.layout.addWidget(LogEntryCard(level, message))
        self.feed.layout.addStretch()


def _read_logs(path: Path, *, query: str, severity: str) -> list[tuple[str, str]]:
    if not path.exists():
        return [("INFO", f"No log file yet. Expected path: {path}")]
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]
    filtered = []
    for line in lines:
        if severity != "All" and severity not in line:
            continue
        if query and query not in line.casefold():
            continue
        filtered.append((_level_for(line), line))
    return filtered


def _level_for(line: str) -> str:
    for level in ("ERROR", "WARNING", "INFO", "DEBUG"):
        if level in line:
            return level
    return "LOG"


def _title(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("SectionTitle")
    return label
