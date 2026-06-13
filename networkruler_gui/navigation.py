from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import QLabel, QPushButton, QStyle, QVBoxLayout, QWidget


@dataclass(frozen=True)
class NavigationItem:
    key: str
    title: str
    subtitle: str


class NavigationButton(QPushButton):
    def __init__(self, item: NavigationItem, parent: QWidget | None = None) -> None:
        super().__init__(item.title.replace("&", "&&"), parent)
        self.item = item
        self.setObjectName("NavButton")
        self.setCheckable(True)
        self.setProperty("active", False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(42)
        self.setToolTip(item.subtitle)
        self.setIcon(self._icon_for(item.key))
        self.setIconSize(QSize(16, 16))

    def set_active(self, active: bool) -> None:
        self.setChecked(active)
        self.setProperty("active", active)
        self.style().unpolish(self)
        self.style().polish(self)

    def _icon_for(self, key: str):
        icons = {
            "dashboard": QStyle.StandardPixmap.SP_ComputerIcon,
            "processes": QStyle.StandardPixmap.SP_FileDialogDetailedView,
            "network": QStyle.StandardPixmap.SP_DriveNetIcon,
            "monitor": QStyle.StandardPixmap.SP_BrowserReload,
            "profiles": QStyle.StandardPixmap.SP_FileDialogListView,
            "logs": QStyle.StandardPixmap.SP_FileIcon,
            "settings": QStyle.StandardPixmap.SP_FileDialogContentsView,
        }
        return self.style().standardIcon(icons.get(key, QStyle.StandardPixmap.SP_FileIcon))


class Sidebar(QWidget):
    selected = Signal(str)

    def __init__(self, items: list[NavigationItem], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self._buttons: dict[str, NavigationButton] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 22, 20, 18)
        layout.setSpacing(7)

        title = QLabel("Network Ruler")
        title.setObjectName("SidebarTitle")
        subtitle = QLabel("v2 desktop")
        subtitle.setObjectName("SidebarSubtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(18)

        for item in items:
            button = NavigationButton(item)
            button.clicked.connect(lambda checked=False, key=item.key: self.select(key))
            self._buttons[item.key] = button
            layout.addWidget(button)

        layout.addStretch()

        footer = QLabel("Preview-first safety")
        footer.setObjectName("CaptionLabel")
        footer.setWordWrap(True)
        layout.addWidget(footer)

    def select(self, key: str) -> None:
        for button_key, button in self._buttons.items():
            button.set_active(button_key == key)
        self.selected.emit(key)
