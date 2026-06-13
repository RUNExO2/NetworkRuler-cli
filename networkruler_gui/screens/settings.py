from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGridLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from networkruler_core.config.paths import get_user_paths
from networkruler_gui.screens.base import Screen, page_layout, scroll_page
from networkruler_gui.theme.engine import ThemeEngine
from networkruler_gui.theme.tokens import THEMES, ThemeName
from networkruler_gui.widgets import (
    PremiumCard,
    SecondaryButton,
    SectionHeader,
    ThemePreviewTile,
)


class SettingsScreen(Screen):
    theme_changed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        page = QWidget()
        layout = page_layout(page)
        layout.addWidget(
            SectionHeader(
                "Settings",
                "Theme, safety, paths, and diagnostics for the v2 desktop shell.",
            )
        )

        theme_card = PremiumCard()
        theme_card.layout.addWidget(_title("Appearance"))
        form = QFormLayout()
        form.setSpacing(14)
        form.setContentsMargins(0, 4, 0, 0)
        self.theme = QComboBox()
        for item in ThemeName:
            self.theme.addItem(item.value, item.value)
        self.theme.currentTextChanged.connect(self.theme_changed.emit)
        form.addRow("Theme", self.theme)
        sync = QCheckBox("Follow system theme when System is selected")
        sync.setChecked(True)
        sync.setEnabled(False)
        form.addRow("System sync", sync)
        theme_card.layout.addLayout(form)
        previews = QGridLayout()
        previews.setSpacing(12)
        engine = ThemeEngine()
        preview_themes = [
            ThemeName.CLEAN_MINIMAL_LIGHT,
            ThemeName.CLEAN_MINIMAL_DARK,
            ThemeName.CYBER,
            ThemeName.GAMING_TECH_NEON,
            ThemeName.PROFESSIONAL_ENTERPRISE,
        ]
        for index, name in enumerate(preview_themes):
            tile = ThemePreviewTile(THEMES[name])
            tile.selected.connect(self._select_theme)
            previews.addWidget(tile, index // 3, index % 3)
        system_tile = ThemePreviewTile(engine.resolve_theme(ThemeName.SYSTEM), title="System")
        system_tile.selected.connect(lambda _theme: self._select_theme(ThemeName.SYSTEM.value))
        previews.addWidget(system_tile, 1, 2)
        theme_card.layout.addLayout(previews)
        layout.addWidget(theme_card)

        safety_card = PremiumCard()
        safety_card.layout.addWidget(_title("Safety"))
        dry_run = QCheckBox("Prefer dry-run previews for write actions")
        dry_run.setChecked(True)
        dry_run.setEnabled(False)
        confirmations = QCheckBox("Require confirmation for dangerous actions")
        confirmations.setChecked(True)
        confirmations.setEnabled(False)
        safety_card.layout.addWidget(dry_run)
        safety_card.layout.addWidget(confirmations)
        safety_card.layout.addWidget(_muted("Safety preferences are enforced by core v2."))
        layout.addWidget(safety_card)

        paths = get_user_paths()
        paths_card = PremiumCard()
        paths_card.layout.addWidget(_title("Paths"))
        path_form = QFormLayout()
        path_form.setSpacing(12)
        path_form.addRow("Config", _muted(str(paths.config_dir)))
        path_form.addRow("Cache", _muted(str(paths.cache_dir)))
        path_form.addRow("Data", _muted(str(paths.data_dir)))
        path_form.addRow("Logs", _muted(str(paths.log_dir)))
        paths_card.layout.addLayout(path_form)
        layout.addWidget(paths_card)

        diagnostics = PremiumCard()
        diagnostics.layout.addWidget(_title("Diagnostics"))
        doctor = SecondaryButton("Run GUI diagnostics")
        doctor.setEnabled(False)
        diagnostics.layout.addWidget(doctor)
        diagnostics.layout.addWidget(
            _muted("Dedicated GUI diagnostics are planned after the first shell.")
        )
        layout.addWidget(diagnostics)
        layout.addStretch()
        root.addWidget(scroll_page(page))

    def _select_theme(self, name: str) -> None:
        index = self.theme.findData(name)
        if index >= 0:
            self.theme.setCurrentIndex(index)


def _title(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("SectionTitle")
    return label


def _muted(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("MutedLabel")
    label.setWordWrap(True)
    label.setTextInteractionFlags(
        label.textInteractionFlags() | Qt.TextInteractionFlag.TextSelectableByMouse
    )
    return label
