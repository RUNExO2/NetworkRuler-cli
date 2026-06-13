from __future__ import annotations

import json

from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from networkruler_core.profiles.models import ProfileApplyResult, ProfileValidationResult
from networkruler_core.profiles.service import ProfileService
from networkruler_core.safety import SafetyContext
from networkruler_gui.screens.base import Screen, page_layout
from networkruler_gui.widgets import (
    Card,
    DangerButton,
    EmptyState,
    PrimaryButton,
    SafetyPreviewDialog,
    SecondaryButton,
    SectionHeader,
    TimelineCard,
    Toolbar,
)


class ProfilesScreen(Screen):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = page_layout(self)
        layout.addWidget(
            SectionHeader(
                "Profiles",
                "Structured v2 profiles with validation and dry-run timelines.",
            )
        )

        toolbar = Toolbar()
        refresh = SecondaryButton("Refresh")
        refresh.clicked.connect(self.refresh)
        create = PrimaryButton("Create")
        create.clicked.connect(self._create_profile)
        delete = SecondaryButton("Delete")
        delete.clicked.connect(self._delete_profile)
        toolbar.add_widget(refresh)
        toolbar.add_widget(create)
        toolbar.add_widget(delete)
        toolbar.add_stretch()
        layout.addWidget(toolbar)

        grid = QGridLayout()
        grid.setSpacing(16)
        self.list_widget = QListWidget()
        self.list_widget.currentTextChanged.connect(self._load_profile)
        grid.addWidget(self.list_widget, 0, 0)

        detail_card = Card()
        detail_card.layout.addWidget(_text_title("Profile detail"))
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        detail_card.layout.addWidget(self.detail)

        action_row = QHBoxLayout()
        validate = SecondaryButton("Validate")
        validate.clicked.connect(self._validate_profile)
        dry_run = SecondaryButton("Dry-run")
        dry_run.clicked.connect(self._dry_run_profile)
        apply = DangerButton("Apply")
        apply.clicked.connect(self._apply_profile)
        action_row.addWidget(validate)
        action_row.addWidget(dry_run)
        action_row.addWidget(apply)
        detail_card.layout.addLayout(action_row)

        self.timeline_card = Card()
        self.timeline_card.layout.addWidget(_text_title("Timeline"))
        self.timeline_body = QWidget()
        self.timeline_body_layout = QVBoxLayout(self.timeline_body)
        self.timeline_body_layout.setContentsMargins(0, 0, 0, 0)
        self.timeline_body_layout.setSpacing(10)
        self.timeline_body.setMinimumHeight(150)
        self.timeline_body_layout.addWidget(
            EmptyState("No timeline yet", "Validate or dry-run a profile to preview actions.")
        )
        self.timeline_card.layout.addWidget(self.timeline_body)
        detail_card.layout.addWidget(self.timeline_card)
        grid.addWidget(detail_card, 0, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 3)
        layout.addLayout(grid)
        self.refresh()

    def refresh(self) -> None:
        self.run_task(lambda: ProfileService().list_profiles(), self._populate)

    def _populate(self, names: list[str]) -> None:
        current = self.list_widget.currentItem().text() if self.list_widget.currentItem() else ""
        self.list_widget.clear()
        self.list_widget.addItems(names)
        if current in names:
            self.list_widget.setCurrentRow(names.index(current))
        elif names:
            self.list_widget.setCurrentRow(0)

    def _selected_name(self) -> str | None:
        item = self.list_widget.currentItem()
        return item.text() if item else None

    def _load_profile(self, name: str) -> None:
        if not name:
            return
        payload = ProfileService().show_profile(name)
        self.detail.setPlainText(json.dumps(payload, indent=2) if payload else "Not found.")

    def _validate_profile(self) -> None:
        name = self._selected_name()
        if not name:
            self.show_error("Select a profile first.")
            return
        self.run_task(lambda: ProfileService().validate_profile(name), self._show_validation)

    def _show_validation(self, result: ProfileValidationResult) -> None:
        self._render_timeline(
            [
                TimelineCard(
                    "Validation",
                    result.reason,
                    "\n".join(result.errors) if result.errors else "Profile is valid.",
                )
            ]
        )

    def _dry_run_profile(self) -> None:
        name = self._selected_name()
        if not name:
            self.show_error("Select a profile first.")
            return
        self.run_task(
            lambda: ProfileService().apply_profile(name, SafetyContext(dry_run=True)),
            self._show_apply_result,
        )

    def _apply_profile(self) -> None:
        name = self._selected_name()
        if not name:
            self.show_error("Select a profile first.")
            return

        def preview() -> ProfileApplyResult:
            return ProfileService().apply_profile(name, SafetyContext(dry_run=True))

        self.run_task(preview, lambda result: self._confirm_apply(name, result))

    def _confirm_apply(self, name: str, preview: ProfileApplyResult) -> None:
        self._show_apply_result(preview)
        if not preview.ok:
            return
        if not SafetyPreviewDialog.confirm(
            parent=self,
            title=f"Apply profile {name}",
            message="Review the profile dry-run timeline before applying actions.",
            payload=preview.to_dict(),
        ):
            return
        self.run_task(
            lambda: ProfileService().apply_profile(name, SafetyContext(yes=True)),
            self._show_apply_result,
        )

    def _show_apply_result(self, result: ProfileApplyResult) -> None:
        cards = [
            TimelineCard(
                "Profile apply",
                result.reason,
                result.message,
            )
        ]
        for index, action in enumerate(result.plan, start=1):
            cards.append(
                TimelineCard(
                    f"{index}. {action.type}",
                    action.risk_level.value,
                    json.dumps(action.params, default=str) if action.params else "No params",
                )
            )
        if result.errors:
            cards.append(TimelineCard("Errors", "invalid", "\n".join(result.errors)))
        self._render_timeline(cards)
        if not result.ok and not result.dry_run:
            QMessageBox.warning(self, "Profile", result.message)

    def _render_timeline(self, cards: list[TimelineCard]) -> None:
        while self.timeline_body_layout.count():
            item = self.timeline_body_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for card in cards:
            self.timeline_body_layout.addWidget(card)
        self.timeline_body_layout.addStretch()

    def _create_profile(self) -> None:
        name, accepted = QInputDialog.getText(self, "Create profile", "Profile name")
        if not accepted or not name.strip():
            return
        result = ProfileService().create_profile(name.strip())
        if not result.ok:
            QMessageBox.warning(self, "Profile", "\n".join(result.errors))
            return
        self.refresh()

    def _delete_profile(self) -> None:
        name = self._selected_name()
        if not name:
            self.show_error("Select a profile first.")
            return
        answer = QMessageBox.question(
            self,
            "Delete profile",
            f"Delete profile '{name}'?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        result = ProfileService().delete_profile(name, yes=True)
        if not result.ok:
            QMessageBox.warning(self, "Profile", "\n".join(result.errors))
            return
        self.refresh()


def _text_title(text: str):
    from PySide6.QtWidgets import QLabel

    label = QLabel(text)
    label.setObjectName("SectionTitle")
    return label
