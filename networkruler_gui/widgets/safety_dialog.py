from __future__ import annotations

import json
from typing import Any

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from networkruler_gui.widgets.primitives import PillBadge, PremiumCard


class SafetyPreviewDialog(QDialog):
    def __init__(
        self,
        title: str,
        message: str,
        payload: dict[str, Any],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("SafetyDialog")
        self.setWindowTitle(title)
        self.setMinimumWidth(640)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(14)

        header = PremiumCard(hero=True, compact=True)
        header.layout.addWidget(PillBadge("Dry-run preview", tone="warning"))
        label = QLabel(message)
        label.setObjectName("SectionTitle")
        label.setWordWrap(True)
        header.layout.addWidget(label)
        layout.addWidget(header)

        danger = PremiumCard(compact=True)
        danger.setObjectName("DangerPanel")
        danger.layout.addWidget(PillBadge("Confirmation required", tone="danger"))
        danger.layout.addWidget(_muted("Review the target and safety result before applying."))
        layout.addWidget(danger)

        detail = QPlainTextEdit()
        detail.setReadOnly(True)
        detail.setPlainText(json.dumps(payload, indent=2, default=str))
        detail.setMinimumHeight(280)
        layout.addWidget(detail)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Ok
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Confirm")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @classmethod
    def confirm(
        cls,
        *,
        parent: QWidget,
        title: str,
        message: str,
        payload: dict[str, Any],
    ) -> bool:
        dialog = cls(title, message, payload, parent)
        return dialog.exec() == QDialog.DialogCode.Accepted


def _muted(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("MutedLabel")
    label.setWordWrap(True)
    return label

