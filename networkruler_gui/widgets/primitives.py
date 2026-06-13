from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

from networkruler_gui.theme.tokens import ThemeTokens


class PremiumCard(QFrame):
    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        hero: bool = False,
        compact: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("HeroCard" if hero else "PremiumCard")
        self.setProperty("interactive", False)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.layout = QVBoxLayout(self)
        margins = (22, 22, 22, 22) if not compact else (14, 14, 14, 14)
        self.layout.setContentsMargins(*margins)
        self.layout.setSpacing(14 if not compact else 10)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def set_interactive(self, interactive: bool = True) -> None:
        self.setProperty("interactive", interactive)
        self.setCursor(
            Qt.CursorShape.PointingHandCursor
            if interactive
            else Qt.CursorShape.ArrowCursor
        )
        self.style().unpolish(self)
        self.style().polish(self)


class FrostedPanel(PremiumCard):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("FrostedPanel")


class SectionHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SectionHeader")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        title_label = QLabel(title)
        title_label.setObjectName("ScreenTitle")
        title_label.setWordWrap(False)
        layout.addWidget(title_label)

        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("ScreenSubtitle")
            subtitle_label.setWordWrap(True)
            layout.addWidget(subtitle_label)


class MetricCard(PremiumCard):
    def __init__(
        self,
        label: str,
        value: str = "—",
        detail: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent, compact=True)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        self.dot = StatusDot("accent")
        self.label = QLabel(label)
        self.label.setObjectName("MetricLabel")
        row.addWidget(self.dot)
        row.addWidget(self.label)
        row.addStretch()
        self.value = QLabel(value)
        self.value.setObjectName("MetricValue")
        self.value.setMinimumHeight(34)
        self.detail = QLabel(detail)
        self.detail.setObjectName("MetricDetail")
        self.detail.setWordWrap(True)
        self.layout.addLayout(row)
        self.layout.addWidget(self.value)
        self.layout.addWidget(self.detail)
        self.layout.addStretch()

    def set_value(self, value: str, detail: str | None = None) -> None:
        self.value.setText(value)
        if detail is not None:
            self.detail.setText(detail)


class PillBadge(QLabel):
    def __init__(
        self,
        text: str,
        *,
        tone: str = "neutral",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self.setObjectName("PillBadge")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.set_tone(tone)

    def set_tone(self, tone: str) -> None:
        self.setProperty("tone", tone)
        self.style().unpolish(self)
        self.style().polish(self)


class StatusDot(QFrame):
    def __init__(self, tone: str = "neutral", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("StatusDot")
        self.set_tone(tone)

    def set_tone(self, tone: str) -> None:
        self.setProperty("tone", tone)
        self.style().unpolish(self)
        self.style().polish(self)


class PrimaryButton(QPushButton):
    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("PrimaryButton")
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class SecondaryButton(QPushButton):
    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("SecondaryButton")
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class DangerButton(QPushButton):
    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("DangerButton")
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class SearchField(QLineEdit):
    def __init__(self, placeholder: str = "Search", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SearchField")
        self.setPlaceholderText(placeholder)


class Toolbar(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Toolbar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(12, 12, 12, 12)
        self.layout.setSpacing(10)

    def add_widget(self, widget: QWidget, stretch: int = 0) -> None:
        self.layout.addWidget(widget, stretch)

    def add_stretch(self) -> None:
        self.layout.addItem(
            QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        )


class ActionCard(PremiumCard):
    triggered = Signal()

    def __init__(
        self,
        title: str,
        subtitle: str,
        button_text: str,
        parent: QWidget | None = None,
        *,
        dangerous: bool = False,
        enabled: bool = True,
    ) -> None:
        super().__init__(parent, compact=True)
        self.setObjectName("ActionCard")
        self.set_interactive(enabled)
        title_label = QLabel(title)
        title_label.setObjectName("SectionTitle")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("MutedLabel")
        subtitle_label.setWordWrap(True)
        self.button = DangerButton(button_text) if dangerous else SecondaryButton(button_text)
        self.button.setEnabled(enabled)
        self.button.clicked.connect(self.triggered.emit)
        self.layout.addWidget(title_label)
        self.layout.addWidget(subtitle_label)
        self.layout.addStretch()
        self.layout.addWidget(self.button)


class EmptyState(QWidget):
    def __init__(self, title: str, detail: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("EmptyState")
        self.setMinimumHeight(120)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)
        title_label = QLabel(title)
        title_label.setObjectName("SectionTitle")
        detail_label = QLabel(detail)
        detail_label.setObjectName("MutedLabel")
        detail_label.setWordWrap(True)
        detail_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        layout.addWidget(detail_label)


Card = PremiumCard
Pill = PillBadge


def horizontal_row(*widgets: QWidget) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)
    for widget in widgets:
        layout.addWidget(widget)
    return row


class ThemePreviewTile(PremiumCard):
    selected = Signal(str)

    def __init__(
        self,
        tokens: ThemeTokens,
        parent: QWidget | None = None,
        *,
        title: str | None = None,
    ) -> None:
        super().__init__(parent, compact=True)
        self.setObjectName("ThemePreviewTile")
        self.tokens = tokens
        self.set_interactive(True)
        self.setMinimumHeight(118)

        title_label = QLabel(title or tokens.name.value)
        title_label.setObjectName("SectionTitle")
        subtitle = QLabel("Preview")
        subtitle.setObjectName("MutedLabel")
        swatches = QHBoxLayout()
        swatches.setSpacing(6)
        for color in (
            tokens.background,
            tokens.card,
            tokens.accent,
            tokens.success,
            tokens.warning,
        ):
            swatch = QFrame()
            swatch.setFixedSize(24, 24)
            swatch.setStyleSheet(
                f"background: {color}; border: 1px solid {tokens.border}; "
                "border-radius: 8px;"
            )
            swatches.addWidget(swatch)
        swatches.addStretch()
        self.layout.addWidget(title_label)
        self.layout.addWidget(subtitle)
        self.layout.addLayout(swatches)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.selected.emit(self.tokens.name.value)
        super().mouseReleaseEvent(event)


class TimelineCard(PremiumCard):
    def __init__(
        self,
        title: str,
        status: str,
        detail: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent, compact=True)
        self.setObjectName("TimelineCard")
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        marker = QFrame()
        marker.setObjectName("TimelineMarker")
        text = QVBoxLayout()
        text.setContentsMargins(0, 0, 0, 0)
        title_label = QLabel(title)
        title_label.setObjectName("SectionTitle")
        status_label = QLabel(status)
        status_label.setObjectName("MutedLabel")
        detail_label = QLabel(detail)
        detail_label.setObjectName("MutedLabel")
        detail_label.setWordWrap(True)
        text.addWidget(title_label)
        text.addWidget(status_label)
        text.addWidget(detail_label)
        row.addWidget(marker, 0, Qt.AlignmentFlag.AlignTop)
        row.addLayout(text, 1)
        self.layout.addLayout(row)


class LogEntryCard(PremiumCard):
    def __init__(self, level: str, message: str, parent: QWidget | None = None) -> None:
        super().__init__(parent, compact=True)
        self.setObjectName("LogEntryCard")
        tone = {
            "ERROR": "danger",
            "WARNING": "warning",
            "INFO": "accent",
            "DEBUG": "neutral",
        }.get(level.upper(), "neutral")
        row = QGridLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setHorizontalSpacing(10)
        badge = PillBadge(level.upper() or "LOG", tone=tone)
        label = QLabel(message)
        label.setObjectName("MutedLabel")
        label.setWordWrap(True)
        row.addWidget(badge, 0, 0, Qt.AlignmentFlag.AlignTop)
        row.addWidget(label, 0, 1)
        row.setColumnStretch(1, 1)
        self.layout.addLayout(row)
