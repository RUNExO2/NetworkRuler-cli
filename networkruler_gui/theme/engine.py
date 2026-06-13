from __future__ import annotations

from networkruler_gui.theme.tokens import THEMES, ThemeName, ThemeTokens


class ThemeEngine:
    def __init__(self, default_theme: ThemeName = ThemeName.SYSTEM) -> None:
        self.default_theme = default_theme

    def resolve_theme(self, theme: ThemeName | str | None = None) -> ThemeTokens:
        selected = self._coerce_theme(theme or self.default_theme)
        if selected is ThemeName.SYSTEM:
            selected = self._system_theme()
        return THEMES[selected]

    def stylesheet_for(self, theme: ThemeName | str | None = None) -> str:
        return self._build_stylesheet(self.resolve_theme(theme))

    def apply(self, app, theme: ThemeName | str | None = None) -> ThemeTokens:
        from PySide6.QtCore import QObject
        from PySide6.QtGui import QFont

        tokens = self.resolve_theme(theme)
        app.setFont(QFont("Segoe UI", 10))
        app.setStyleSheet(self._build_stylesheet(tokens))
        for widget in app.topLevelWidgets():
            for child in [widget, *widget.findChildren(QObject)]:
                if hasattr(child, "style"):
                    child.style().unpolish(child)
                    child.style().polish(child)
                update = getattr(child, "update", None)
                if callable(update):
                    try:
                        update()
                    except TypeError:
                        pass
        return tokens

    def _coerce_theme(self, theme: ThemeName | str) -> ThemeName:
        if isinstance(theme, ThemeName):
            return theme
        for candidate in ThemeName:
            if theme in {candidate.name, candidate.value}:
                return candidate
        return ThemeName.SYSTEM

    def _system_theme(self) -> ThemeName:
        try:
            from PySide6.QtCore import Qt
            from PySide6.QtGui import QGuiApplication

            app = QGuiApplication.instance()
            if app and app.styleHints().colorScheme() == Qt.ColorScheme.Dark:
                return ThemeName.DARK_ENTERPRISE
        except Exception:
            return ThemeName.DARK_ENTERPRISE
        return ThemeName.DARK_ENTERPRISE

    def _build_stylesheet(self, t: ThemeTokens) -> str:
        return f"""
        QMainWindow, QDialog, QWidget#AppShell {{
            background: {t.background};
            color: {t.text_primary};
            font-family: "Segoe UI", "San Francisco", "Inter", sans-serif;
            font-size: 13px;
        }}
        QWidget {{
            color: {t.text_primary};
            selection-background-color: {t.accent};
            selection-color: {t.on_accent};
        }}
        QWidget#ContentViewport {{
            background: {t.background};
        }}
        QScrollArea, QScrollArea > QWidget > QWidget {{
            background: transparent;
            border: 0;
        }}
        #PageContent {{
            background: transparent;
        }}
        #Sidebar {{
            background: {t.surface};
            border-right: 1px solid {t.border};
        }}
        #SidebarTitle {{
            color: {t.text_primary};
            font-size: 20px;
            font-weight: 750;
            padding: 0;
        }}
        #SidebarSubtitle, #MutedLabel, #CaptionLabel {{
            color: {t.text_secondary};
        }}
        #ScreenTitle {{
            color: {t.text_primary};
            font-size: 27px;
            font-weight: 760;
            padding: 0;
        }}
        #ScreenSubtitle {{
            color: {t.text_secondary};
            font-size: 13px;
            line-height: 18px;
        }}
        #SectionTitle {{
            color: {t.text_primary};
            font-size: 15px;
            font-weight: 700;
        }}
        #PremiumCard, #Card {{
            background: {t.card};
            border: 1px solid {t.border};
            border-radius: {t.radius}px;
        }}
        #PremiumCard[interactive="true"]:hover, #ThemePreviewTile:hover {{
            background: {t.card_hover};
            border-color: {t.accent};
        }}
        #PremiumCard:hover, #ActionCard:hover {{
            background: {t.card_hover};
            border-color: {t.border_strong};
        }}
        #HeroCard {{
            background: qlineargradient(
                x1: 0, y1: 0, x2: 1, y2: 1,
                stop: 0 {t.elevated_surface},
                stop: 0.62 {t.card},
                stop: 1 {t.accent_soft}
            );
            border: 1px solid {t.border};
            border-radius: {t.radius}px;
        }}
        #AccentPanel {{
            background: qlineargradient(
                x1: 0, y1: 0, x2: 1, y2: 1,
                stop: 0 {t.accent},
                stop: 1 {t.accent_hover}
            );
            border: 0;
            border-radius: {t.radius}px;
            color: {t.on_accent};
        }}
        #FrostedPanel {{
            background: {t.surface};
            border: 1px solid {t.border};
            border-radius: {t.radius}px;
        }}
        #ThemePreviewTile, #TimelineCard, #LogEntryCard {{
            background: {t.card};
            border: 1px solid {t.border};
            border-radius: {t.radius_small}px;
        }}
        #TimelineMarker {{
            background: {t.accent};
            border-radius: 6px;
            min-width: 12px;
            max-width: 12px;
            min-height: 12px;
            max-height: 12px;
        }}
        #SafetyDialog {{
            background: {t.background};
            color: {t.text_primary};
        }}
        #DangerPanel {{
            background: {t.danger_soft};
            border: 1px solid {t.danger};
            border-radius: {t.radius}px;
        }}
        #Toolbar {{
            background: {t.surface};
            border: 1px solid {t.border};
            border-radius: {t.radius}px;
        }}
        #MetricValue {{
            color: {t.text_primary};
            font-size: 27px;
            font-weight: 780;
        }}
        #MetricLabel {{
            color: {t.text_secondary};
            font-weight: 650;
        }}
        #MetricDetail {{
            color: {t.text_muted};
            font-size: 12px;
        }}
        #StatusDot {{
            border-radius: 5px;
            min-width: 10px;
            max-width: 10px;
            min-height: 10px;
            max-height: 10px;
        }}
        #StatusDot[tone="success"] {{ background: {t.success}; }}
        #StatusDot[tone="warning"] {{ background: {t.warning}; }}
        #StatusDot[tone="danger"] {{ background: {t.danger}; }}
        #StatusDot[tone="accent"] {{ background: {t.accent}; }}
        #StatusDot[tone="neutral"] {{ background: {t.text_muted}; }}
        #PillBadge {{
            border-radius: 999px;
            padding: 5px 10px;
            font-weight: 700;
        }}
        #PillBadge[tone="success"] {{
            background: {t.success_soft};
            color: {t.success};
        }}
        #PillBadge[tone="warning"] {{
            background: {t.warning_soft};
            color: {t.warning};
        }}
        #PillBadge[tone="danger"] {{
            background: {t.danger_soft};
            color: {t.danger};
        }}
        #PillBadge[tone="accent"] {{
            background: {t.accent_soft};
            color: {t.accent};
        }}
        #PillBadge[tone="neutral"] {{
            background: {t.card_hover};
            color: {t.text_secondary};
        }}
        QPushButton {{
            background: {t.card_hover};
            border: 1px solid {t.border};
            border-radius: {t.radius_small}px;
            color: {t.text_primary};
            padding: 6px 16px;
            min-height: 18px;
            font-weight: 650;
        }}
        QPushButton:hover {{
            background: {t.elevated_surface};
            border-color: {t.border_strong};
        }}
        QPushButton:pressed {{
            background: {t.accent_soft};
        }}
        QPushButton:disabled {{
            background: {t.surface};
            color: {t.text_muted};
            border-color: {t.border};
        }}
        QPushButton#PrimaryButton {{
            background: {t.accent};
            color: {t.on_accent};
            border-color: {t.accent};
        }}
        QPushButton#PrimaryButton:hover {{
            background: {t.accent_hover};
            border-color: {t.accent_hover};
        }}
        QPushButton#PrimaryButton:pressed {{
            background: {t.accent_soft};
        }}
        QPushButton#SecondaryButton {{
            background: {t.card};
            color: {t.text_primary};
        }}
        QPushButton#SecondaryButton:hover {{
            background: {t.card_hover};
        }}
        QPushButton#SecondaryButton:pressed {{
            background: {t.surface};
        }}
        QPushButton#DangerButton {{
            background: {t.danger};
            color: {t.on_accent};
            border-color: {t.danger};
        }}
        QPushButton#DangerButton:hover {{
            background: {t.danger_soft};
            color: {t.danger};
            border-color: {t.danger};
        }}
        QPushButton#DangerButton:pressed {{
            background: {t.danger};
            color: {t.on_accent};
        }}
        QPushButton#NavButton {{
            background: transparent;
            border: 1px solid transparent;
            border-radius: {t.radius_small}px;
            color: {t.text_secondary};
            padding: 11px 12px;
            text-align: left;
            font-weight: 650;
        }}
        QPushButton#NavButton:hover {{
            background: {t.card_hover};
            color: {t.text_primary};
        }}
        QPushButton#NavButton[active="true"] {{
            background: {t.accent_soft};
            color: {t.text_primary};
            border-color: {t.border};
        }}
        QLineEdit, QComboBox, QSpinBox {{
            background: {t.background};
            border: 1px solid {t.border};
            border-radius: {t.radius_small}px;
            color: {t.text_primary};
            padding: 8px 11px;
            min-height: 20px;
        }}
        QLineEdit#SearchField {{
            padding-left: 13px;
        }}
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
            border-color: {t.accent};
        }}
        QComboBox::drop-down {{
            border: 0;
            width: 26px;
        }}
        QCheckBox {{
            color: {t.text_primary};
            spacing: 8px;
        }}
        QCheckBox::indicator {{
            width: 17px;
            height: 17px;
            border-radius: 5px;
            border: 1px solid {t.border_strong};
            background: {t.card};
        }}
        QCheckBox::indicator:checked {{
            background: {t.accent};
            border-color: {t.accent};
        }}
        QTableWidget, QTableView {{
            background: {t.background};
            alternate-background-color: {t.card};
            border: 1px solid {t.border};
            border-radius: {t.radius}px;
            gridline-color: transparent;
            color: {t.text_primary};
            outline: 0;
            selection-background-color: {t.accent_soft};
            selection-color: {t.text_primary};
        }}
        QTableWidget::item, QTableView::item {{
            padding: 8px 10px;
            border: 0;
        }}
        QTableWidget::item:selected, QTableView::item:selected {{
            background: {t.accent_soft};
            color: {t.text_primary};
        }}
        QHeaderView::section {{
            background: {t.card};
            color: {t.text_primary};
            border: 0;
            border-bottom: 1px solid {t.border};
            padding: 10px;
            font-weight: bold;
        }}
        QTableCornerButton::section {{
            background: {t.surface};
            border: 0;
            border-bottom: 1px solid {t.border};
        }}
        QListWidget, QTextEdit, QPlainTextEdit {{
            background: {t.card};
            border: 1px solid {t.border};
            border-radius: {t.radius}px;
            color: {t.text_primary};
            selection-background-color: {t.accent_soft};
            selection-color: {t.text_primary};
            padding: 8px;
        }}
        QListWidget::item {{
            border-radius: {t.radius_small}px;
            padding: 10px;
            margin: 2px;
        }}
        QListWidget::item:selected {{
            background: {t.accent_soft};
            color: {t.text_primary};
        }}
        QScrollBar:vertical {{
            background: transparent;
            width: 10px;
            margin: 4px 2px 4px 2px;
        }}
        QScrollBar::handle:vertical {{
            background: {t.border_strong};
            border-radius: 5px;
            min-height: 30px;
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0;
        }}
        QScrollBar:horizontal {{
            background: transparent;
            height: 10px;
            margin: 2px 4px 2px 4px;
        }}
        QScrollBar::handle:horizontal {{
            background: {t.border_strong};
            border-radius: 5px;
            min-width: 30px;
        }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0;
        }}
        QStatusBar {{
            background: {t.surface};
            color: {t.text_muted};
            border-top: 1px solid {t.border};
            padding: 2px 10px;
        }}
        QDockWidget {{
            color: {t.text_primary};
            titlebar-close-icon: none;
            titlebar-normal-icon: none;
        }}
        QDockWidget::title {{
            background: {t.surface};
            color: {t.text_secondary};
            padding: 8px;
            border-top: 1px solid {t.border};
        }}
        QToolTip {{
            background: {t.elevated_surface};
            color: {t.text_primary};
            border: 1px solid {t.border};
            border-radius: 8px;
            padding: 7px;
        }}
        """
