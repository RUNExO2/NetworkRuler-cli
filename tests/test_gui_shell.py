from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest


def test_gui_package_import_is_lazy_and_does_not_mutate_argv():
    original_argv = list(sys.argv)

    import networkruler_gui
    from networkruler_gui import app

    assert networkruler_gui.__version__
    assert callable(app.main)
    assert sys.argv == original_argv


def test_theme_engine_generates_named_theme_stylesheet():
    from networkruler_gui.theme.engine import ThemeEngine
    from networkruler_gui.theme.tokens import ThemeName

    engine = ThemeEngine()
    stylesheet = engine.stylesheet_for(ThemeName.CLEAN_MINIMAL_DARK)

    assert "#AppShell" in stylesheet
    assert "#PremiumCard" in stylesheet
    assert "#NavButton[active=\"true\"]" in stylesheet
    assert "QPushButton#PrimaryButton" in stylesheet
    assert engine.resolve_theme(ThemeName.SYSTEM).name in ThemeName


def test_theme_tokens_expose_design_system_names():
    from networkruler_gui.theme.engine import ThemeEngine
    from networkruler_gui.theme.tokens import ThemeName

    tokens = ThemeEngine().resolve_theme(ThemeName.CLEAN_MINIMAL_LIGHT)

    assert tokens.background.startswith("#")
    assert tokens.card.startswith("#")
    assert tokens.text_primary.startswith("#")
    assert tokens.text_secondary.startswith("#")
    assert tokens.accent_hover.startswith("#")
    assert tokens.spacing >= 8
    assert tokens.radius >= 12


def test_premium_widgets_can_be_created():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtWidgets import QApplication

    from networkruler_gui.widgets import (
        DangerButton,
        FrostedPanel,
        LogEntryCard,
        PillBadge,
        PremiumCard,
        PrimaryButton,
        SearchField,
        SecondaryButton,
        StatusDot,
        ThemePreviewTile,
        TimelineCard,
        Toolbar,
    )
    from networkruler_gui.theme.engine import ThemeEngine
    from networkruler_gui.theme.tokens import ThemeName

    app = QApplication.instance() or QApplication([])
    tokens = ThemeEngine().resolve_theme(ThemeName.CLEAN_MINIMAL_LIGHT)

    widgets = [
        PremiumCard(),
        FrostedPanel(),
        PillBadge("Ready"),
        PrimaryButton("Primary"),
        SecondaryButton("Secondary"),
        DangerButton("Danger"),
        SearchField("Search"),
        Toolbar(),
        StatusDot("success"),
        ThemePreviewTile(tokens),
        TimelineCard("network.dns.flush", "Dry-run", "No action executed."),
        LogEntryCard("INFO", "Network Ruler started"),
    ]

    assert [widget.objectName() for widget in widgets[:8]] == [
        "PremiumCard",
        "FrostedPanel",
        "PillBadge",
        "PrimaryButton",
        "SecondaryButton",
        "DangerButton",
        "SearchField",
        "Toolbar",
    ]
    assert widgets[9].objectName() == "ThemePreviewTile"
    assert widgets[10].objectName() == "TimelineCard"
    assert widgets[11].objectName() == "LogEntryCard"

    for widget in widgets:
        widget.deleteLater()
    app.processEvents()


def test_gui_and_core_do_not_import_cli_or_legacy():
    problems = []
    for root in (Path("networkruler_core"), Path("networkruler_gui")):
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith(("networkruler_cli", "legacy")):
                            problems.append((str(path), alias.name))
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if module.startswith(("networkruler_cli", "legacy")):
                        problems.append((str(path), module))

    assert problems == []


def test_theme_stylesheet_has_phase_two_polish_selectors():
    from networkruler_gui.theme.engine import ThemeEngine
    from networkruler_gui.theme.tokens import ThemeName

    stylesheet = ThemeEngine().stylesheet_for(ThemeName.CLEAN_MINIMAL_LIGHT)

    assert "qlineargradient" in stylesheet
    assert "#ThemePreviewTile" in stylesheet
    assert "#TimelineCard" in stylesheet
    assert "#LogEntryCard" in stylesheet
    assert "#SafetyDialog" in stylesheet


def test_main_window_can_be_created_when_pyside6_is_available():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtWidgets import QApplication

    from networkruler_gui.main_window import MainWindow
    from networkruler_gui.theme.tokens import ThemeName

    app = QApplication.instance() or QApplication([])
    window = MainWindow(initial_theme=ThemeName.CLEAN_MINIMAL_LIGHT)

    assert window.windowTitle() == "Network Ruler"
    assert window.screen_count == 7
    assert window.centralWidget().objectName() == "AppShell"

    window.close()
    app.processEvents()


def test_navigation_switches_single_stacked_content_page():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtWidgets import QApplication

    from networkruler_gui.main_window import MainWindow
    from networkruler_gui.theme.tokens import ThemeName

    app = QApplication.instance() or QApplication([])
    window = MainWindow(initial_theme=ThemeName.CLEAN_MINIMAL_DARK)

    first_index = window.stack.currentIndex()
    window.sidebar.select("settings")
    app.processEvents()

    assert window.stack.currentIndex() != first_index
    assert window.stack.currentWidget().objectName() == "SettingsScreen"
    assert window.stack.count() == 7

    window.apply_theme(ThemeName.CLEAN_MINIMAL_LIGHT)
    assert window.tokens is not None
    assert window.tokens.name is ThemeName.CLEAN_MINIMAL_LIGHT

    window.close()
    app.processEvents()
