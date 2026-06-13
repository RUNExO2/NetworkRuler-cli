from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtWidgets import (
    QDockWidget,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from networkruler_gui.navigation import NavigationItem, Sidebar
from networkruler_gui.screens import (
    DashboardScreen,
    NetworkScreen,
    ProcessesScreen,
)
from networkruler_gui.theme.engine import ThemeEngine
from networkruler_gui.theme.tokens import ThemeName, ThemeTokens


class MainWindow(QMainWindow):
    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        theme_engine: ThemeEngine | None = None,
        initial_theme: ThemeName = ThemeName.SYSTEM,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Network Ruler")
        self.theme_engine = theme_engine or ThemeEngine()
        self.tokens: ThemeTokens | None = None
        self._screens: dict[str, QWidget] = {}
        self.setMinimumSize(1100, 720)

        self.stack = QStackedWidget()
        self.stack.setObjectName("ContentStack")
        self.opacity = QGraphicsOpacityEffect(self.stack)
        self.stack.setGraphicsEffect(self.opacity)
        self.fade = QPropertyAnimation(self.opacity, b"opacity", self)
        self.fade.setDuration(160)
        self.fade.setEasingCurve(QEasingCurve.Type.OutCubic)

        items = [
            NavigationItem("dashboard", "Dashboard", "System health and quick actions"),
            NavigationItem("processes", "Apps & Performance", "Manage user applications"),
            NavigationItem("network", "Network", "Check internet connection"),
        ]
        self.sidebar = Sidebar(items)
        self.sidebar.setFixedWidth(252)
        self.sidebar.selected.connect(self.select_screen)

        shell = QWidget()
        shell.setObjectName("AppShell")
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(self.sidebar)
        content = QFrame()
        content.setObjectName("ContentFrame")
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.addWidget(self.stack)
        shell_layout.addWidget(content, 1)
        self.setCentralWidget(shell)

        self._create_screens()
        self._create_console_dock()
        self.apply_theme(initial_theme)
        self.sidebar.select("dashboard")
        self.statusBar().showMessage("Network Ruler v2 (Non-Technical View)")

    @property
    def screen_count(self) -> int:
        return len(self._screens)

    def select_screen(self, key: str) -> None:
        screen = self._screens.get(key)
        if screen is None:
            return
        self.fade.stop()
        self.opacity.setOpacity(0.55)
        self.stack.setCurrentWidget(screen)
        self.fade.setStartValue(0.55)
        self.fade.setEndValue(1.0)
        self.fade.start()

    def apply_theme(self, theme: ThemeName | str) -> None:
        from PySide6.QtWidgets import QApplication

        instance = QApplication.instance()
        if instance is not None:
            self.tokens = self.theme_engine.apply(instance, theme)

    def _create_screens(self) -> None:
        dashboard = DashboardScreen()
        dashboard.navigate_requested.connect(self.sidebar.select)
        screens: list[tuple[str, QWidget]] = [
            ("dashboard", dashboard),
            ("processes", ProcessesScreen()),
            ("network", NetworkScreen()),
        ]
        for key, screen in screens:
            screen.setObjectName(f"{key.title().replace('_', '')}Screen")
            self._screens[key] = screen
            self.stack.addWidget(screen)

    def _create_console_dock(self) -> None:
        pass # Removed to simplify UI for non-technical users
