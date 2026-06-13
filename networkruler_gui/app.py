from __future__ import annotations

import logging
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    from networkruler_core.logging_config import configure_logging

    configure_logging()
    logging.getLogger("networkruler.gui").info("Network Ruler GUI started")

    try:
        from PySide6.QtGui import QFont
        from PySide6.QtWidgets import QApplication
    except ModuleNotFoundError as error:
        raise SystemExit(
            "PySide6 is required for the Network Ruler GUI. "
            'Install it with: python -m pip install -e ".[gui]"'
        ) from error

    from networkruler_gui.main_window import MainWindow
    from networkruler_gui.theme.engine import ThemeEngine
    from networkruler_gui.theme.tokens import ThemeName

    app = QApplication.instance() or QApplication(list(argv or []))
    app.setApplicationName("Network Ruler")
    app.setOrganizationName("NetworkRuler")
    app.setFont(QFont("Segoe UI", 10))

    engine = ThemeEngine()
    engine.apply(app, ThemeName.SYSTEM)

    window = MainWindow(theme_engine=engine)
    window.resize(1320, 860)
    window.show()
    return app.exec()
