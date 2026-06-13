from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from networkruler_core.config.paths import DEFAULT_APP_NAME, get_user_paths


def configure_logging(
    app_name: str = DEFAULT_APP_NAME,
    *,
    level: int = logging.INFO,
    log_file: Path | None = None,
) -> Path:
    paths = get_user_paths(app_name)
    destination = log_file or paths.log_file
    destination.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("networkruler")
    logger.setLevel(level)
    logger.handlers.clear()

    handler = RotatingFileHandler(
        destination,
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logger.addHandler(handler)
    logger.propagate = False

    return destination

