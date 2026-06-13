from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_cache_path, user_config_path, user_data_path, user_log_path


DEFAULT_APP_NAME = "NetworkRuler"


@dataclass(frozen=True)
class UserPaths:
    app_name: str
    config_dir: Path
    cache_dir: Path
    data_dir: Path
    log_dir: Path

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def log_file(self) -> Path:
        return self.log_dir / "networkruler.log"


def get_user_paths(app_name: str = DEFAULT_APP_NAME) -> UserPaths:
    return UserPaths(
        app_name=app_name,
        config_dir=user_config_path(app_name, appauthor=False),
        cache_dir=user_cache_path(app_name, appauthor=False),
        data_dir=user_data_path(app_name, appauthor=False),
        log_dir=user_log_path(app_name, appauthor=False),
    )

