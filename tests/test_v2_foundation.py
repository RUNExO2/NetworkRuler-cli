from pathlib import Path
import logging

from typer.testing import CliRunner


def test_v2_packages_import():
    import networkruler_cli
    import networkruler_core
    import networkruler_gui

    assert networkruler_core.__version__
    assert networkruler_cli.__version__ == networkruler_core.__version__
    assert networkruler_gui.__version__ == networkruler_core.__version__


def test_cli_app_imports():
    from networkruler_cli.app import app

    assert app.info.name == "nr"


def test_user_paths_resolve_outside_repo_root():
    from networkruler_core.config.paths import get_user_paths

    repo_root = Path.cwd().resolve()
    paths = get_user_paths("NetworkRulerTest")

    for path in (paths.config_dir, paths.cache_dir, paths.log_dir):
        resolved = path.resolve()
        assert resolved != repo_root
        assert repo_root not in resolved.parents


def test_doctor_runs():
    from networkruler_cli.app import app

    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "NetworkRuler doctor" in result.output
    assert "Runtime paths" in result.output


def test_logging_initialization_writes_networkruler_log(tmp_path):
    from networkruler_core.logging_config import configure_logging

    log_file = configure_logging(log_file=tmp_path / "networkruler.log")
    logging.getLogger("networkruler.test").info("logging smoke test")

    assert log_file.exists()
    assert "logging smoke test" in log_file.read_text(encoding="utf-8")
