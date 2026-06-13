from pathlib import Path


def test_legacy_wrappers_are_not_in_repo_root():
    assert not Path("nr.bat").exists()
    assert not Path("network_ruler.ps1").exists()
    assert Path("legacy/wrappers/nr.bat").exists()
    assert Path("legacy/wrappers/network_ruler.ps1").exists()


def test_gitignore_covers_runtime_generated_files():
    gitignore = Path(".gitignore").read_text(encoding="utf-8")

    for pattern in [
        "activity_log.txt",
        "__pycache__/",
        "*.pyc",
        "logs/",
        "aliases.json",
        ".pytest_cache/",
        ".ruff_cache/",
    ]:
        assert pattern in gitignore
