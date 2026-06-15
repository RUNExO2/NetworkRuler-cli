from pathlib import Path

from networkruler_core.profiles.service import ProfileService


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
        ".mypy_cache/",
    ]:
        assert pattern in gitignore


def test_runtime_state_is_not_committed_to_the_repo():
    # aliases.json is per-user runtime state and must never be tracked.
    assert not Path("aliases.json").exists()
    # The old throwaway profile fixtures must stay deleted.
    for junk in ("profiles/test.json", "profiles/what.json", "profiles/whats.json"):
        assert not Path(junk).exists()


def test_shipped_example_profiles_pass_v2_validation(tmp_path):
    example_dir = Path("examples/profiles")
    profiles = sorted(example_dir.glob("*.json"))
    assert profiles, "expected at least one example profile"

    service = ProfileService(profile_dir=example_dir)
    for profile in profiles:
        result = service.validate_profile(profile.stem)
        assert result.ok, f"{profile.name} failed validation: {result.errors}"
        assert result.legacy is False
