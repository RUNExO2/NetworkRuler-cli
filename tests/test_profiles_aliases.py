from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from networkruler_cli.app import app
from networkruler_core.aliases.service import AliasService
from networkruler_core.profiles.service import ProfileService
from networkruler_core.safety import RiskLevel, SafetyContext


def write_profile(directory: Path, name: str, payload: dict[str, object]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")


def valid_profile_payload(name: str = "safe") -> dict[str, object]:
    return {
        "version": 2,
        "name": name,
        "actions": [
            {
                "type": "network.dns.flush",
                "params": {},
                "risk_level": "ELEVATED_WRITE",
                "requires_admin": False,
                "supports_dry_run": True,
            }
        ],
    }


def test_valid_profile_validates(tmp_path):
    write_profile(tmp_path, "safe", valid_profile_payload())
    service = ProfileService(profile_dir=tmp_path)

    result = service.validate_profile("safe")

    assert result.ok is True
    assert result.legacy is False
    assert result.actions[0].type == "network.dns.flush"


def test_invalid_profile_reports_schema_errors(tmp_path):
    write_profile(
        tmp_path,
        "broken",
        {"version": 2, "name": "broken", "actions": [{"params": {}}]},
    )
    service = ProfileService(profile_dir=tmp_path)

    result = service.validate_profile("broken")

    assert result.ok is False
    assert result.reason == "invalid"
    assert "actions[0].type is required" in result.errors


def test_legacy_profile_detected_and_not_supported(tmp_path):
    write_profile(
        tmp_path,
        "legacy",
        {"profile_name": "legacy", "settings": "-f dns", "commands": ["-f dns"]},
    )
    service = ProfileService(profile_dir=tmp_path)

    result = service.validate_profile("legacy")

    assert result.ok is False
    assert result.legacy is True
    assert result.reason == "legacy_unsupported"


def test_profile_apply_dry_run_returns_full_plan_and_never_executes(tmp_path):
    write_profile(tmp_path, "safe", valid_profile_payload())
    executed = []

    def fake_handler(params, context):
        executed.append(params)
        raise AssertionError("dry-run must not execute handlers")

    service = ProfileService(
        profile_dir=tmp_path,
        action_handlers={"network.dns.flush": fake_handler},
    )

    result = service.apply_profile("safe", SafetyContext(dry_run=True))

    assert result.ok is True
    assert result.dry_run is True
    assert result.executed == []
    assert executed == []
    assert result.plan[0].type == "network.dns.flush"
    assert result.plan[0].risk_level == RiskLevel.ELEVATED_WRITE


def test_profile_apply_validates_every_action_before_execution(tmp_path):
    write_profile(
        tmp_path,
        "mixed",
        {
            "version": 2,
            "name": "mixed",
            "actions": [
                {
                    "type": "network.dns.flush",
                    "params": {},
                    "risk_level": "ELEVATED_WRITE",
                    "requires_admin": False,
                    "supports_dry_run": True,
                },
                {
                    "type": "unknown.action",
                    "params": {},
                    "risk_level": "READ",
                    "requires_admin": False,
                    "supports_dry_run": True,
                },
            ],
        },
    )
    executed = []
    service = ProfileService(
        profile_dir=tmp_path,
        action_handlers={"network.dns.flush": lambda params, context: executed.append(params)},
    )

    result = service.apply_profile("mixed", SafetyContext(yes=True))

    assert result.ok is False
    assert result.reason == "invalid"
    assert executed == []


def test_alias_recursion_prevention(tmp_path):
    service = AliasService(alias_file=tmp_path / "aliases.json")
    service.set_alias("base", ["network", "dns", "flush"])
    service.set_alias("shortcut", ["base"])

    result = service.set_alias("base", ["shortcut"])

    assert result.ok is False
    assert result.reason == "recursive_alias"


def test_alias_storage_path_uses_config_directory(tmp_path):
    alias_file = tmp_path / "config" / "aliases.json"
    service = AliasService(alias_file=alias_file)

    result = service.set_alias("flush", ["network", "dns", "flush"])

    assert result.ok is True
    assert alias_file.exists()
    assert service.storage_path == alias_file
    assert Path.cwd().resolve() not in alias_file.resolve().parents


def test_profile_apply_dry_run_cli_prints_plan(tmp_path, monkeypatch):
    write_profile(tmp_path, "safe", valid_profile_payload())
    monkeypatch.setattr(
        "networkruler_cli.commands.profile.ProfileService",
        lambda: ProfileService(profile_dir=tmp_path),
    )

    result = CliRunner().invoke(app, ["profile", "apply", "safe", "--dry-run"])

    assert result.exit_code == 0
    assert "Execution Plan" in result.output
    assert "network.dns.flush" in result.output


def test_alias_resolve_cli_prints_shortcut(tmp_path, monkeypatch):
    service = AliasService(alias_file=tmp_path / "aliases.json")
    service.set_alias("flush", ["network", "dns", "flush"])
    monkeypatch.setattr("networkruler_cli.commands.alias.AliasService", lambda: service)

    result = CliRunner().invoke(app, ["alias", "resolve", "flush"])

    assert result.exit_code == 0
    assert "network dns flush" in result.output


def test_alias_execute_routes_to_cli_command(tmp_path, monkeypatch):
    service = AliasService(alias_file=tmp_path / "aliases.json")
    service.set_alias("ver", ["version"])
    monkeypatch.setattr("networkruler_cli.commands.alias.AliasService", lambda: service)

    result = CliRunner().invoke(app, ["alias", "execute", "ver"])

    assert result.exit_code == 0
    assert "2.0.0" in result.output
