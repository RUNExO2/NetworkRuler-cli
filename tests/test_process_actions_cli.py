from __future__ import annotations

from typer.testing import CliRunner

from networkruler_cli.app import app
from networkruler_core.process.models import ProcessActionResult, ProcessInfo
from networkruler_core.safety import (
    RiskLevel,
    SafetyDecision,
    TargetPreview,
)


def make_action_result(
    *,
    ok: bool = True,
    action: str = "kill",
    executed: bool = True,
    dry_run: bool = False,
    reason: str = "allowed",
    message: str = "Safety checks passed.",
    targets: list[ProcessInfo] | None = None,
) -> ProcessActionResult:
    targets = targets or [ProcessInfo(pid=123, name="app.exe")]
    return ProcessActionResult(
        ok=ok,
        action=action,
        message=message,
        reason=reason,
        targets=targets,
        safety=SafetyDecision(
            allowed=ok or dry_run,
            executed=executed,
            dry_run=dry_run,
            confirmed=True,
            forced=False,
            risk=RiskLevel.DANGEROUS,
            reason=reason,
            message=message,
            preview=TargetPreview(
                label="Process",
                identifier="123",
                details={"name": "app.exe"},
            ),
        ),
    )


def test_process_kill_dry_run_prints_preview(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.kill_process",
        lambda self, pid, context: make_action_result(
            executed=False,
            dry_run=True,
            message="Dry-run only. No action executed.",
        ),
    )

    result = CliRunner().invoke(app, ["process", "kill", "123", "--dry-run"])

    assert result.exit_code == 0
    assert "DRY-RUN" in result.output
    assert "app.exe" in result.output


def test_process_kill_requires_yes(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.kill_process",
        lambda self, pid, context: make_action_result(
            ok=False,
            executed=False,
            reason="confirmation_required",
            message="process.kill requires confirmation. Re-run with --yes.",
        ),
    )

    result = CliRunner().invoke(app, ["process", "kill", "123"])

    assert result.exit_code == 1
    assert "--yes" in result.output


def test_process_kill_name_requires_all_for_multiple_matches(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.kill_by_name",
        lambda self, name, context, all_matches=False: make_action_result(
            ok=False,
            executed=False,
            reason="multiple_matches",
            message="Multiple processes matched. Re-run with --all.",
            targets=[
                ProcessInfo(pid=1, name="app.exe"),
                ProcessInfo(pid=2, name="app.exe"),
            ],
        ),
    )

    result = CliRunner().invoke(app, ["process", "kill-name", "app.exe", "--yes"])

    assert result.exit_code == 1
    assert "--all" in result.output
    assert "1" in result.output
    assert "2" in result.output


def test_process_suspend_passes_yes_and_dry_run(monkeypatch):
    seen = {}

    def fake_suspend(self, pid, context):
        seen["pid"] = pid
        seen["dry_run"] = context.dry_run
        seen["yes"] = context.yes
        return make_action_result(action="suspend", executed=False, dry_run=True)

    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.suspend_process",
        fake_suspend,
    )

    result = CliRunner().invoke(
        app,
        ["process", "suspend", "123", "--dry-run", "--yes"],
    )

    assert result.exit_code == 0
    assert seen == {"pid": 123, "dry_run": True, "yes": True}


def test_process_resume_does_not_require_yes(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.resume_process",
        lambda self, pid, context: make_action_result(action="resume"),
    )

    result = CliRunner().invoke(app, ["process", "resume", "123"])

    assert result.exit_code == 0
    assert "resume" in result.output


def test_process_priority_rejects_realtime_without_allow_dangerous():
    result = CliRunner().invoke(app, ["process", "priority", "123", "realtime"])

    assert result.exit_code != 0
    assert "Invalid value" in result.output


def test_process_priority_passes_level(monkeypatch):
    seen = {}

    def fake_priority(self, pid, level, context):
        seen["pid"] = pid
        seen["level"] = level
        seen["yes"] = context.yes
        return make_action_result(action="priority")

    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.set_priority",
        fake_priority,
    )

    result = CliRunner().invoke(app, ["process", "priority", "123", "high", "--yes"])

    assert result.exit_code == 0
    assert seen == {"pid": 123, "level": "high", "yes": True}


def test_process_action_invalid_pid_fails_before_service():
    result = CliRunner().invoke(app, ["process", "kill", "not-a-pid", "--yes"])

    assert result.exit_code != 0
    assert "Invalid value" in result.output
