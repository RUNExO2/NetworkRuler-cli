from __future__ import annotations

from typer.testing import CliRunner

from networkruler_cli.app import app
from networkruler_core.network.models import NetworkActionResult
from networkruler_core.safety import RiskLevel, SafetyDecision, TargetPreview


def make_network_result(
    *,
    ok: bool = True,
    action: str = "dns.flush",
    message: str = "Network action applied.",
    reason: str = "allowed",
    executed: bool = True,
    dry_run: bool = False,
    command: list[str] | None = None,
    current_state: dict[str, object] | None = None,
    output: str = "",
) -> NetworkActionResult:
    command = command or ["ipconfig", "/flushdns"]
    return NetworkActionResult(
        ok=ok,
        action=action,
        message=message,
        reason=reason,
        command=command,
        current_state=current_state,
        output=output or ("ok" if ok and executed else ""),
        safety=SafetyDecision(
            allowed=ok or dry_run,
            executed=executed,
            dry_run=dry_run,
            confirmed=True,
            forced=False,
            risk=RiskLevel.ELEVATED_WRITE,
            reason=reason,
            message=message,
            preview=TargetPreview(
                label="Network action",
                identifier=action,
                details={"command": command},
            ),
        ),
    )


def test_dns_flush_dry_run_prints_preview(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.flush_dns",
        lambda self, context: make_network_result(
            action="dns.flush",
            dry_run=True,
            executed=False,
            message="Dry-run only. No action executed.",
        ),
    )

    result = CliRunner().invoke(app, ["network", "dns", "flush", "--dry-run"])

    assert result.exit_code == 0
    assert "DRY-RUN" in result.output
    assert "ipconfig /flushdns" in result.output


def test_dns_register_requires_yes(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.register_dns",
        lambda self, context: make_network_result(
            ok=False,
            action="dns.register",
            message="network.dns.register requires confirmation. Re-run with --yes.",
            reason="confirmation_required",
            executed=False,
            command=["ipconfig", "/registerdns"],
        ),
    )

    result = CliRunner().invoke(app, ["network", "dns", "register"])

    assert result.exit_code == 1
    assert "--yes" in result.output


def test_ip_release_passes_adapter_and_yes(monkeypatch):
    seen = {}

    def fake_release(self, context, adapter=None):
        seen["adapter"] = adapter
        seen["yes"] = context.yes
        return make_network_result(
            action="ip.release",
            command=["ipconfig", "/release", adapter],
        )

    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.release_ip",
        fake_release,
    )

    result = CliRunner().invoke(
        app,
        ["network", "ip", "release", "--adapter", "Ethernet", "--yes"],
    )

    assert result.exit_code == 0
    assert seen == {"adapter": "Ethernet", "yes": True}
    assert "Ethernet" in result.output


def test_proxy_reset_prints_current_state(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.reset_proxy",
        lambda self, context: make_network_result(
            action="proxy.reset",
            command=["netsh", "winhttp", "reset", "proxy"],
            current_state={"raw": "Direct access", "enabled": False},
        ),
    )

    result = CliRunner().invoke(app, ["network", "proxy", "reset", "--yes"])

    assert result.exit_code == 0
    assert "Current State" in result.output
    assert "Direct access" in result.output


def test_firewall_disable_admin_failure_is_non_zero(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.set_firewall_enabled",
        lambda self, enabled, context: make_network_result(
            ok=False,
            action="firewall.disable",
            message="network.firewall.disable requires administrator privileges.",
            reason="admin_required",
            executed=False,
            command=["netsh", "advfirewall", "set", "allprofiles", "state", "off"],
        ),
    )

    result = CliRunner().invoke(app, ["network", "firewall", "disable", "--yes"])

    assert result.exit_code == 1
    assert "administrator" in result.output


def test_winsock_reset_success_output(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.reset_winsock",
        lambda self, context: make_network_result(
            action="winsock.reset",
            command=["netsh", "winsock", "reset"],
            output="Successfully reset the Winsock Catalog.",
        ),
    )

    result = CliRunner().invoke(app, ["network", "winsock", "reset", "--yes"])

    assert result.exit_code == 0
    assert "winsock.reset" in result.output
    assert "Successfully reset" in result.output


def test_tcp_reset_failure_output(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.reset_tcp",
        lambda self, context: make_network_result(
            ok=False,
            action="tcp.reset",
            message="command failed cleanly",
            reason="command_failed",
            executed=False,
            command=["netsh", "int", "ip", "reset"],
        ),
    )

    result = CliRunner().invoke(app, ["network", "tcp", "reset", "--yes"])

    assert result.exit_code == 1
    assert "command failed cleanly" in result.output
