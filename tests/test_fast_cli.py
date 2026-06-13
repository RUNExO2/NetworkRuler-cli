from __future__ import annotations

import json

from typer.testing import CliRunner

from networkruler_cli.app import app
from networkruler_core.monitor.models import BandwidthSample
from networkruler_core.network.models import (
    InterfaceInfo,
    NetworkConnection,
    ProxyStatus,
    WifiSignal,
)
from networkruler_core.process.models import ProcessActionResult, ProcessInfo
from networkruler_core.safety import RiskLevel, SafetyDecision, TargetPreview


def _process_action_result(
    *,
    action: str = "kill",
    dry_run: bool = True,
    target: ProcessInfo | None = None,
) -> ProcessActionResult:
    target = target or ProcessInfo(pid=123, name="chrome.exe")
    return ProcessActionResult(
        ok=True,
        action=action,
        message="Dry-run only. No action executed.",
        reason="dry_run",
        targets=[target],
        safety=SafetyDecision(
            allowed=True,
            executed=False,
            dry_run=dry_run,
            confirmed=False,
            forced=False,
            risk=RiskLevel.DANGEROUS,
            reason="dry_run",
            message="Dry-run only. No action executed.",
            preview=TargetPreview(
                label="Process",
                identifier=str(target.pid),
                details={"name": target.name},
            ),
        ),
    )


def test_root_opens_quick_launcher():
    result = CliRunner().invoke(app, [])

    assert result.exit_code == 0
    assert "Network Ruler" in result.output
    assert "Fast lane" in result.output
    assert "nr ps" in result.output
    assert "nr if" in result.output


def test_fast_ps_accepts_positional_filter_and_json(monkeypatch):
    seen = {}

    def fake_list(self, filter_text=None, sort_by="cpu"):
        seen["filter_text"] = filter_text
        seen["sort_by"] = sort_by
        return [ProcessInfo(pid=10, name="chrome.exe", cpu_percent=4.2)]

    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.list_processes",
        fake_list,
    )

    result = CliRunner().invoke(app, ["ps", "chrome", "--sort", "name", "--json"])

    assert result.exit_code == 0
    assert seen == {"filter_text": "chrome", "sort_by": "name"}
    assert json.loads(result.output)[0]["name"] == "chrome.exe"


def test_fast_top_is_short_process_view(monkeypatch):
    seen = {}

    def fake_list(self, filter_text=None, sort_by="cpu"):
        seen["sort_by"] = sort_by
        return [ProcessInfo(pid=10, name="busy.exe", cpu_percent=91.2)]

    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.list_processes",
        fake_list,
    )

    result = CliRunner().invoke(app, ["top", "--limit", "5"])

    assert result.exit_code == 0
    assert seen["sort_by"] == "cpu"
    assert "busy.exe" in result.output


def test_process_parent_defaults_to_process_list(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.list_processes",
        lambda self, filter_text=None, sort_by="cpu": [
            ProcessInfo(pid=10, name="parent-default.exe", cpu_percent=1.0)
        ],
    )

    result = CliRunner().invoke(app, ["process"])

    assert result.exit_code == 0
    assert "parent-default.exe" in result.output


def test_network_parent_defaults_to_summary(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.list_interfaces",
        lambda self: [InterfaceInfo(name="Ethernet", state="Connected")],
    )
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.wifi_signal",
        lambda self: WifiSignal(raw="Signal : 88%", ssid="Home", signal_percent=88),
    )
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.show_proxy",
        lambda self: ProxyStatus(raw="Direct access", enabled=False),
    )

    result = CliRunner().invoke(app, ["network"])

    assert result.exit_code == 0
    assert "Ethernet" in result.output
    assert "Home" in result.output


def test_fast_network_shortcuts(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.list_interfaces",
        lambda self: [InterfaceInfo(name="Ethernet", state="Connected")],
    )
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.wifi_signal",
        lambda self: WifiSignal(raw="Signal : 88%", ssid="Home", signal_percent=88),
    )
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.list_connections",
        lambda self: [
            NetworkConnection(
                protocol="tcp",
                local_address="127.0.0.1:5000",
                remote_address="127.0.0.1:6000",
                status="ESTABLISHED",
                pid=123,
            )
        ],
    )

    if_result = CliRunner().invoke(app, ["if"])
    wifi_result = CliRunner().invoke(app, ["wifi"])
    ports_result = CliRunner().invoke(app, ["ports"])

    assert if_result.exit_code == 0
    assert "Ethernet" in if_result.output
    assert wifi_result.exit_code == 0
    assert "Home" in wifi_result.output
    assert ports_result.exit_code == 0
    assert "127.0.0.1:5000" in ports_result.output


def test_fast_bw_uses_monitor_bandwidth(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.monitor.MonitorService.bandwidth_samples",
        lambda self, interval, adapter=None: iter(
            [
                BandwidthSample(
                    timestamp=1.0,
                    adapter=adapter,
                    bytes_sent_per_sec=10.0,
                    bytes_recv_per_sec=20.0,
                    total_bytes_sent=100,
                    total_bytes_recv=200,
                )
            ]
        ),
    )

    result = CliRunner().invoke(app, ["bw", "--jsonl", "--samples", "1"])

    assert result.exit_code == 0
    assert json.loads(result.output)["bytes_recv_per_sec"] == 20.0


def test_fast_kill_routes_pid_and_name(monkeypatch):
    seen = {}

    def fake_kill_pid(self, pid, context):
        seen["pid"] = pid
        seen["pid_dry_run"] = context.dry_run
        return _process_action_result(target=ProcessInfo(pid=pid, name="app.exe"))

    def fake_kill_name(self, name, context, all_matches=False):
        seen["name"] = name
        seen["all"] = all_matches
        return _process_action_result(target=ProcessInfo(pid=222, name=name))

    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.kill_process",
        fake_kill_pid,
    )
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.kill_by_name",
        fake_kill_name,
    )

    pid_result = CliRunner().invoke(app, ["kill", "123", "--dry-run"])
    name_result = CliRunner().invoke(app, ["kill", "chrome.exe", "--dry-run", "--all"])

    assert pid_result.exit_code == 0
    assert name_result.exit_code == 0
    assert seen == {
        "pid": 123,
        "pid_dry_run": True,
        "name": "chrome.exe",
        "all": True,
    }


def test_fast_dns_flush_routes_existing_handler(monkeypatch):
    seen = {}

    def fake_flush(self, context):
        seen["dry_run"] = context.dry_run
        from tests.test_network_actions_cli import make_network_result

        return make_network_result(dry_run=True, executed=False)

    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.flush_dns",
        fake_flush,
    )

    result = CliRunner().invoke(app, ["dns", "flush", "--dry-run"])

    assert result.exit_code == 0
    assert seen == {"dry_run": True}
    assert "DRY-RUN" in result.output
