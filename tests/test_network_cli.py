from __future__ import annotations

import json

from typer.testing import CliRunner

from networkruler_cli.app import app
from networkruler_core.exceptions import UnsupportedPlatformError
from networkruler_core.network.models import (
    FirewallStatus,
    InterfaceInfo,
    IpConfig,
    NetworkConnection,
    ProxyStatus,
    WifiSignal,
)


def test_network_interfaces_outputs_table(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.list_interfaces",
        lambda self: [
            InterfaceInfo(
                name="Wi-Fi",
                admin_state="Enabled",
                state="Connected",
                type="Dedicated",
            )
        ],
    )

    result = CliRunner().invoke(app, ["network", "interfaces"])

    assert result.exit_code == 0
    assert "Interfaces" in result.output
    assert "Wi-Fi" in result.output


def test_network_interfaces_outputs_json(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.list_interfaces",
        lambda self: [InterfaceInfo(name="Wi-Fi", state="Connected")],
    )

    result = CliRunner().invoke(app, ["network", "interfaces", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["name"] == "Wi-Fi"


def test_network_ip_show_outputs_raw_text(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.show_ip_config",
        lambda self: IpConfig(raw="Windows IP Configuration"),
    )

    result = CliRunner().invoke(app, ["network", "ip", "show"])

    assert result.exit_code == 0
    assert "Windows IP Configuration" in result.output


def test_network_proxy_show_outputs_json(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.show_proxy",
        lambda self: ProxyStatus(raw="Direct access", enabled=False),
    )

    result = CliRunner().invoke(app, ["network", "proxy", "show", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["enabled"] is False


def test_network_firewall_show_outputs_table(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.show_firewall",
        lambda self: FirewallStatus(raw="State ON"),
    )

    result = CliRunner().invoke(app, ["network", "firewall", "show"])

    assert result.exit_code == 0
    assert "Firewall" in result.output
    assert "State ON" in result.output


def test_network_wifi_signal_outputs_json(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.wifi_signal",
        lambda self: WifiSignal(ssid="Home", signal_percent=91, raw="Signal : 91%"),
    )

    result = CliRunner().invoke(app, ["network", "wifi", "signal", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ssid"] == "Home"
    assert payload["signal_percent"] == 91


def test_network_connections_outputs_json(monkeypatch):
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

    result = CliRunner().invoke(app, ["network", "connections", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["pid"] == 123


def test_network_command_handles_unsupported_platform(monkeypatch):
    def raise_unsupported(self):
        raise UnsupportedPlatformError("Network tools are only supported on Windows.")

    monkeypatch.setattr(
        "networkruler_cli.commands.network.NetworkService.show_proxy",
        raise_unsupported,
    )

    result = CliRunner().invoke(app, ["network", "proxy", "show"])

    assert result.exit_code == 1
    assert "only supported on Windows" in result.output
