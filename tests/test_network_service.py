from __future__ import annotations

import subprocess

import pytest

from networkruler_core.exceptions import UnsupportedPlatformError
from networkruler_core.network.service import NetworkService
from networkruler_core.platform.windows import WindowsNetworkPlatform


class FakePlatform:
    is_supported = True

    def __init__(self) -> None:
        self.calls: list[str] = []

    def list_interfaces(self):
        self.calls.append("list_interfaces")
        return [
            {
                "name": "Wi-Fi",
                "admin_state": "Enabled",
                "state": "Connected",
                "type": "Dedicated",
            }
        ]

    def show_ip_config(self):
        self.calls.append("show_ip_config")
        return {"raw": "Windows IP Configuration\nIPv4 Address . . . : 192.168.1.5"}

    def show_proxy(self):
        self.calls.append("show_proxy")
        return {"raw": "Direct access (no proxy server).", "enabled": False}

    def show_firewall(self):
        self.calls.append("show_firewall")
        return {"raw": "Domain Profile Settings:\nState ON"}

    def wifi_signal(self):
        self.calls.append("wifi_signal")
        return {"ssid": "Home", "signal_percent": 87, "raw": "Signal : 87%"}

    def list_connections(self):
        self.calls.append("list_connections")
        return [
            {
                "protocol": "tcp",
                "local_address": "127.0.0.1:5000",
                "remote_address": "127.0.0.1:6000",
                "status": "ESTABLISHED",
                "pid": 123,
            }
        ]


class UnsupportedPlatform:
    is_supported = False


def test_network_service_returns_structured_interfaces():
    service = NetworkService(platform=FakePlatform())

    interfaces = service.list_interfaces()

    assert interfaces[0].name == "Wi-Fi"
    assert interfaces[0].state == "Connected"


def test_network_service_raises_cleanly_on_unsupported_platform():
    service = NetworkService(platform=UnsupportedPlatform())

    with pytest.raises(UnsupportedPlatformError):
        service.show_proxy()


def test_windows_platform_uses_timeout_and_no_shell_for_interfaces(monkeypatch):
    seen = {}

    def fake_run(command, *, capture_output, text, timeout, shell, check):
        seen["command"] = command
        seen["timeout"] = timeout
        seen["shell"] = shell
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                "Admin State    State          Type             Interface Name\n"
                "-------------------------------------------------------------------------\n"
                "Enabled        Connected      Dedicated        Wi-Fi\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    platform = WindowsNetworkPlatform()
    interfaces = platform.list_interfaces()

    assert seen["command"] == ["netsh", "interface", "show", "interface"]
    assert seen["timeout"] > 0
    assert seen["shell"] is False
    assert interfaces[0]["name"] == "Wi-Fi"


def test_windows_platform_parses_wifi_signal(monkeypatch):
    def fake_run(command, *, capture_output, text, timeout, shell, check):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="SSID                   : Home\nSignal                 : 91%\n",
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    signal = WindowsNetworkPlatform().wifi_signal()

    assert signal["ssid"] == "Home"
    assert signal["signal_percent"] == 91


def test_windows_platform_timeout_is_clean_runtime_error(monkeypatch):
    def fake_run(command, *, capture_output, text, timeout, shell, check):
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr("subprocess.run", fake_run)

    with pytest.raises(RuntimeError, match="timed out"):
        WindowsNetworkPlatform().show_proxy()
