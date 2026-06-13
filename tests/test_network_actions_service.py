from __future__ import annotations

import subprocess

from networkruler_core.network.service import NetworkService
from networkruler_core.platform.windows import WindowsNetworkPlatform
from networkruler_core.safety import SafetyContext


class FakeNetworkPlatform:
    is_supported = True

    def __init__(self) -> None:
        self.executed: list[tuple[str, dict[str, object]]] = []
        self.show_proxy_calls = 0
        self.show_firewall_calls = 0
        self.fail_next = False

    def show_proxy(self):
        self.show_proxy_calls += 1
        return {"raw": "Direct access (no proxy server).", "enabled": False}

    def show_firewall(self):
        self.show_firewall_calls += 1
        return {"raw": "State ON"}

    def flush_dns(self):
        return self._record("dns.flush")

    def register_dns(self):
        return self._record("dns.register")

    def release_ip(self, adapter: str | None = None):
        return self._record("ip.release", adapter=adapter)

    def renew_ip(self, adapter: str | None = None):
        return self._record("ip.renew", adapter=adapter)

    def reset_proxy(self):
        return self._record("proxy.reset")

    def set_firewall_state(self, enabled: bool):
        return self._record("firewall.enable" if enabled else "firewall.disable")

    def reset_firewall(self):
        return self._record("firewall.reset")

    def reset_winsock(self):
        return self._record("winsock.reset")

    def reset_tcp(self):
        return self._record("tcp.reset")

    def _record(self, action: str, **kwargs):
        if self.fail_next:
            raise RuntimeError("command failed cleanly")
        self.executed.append((action, kwargs))
        return {"raw": f"{action} ok"}


def test_network_action_dry_run_never_executes_platform_action():
    platform = FakeNetworkPlatform()
    service = NetworkService(platform=platform)

    result = service.flush_dns(SafetyContext(dry_run=True))

    assert result.ok is True
    assert result.safety.dry_run is True
    assert result.safety.executed is False
    assert platform.executed == []
    assert result.command == ["ipconfig", "/flushdns"]


def test_network_action_requires_confirmation():
    platform = FakeNetworkPlatform()
    service = NetworkService(platform=platform)

    result = service.register_dns(SafetyContext())

    assert result.ok is False
    assert result.reason == "confirmation_required"
    assert platform.executed == []


def test_admin_required_behavior_blocks_before_execution():
    platform = FakeNetworkPlatform()
    service = NetworkService(platform=platform, is_admin=lambda: False)

    result = service.reset_winsock(SafetyContext(yes=True))

    assert result.ok is False
    assert result.reason == "admin_required"
    assert platform.executed == []


def test_yes_allows_network_action_to_execute():
    platform = FakeNetworkPlatform()
    service = NetworkService(platform=platform, is_admin=lambda: True)

    result = service.renew_ip(SafetyContext(yes=True), adapter="Ethernet")

    assert result.ok is True
    assert result.safety.executed is True
    assert platform.executed == [("ip.renew", {"adapter": "Ethernet"})]
    assert result.command == ["ipconfig", "/renew", "Ethernet"]


def test_proxy_reset_captures_current_state_before_change():
    platform = FakeNetworkPlatform()
    service = NetworkService(platform=platform, is_admin=lambda: True)

    result = service.reset_proxy(SafetyContext(yes=True))

    assert result.ok is True
    assert platform.show_proxy_calls == 1
    assert result.current_state == {"raw": "Direct access (no proxy server).", "enabled": False}
    assert platform.executed == [("proxy.reset", {})]


def test_firewall_disable_captures_current_state_before_change():
    platform = FakeNetworkPlatform()
    service = NetworkService(platform=platform, is_admin=lambda: True)

    result = service.set_firewall_enabled(False, SafetyContext(yes=True))

    assert result.ok is True
    assert platform.show_firewall_calls == 1
    assert result.current_state == {"raw": "State ON"}
    assert platform.executed == [("firewall.disable", {})]


def test_failed_platform_command_returns_clean_error():
    platform = FakeNetworkPlatform()
    platform.fail_next = True
    service = NetworkService(platform=platform, is_admin=lambda: True)

    result = service.flush_dns(SafetyContext(yes=True))

    assert result.ok is False
    assert result.reason == "command_failed"
    assert result.safety.executed is False
    assert "command failed cleanly" in result.message


def test_windows_write_command_uses_timeout_and_no_shell(monkeypatch):
    seen = {}

    def fake_run(command, *, capture_output, text, timeout, shell, check):
        seen["command"] = command
        seen["timeout"] = timeout
        seen["shell"] = shell
        return subprocess.CompletedProcess(command, 0, stdout="flushed", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = WindowsNetworkPlatform().flush_dns()

    assert seen["command"] == ["ipconfig", "/flushdns"]
    assert seen["timeout"] > 0
    assert seen["shell"] is False
    assert result == {"raw": "flushed"}
