from __future__ import annotations

from collections.abc import Callable
from typing import Any

from networkruler_core.exceptions import UnsupportedPlatformError
from networkruler_core.network.models import (
    FirewallStatus,
    InterfaceInfo,
    IpConfig,
    NetworkActionResult,
    NetworkConnection,
    ProxyStatus,
    WifiSignal,
)
from networkruler_core.platform.windows import WindowsNetworkPlatform
from networkruler_core.safety import (
    CommandRisk,
    RiskLevel,
    SafetyContext,
    SafetyDecision,
    TargetPreview,
    check_windows_admin,
    run_with_safety,
)


class NetworkService:
    def __init__(
        self,
        platform: Any | None = None,
        *,
        is_admin: Callable[[], bool] | None = None,
    ) -> None:
        self._platform = platform or WindowsNetworkPlatform()
        self._is_admin = is_admin or check_windows_admin

    def list_interfaces(self) -> list[InterfaceInfo]:
        self._ensure_supported()
        return [InterfaceInfo(**item) for item in self._platform.list_interfaces()]

    def show_ip_config(self) -> IpConfig:
        self._ensure_supported()
        return IpConfig(**self._platform.show_ip_config())

    def show_proxy(self) -> ProxyStatus:
        self._ensure_supported()
        return ProxyStatus(**self._platform.show_proxy())

    def show_firewall(self) -> FirewallStatus:
        self._ensure_supported()
        return FirewallStatus(**self._platform.show_firewall())

    def wifi_signal(self) -> WifiSignal:
        self._ensure_supported()
        return WifiSignal(**self._platform.wifi_signal())

    def list_connections(self) -> list[NetworkConnection]:
        self._ensure_supported()
        return [NetworkConnection(**item) for item in self._platform.list_connections()]

    def flush_dns(self, context: SafetyContext) -> NetworkActionResult:
        return self._run_network_action(
            action_name="dns.flush",
            command=["ipconfig", "/flushdns"],
            context=context,
            executor=self._platform.flush_dns,
            requires_admin=False,
        )

    def register_dns(self, context: SafetyContext) -> NetworkActionResult:
        return self._run_network_action(
            action_name="dns.register",
            command=["ipconfig", "/registerdns"],
            context=context,
            executor=self._platform.register_dns,
            requires_admin=False,
        )

    def release_ip(
        self,
        context: SafetyContext,
        *,
        adapter: str | None = None,
    ) -> NetworkActionResult:
        return self._run_network_action(
            action_name="ip.release",
            command=self._adapter_command(["ipconfig", "/release"], adapter),
            context=context,
            executor=lambda: self._platform.release_ip(adapter),
            requires_admin=True,
            details={"adapter": adapter} if adapter else {},
        )

    def renew_ip(
        self,
        context: SafetyContext,
        *,
        adapter: str | None = None,
    ) -> NetworkActionResult:
        return self._run_network_action(
            action_name="ip.renew",
            command=self._adapter_command(["ipconfig", "/renew"], adapter),
            context=context,
            executor=lambda: self._platform.renew_ip(adapter),
            requires_admin=True,
            details={"adapter": adapter} if adapter else {},
        )

    def reset_proxy(self, context: SafetyContext) -> NetworkActionResult:
        return self._run_network_action(
            action_name="proxy.reset",
            command=["netsh", "winhttp", "reset", "proxy"],
            context=context,
            executor=self._platform.reset_proxy,
            requires_admin=False,
            current_state_loader=self._platform.show_proxy,
        )

    def set_firewall_enabled(
        self,
        enabled: bool,
        context: SafetyContext,
    ) -> NetworkActionResult:
        state = "on" if enabled else "off"
        return self._run_network_action(
            action_name="firewall.enable" if enabled else "firewall.disable",
            command=["netsh", "advfirewall", "set", "allprofiles", "state", state],
            context=context,
            executor=lambda: self._platform.set_firewall_state(enabled),
            requires_admin=True,
            current_state_loader=self._platform.show_firewall,
        )

    def reset_firewall(self, context: SafetyContext) -> NetworkActionResult:
        return self._run_network_action(
            action_name="firewall.reset",
            command=["netsh", "advfirewall", "reset"],
            context=context,
            executor=self._platform.reset_firewall,
            requires_admin=True,
            current_state_loader=self._platform.show_firewall,
        )

    def reset_winsock(self, context: SafetyContext) -> NetworkActionResult:
        return self._run_network_action(
            action_name="winsock.reset",
            command=["netsh", "winsock", "reset"],
            context=context,
            executor=self._platform.reset_winsock,
            requires_admin=True,
        )

    def reset_tcp(self, context: SafetyContext) -> NetworkActionResult:
        return self._run_network_action(
            action_name="tcp.reset",
            command=["netsh", "int", "ip", "reset"],
            context=context,
            executor=self._platform.reset_tcp,
            requires_admin=True,
        )

    def _ensure_supported(self) -> None:
        if not self._platform.is_supported:
            raise UnsupportedPlatformError("Network tools are only supported on Windows.")

    def _run_network_action(
        self,
        *,
        action_name: str,
        command: list[str],
        context: SafetyContext,
        executor: Callable[[], dict[str, Any]],
        requires_admin: bool,
        current_state_loader: Callable[[], dict[str, Any]] | None = None,
        details: dict[str, Any] | None = None,
    ) -> NetworkActionResult:
        self._ensure_supported()
        details = details or {}
        metadata = CommandRisk(
            name=f"network.{action_name}",
            risk=RiskLevel.ELEVATED_WRITE,
            requires_confirmation=True,
            requires_admin=requires_admin,
            preview=TargetPreview(
                label="Network action",
                identifier=action_name,
                details={"command": command, **details},
            ),
        )
        current_state = None

        def action() -> dict[str, Any]:
            nonlocal current_state
            if current_state_loader is not None:
                current_state = current_state_loader()
            return executor()

        try:
            safety_result = run_with_safety(
                metadata,
                context,
                action,
                is_admin=self._is_admin,
            )
        except RuntimeError as error:
            return self._failure_result(
                action=action_name,
                command=command,
                context=context,
                reason="command_failed",
                message=str(error),
                requires_admin=requires_admin,
                current_state=current_state,
            )

        decision = safety_result.decision
        output = ""
        if isinstance(safety_result.value, dict):
            output = str(safety_result.value.get("raw") or "")

        return NetworkActionResult(
            ok=decision.allowed,
            action=action_name,
            message=decision.message if not decision.executed else "Network action applied.",
            reason=decision.reason,
            command=command,
            output=output,
            current_state=current_state,
            safety=decision,
        )

    def _failure_result(
        self,
        *,
        action: str,
        command: list[str],
        context: SafetyContext,
        reason: str,
        message: str,
        requires_admin: bool,
        current_state: dict[str, object] | None = None,
    ) -> NetworkActionResult:
        return NetworkActionResult(
            ok=False,
            action=action,
            message=message,
            reason=reason,
            command=command,
            current_state=current_state,
            safety=SafetyDecision(
                allowed=False,
                executed=False,
                dry_run=context.dry_run,
                confirmed=context.yes,
                forced=context.force,
                risk=RiskLevel.ELEVATED_WRITE,
                reason=reason,
                message=message,
                preview=TargetPreview(
                    label="Network action",
                    identifier=action,
                    details={"command": command, "requires_admin": requires_admin},
                ),
            ),
        )

    def _adapter_command(self, command: list[str], adapter: str | None) -> list[str]:
        if adapter:
            return [*command, adapter]
        return command
