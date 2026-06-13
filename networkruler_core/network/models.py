from __future__ import annotations

from dataclasses import asdict, dataclass

from networkruler_core.safety import SafetyDecision


@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    admin_state: str | None = None
    state: str | None = None
    type: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class IpConfig:
    raw: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProxyStatus:
    raw: str
    enabled: bool | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FirewallStatus:
    raw: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class WifiSignal:
    raw: str
    ssid: str | None = None
    signal_percent: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class NetworkConnection:
    protocol: str
    local_address: str
    remote_address: str | None = None
    status: str | None = None
    pid: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class NetworkActionResult:
    ok: bool
    action: str
    message: str
    reason: str
    command: list[str]
    safety: SafetyDecision
    output: str = ""
    current_state: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "action": self.action,
            "message": self.message,
            "reason": self.reason,
            "command": self.command,
            "output": self.output,
            "current_state": self.current_state,
            "safety": self.safety.to_dict(),
        }
