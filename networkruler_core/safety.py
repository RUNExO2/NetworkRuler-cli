from __future__ import annotations

import ctypes
import platform
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, TypeVar


class RiskLevel(Enum):
    READ = "READ"
    NORMAL_WRITE = "NORMAL_WRITE"
    ELEVATED_WRITE = "ELEVATED_WRITE"
    DANGEROUS = "DANGEROUS"


@dataclass(frozen=True)
class TargetPreview:
    label: str
    identifier: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CommandRisk:
    name: str
    risk: RiskLevel
    preview: TargetPreview | None = None
    requires_confirmation: bool = False
    requires_admin: bool = False
    supports_dry_run: bool = True
    supports_force: bool = True


@dataclass(frozen=True)
class SafetyContext:
    dry_run: bool = False
    yes: bool = False
    force: bool = False


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    executed: bool
    dry_run: bool
    confirmed: bool
    forced: bool
    risk: RiskLevel
    reason: str
    message: str
    preview: TargetPreview | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "executed": self.executed,
            "dry_run": self.dry_run,
            "confirmed": self.confirmed,
            "forced": self.forced,
            "risk": self.risk.value,
            "reason": self.reason,
            "message": self.message,
            "preview": self.preview.to_dict() if self.preview else None,
        }


T = TypeVar("T")


@dataclass(frozen=True)
class SafetyResult:
    decision: SafetyDecision
    value: Any = None

    @property
    def allowed(self) -> bool:
        return self.decision.allowed

    @property
    def executed(self) -> bool:
        return self.decision.executed

    @property
    def dry_run(self) -> bool:
        return self.decision.dry_run

    @property
    def preview(self) -> TargetPreview | None:
        return self.decision.preview

    def to_dict(self) -> dict[str, Any]:
        return {
            "safety": self.decision.to_dict(),
            "value": self.value,
        }


def evaluate_safety(
    metadata: CommandRisk,
    context: SafetyContext,
    *,
    is_admin: Callable[[], bool] | None = None,
) -> SafetyDecision:
    admin_probe = is_admin or check_windows_admin

    if context.dry_run and not metadata.supports_dry_run:
        return _decision(
            metadata,
            context,
            allowed=False,
            reason="dry_run_not_supported",
            message=f"{metadata.name} does not support dry-run.",
        )

    if context.dry_run:
        return _decision(
            metadata,
            context,
            allowed=True,
            reason="dry_run",
            message="Dry-run only. No action executed.",
        )

    if metadata.requires_admin and not admin_probe():
        return _decision(
            metadata,
            context,
            allowed=False,
            reason="admin_required",
            message=f"{metadata.name} requires administrator privileges.",
        )

    if metadata.requires_confirmation and not (context.yes or context.force):
        return _decision(
            metadata,
            context,
            allowed=False,
            reason="confirmation_required",
            message=f"{metadata.name} requires confirmation. Re-run with --yes.",
        )

    if context.force and not metadata.supports_force:
        return _decision(
            metadata,
            context,
            allowed=False,
            reason="force_not_supported",
            message=f"{metadata.name} does not support --force.",
        )

    return _decision(
        metadata,
        context,
        allowed=True,
        reason="allowed",
        message="Safety checks passed.",
    )


def run_with_safety(
    metadata: CommandRisk,
    context: SafetyContext,
    action: Callable[[], T],
    *,
    is_admin: Callable[[], bool] | None = None,
) -> SafetyResult:
    decision = evaluate_safety(metadata, context, is_admin=is_admin)
    if not decision.allowed or context.dry_run:
        return SafetyResult(decision=decision, value=None)

    value = action()
    executed_decision = SafetyDecision(
        allowed=decision.allowed,
        executed=True,
        dry_run=decision.dry_run,
        confirmed=decision.confirmed,
        forced=decision.forced,
        risk=decision.risk,
        reason=decision.reason,
        message=decision.message,
        preview=decision.preview,
    )
    return SafetyResult(decision=executed_decision, value=value)


def check_windows_admin(
    *,
    system_name: Callable[[], str] = platform.system,
    admin_probe: Callable[[], bool] | None = None,
) -> bool:
    if system_name().lower() != "windows":
        return False

    probe = admin_probe or _windows_admin_probe
    try:
        return bool(probe())
    except Exception:
        return False


def _windows_admin_probe() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def _decision(
    metadata: CommandRisk,
    context: SafetyContext,
    *,
    allowed: bool,
    reason: str,
    message: str,
) -> SafetyDecision:
    return SafetyDecision(
        allowed=allowed,
        executed=False,
        dry_run=context.dry_run,
        confirmed=context.yes,
        forced=context.force,
        risk=metadata.risk,
        reason=reason,
        message=message,
        preview=metadata.preview,
    )
