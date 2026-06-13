from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from networkruler_core.safety import RiskLevel


@dataclass(frozen=True)
class ProfileAction:
    type: str
    params: dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.READ
    requires_admin: bool = False
    supports_dry_run: bool = True

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        return data


@dataclass(frozen=True)
class ProfileValidationResult:
    ok: bool
    name: str
    reason: str
    legacy: bool = False
    errors: list[str] = field(default_factory=list)
    actions: list[ProfileAction] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "name": self.name,
            "reason": self.reason,
            "legacy": self.legacy,
            "errors": self.errors,
            "actions": [action.to_dict() for action in self.actions],
        }


@dataclass(frozen=True)
class ProfileApplyResult:
    ok: bool
    name: str
    reason: str
    message: str
    dry_run: bool
    plan: list[ProfileAction] = field(default_factory=list)
    executed: list[object] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "name": self.name,
            "reason": self.reason,
            "message": self.message,
            "dry_run": self.dry_run,
            "plan": [action.to_dict() for action in self.plan],
            "executed": [
                item.to_dict() if hasattr(item, "to_dict") else item
                for item in self.executed
            ],
            "errors": self.errors,
        }

