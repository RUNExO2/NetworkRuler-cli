from __future__ import annotations

from dataclasses import asdict, dataclass, field

from networkruler_core.safety import SafetyDecision


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    username: str | None = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    status: str | None = None
    ppid: int | None = None
    cmdline: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProcessTreeNode:
    process: ProcessInfo
    children: list["ProcessTreeNode"] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "process": self.process.to_dict(),
            "children": [child.to_dict() for child in self.children],
        }


@dataclass(frozen=True)
class ProcessActionResult:
    ok: bool
    action: str
    message: str
    reason: str
    targets: list[ProcessInfo]
    safety: SafetyDecision

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "action": self.action,
            "message": self.message,
            "reason": self.reason,
            "targets": [target.to_dict() for target in self.targets],
            "safety": self.safety.to_dict(),
        }
