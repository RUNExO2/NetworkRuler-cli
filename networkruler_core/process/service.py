from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

import psutil

from networkruler_core.process.models import (
    ProcessActionResult,
    ProcessInfo,
    ProcessTreeNode,
)
from networkruler_core.safety import (
    CommandRisk,
    RiskLevel,
    SafetyContext,
    SafetyDecision,
    TargetPreview,
    run_with_safety,
)


ProcessSortKey = Literal["cpu", "mem", "name", "pid"]
ProcessPriorityLevel = Literal["low", "below", "normal", "above", "high"]


class ProcessService:
    def __init__(self, psutil_module: Any = psutil) -> None:
        self._psutil = psutil_module

    def list_processes(
        self,
        *,
        filter_text: str | None = None,
        sort_by: ProcessSortKey = "cpu",
    ) -> list[ProcessInfo]:
        processes = []
        attrs = [
            "pid",
            "name",
            "username",
            "cpu_percent",
            "memory_percent",
            "status",
            "ppid",
        ]
        for process in self._psutil.process_iter(attrs):
            try:
                info = self._process_info_from_iter(process.info)
            except (
                psutil.AccessDenied,
                psutil.NoSuchProcess,
                psutil.ZombieProcess,
                KeyError,
            ):
                continue

            if self._matches_filter(info, filter_text):
                processes.append(info)

        return sorted(processes, key=self._sort_key(sort_by), reverse=sort_by in {"cpu", "mem"})

    def get_process_info(self, pid: int) -> ProcessInfo:
        process = self._psutil.Process(pid)
        with process.oneshot():
            return ProcessInfo(
                pid=process.pid,
                name=process.name(),
                username=self._safe_call(process.username),
                cpu_percent=float(self._safe_call(process.cpu_percent, 0.0, interval=0.0)),
                memory_percent=float(self._safe_call(process.memory_percent, 0.0)),
                status=self._safe_call(process.status),
                ppid=self._safe_call(process.ppid),
                cmdline=list(self._safe_call(process.cmdline, [])),
            )

    def process_tree(self) -> list[ProcessTreeNode]:
        processes = self.list_processes(sort_by="pid")
        nodes = {process.pid: ProcessTreeNode(process=process) for process in processes}
        roots: list[ProcessTreeNode] = []

        for process in processes:
            node = nodes[process.pid]
            parent_pid = process.ppid
            if parent_pid in nodes and parent_pid != process.pid:
                nodes[parent_pid].children.append(node)
            else:
                roots.append(node)

        return roots

    def kill_process(
        self,
        pid: int,
        context: SafetyContext,
    ) -> ProcessActionResult:
        process, target, failure = self._load_action_target(pid, "kill", RiskLevel.DANGEROUS, context)
        if failure:
            return failure

        metadata = self._command_risk(
            name="process.kill",
            action="kill",
            risk=RiskLevel.DANGEROUS,
            targets=[target],
            requires_confirmation=True,
        )

        def action() -> None:
            if context.force:
                process.kill()
            else:
                process.terminate()

        return self._run_process_action("kill", metadata, context, [target], action)

    def kill_by_name(
        self,
        name: str,
        context: SafetyContext,
        *,
        all_matches: bool = False,
    ) -> ProcessActionResult:
        matches = [
            process
            for process in self.list_processes(sort_by="pid")
            if process.name.casefold() == name.casefold()
        ]
        metadata = self._command_risk(
            name="process.kill-name",
            action="kill-name",
            risk=RiskLevel.DANGEROUS,
            targets=matches,
            requires_confirmation=True,
        )

        if not matches:
            return self._failure_result(
                action="kill-name",
                risk=RiskLevel.DANGEROUS,
                context=context,
                reason="not_found",
                message=f"No process found with name '{name}'.",
                targets=[],
            )

        if len(matches) > 1 and not all_matches:
            return self._failure_result(
                action="kill-name",
                risk=RiskLevel.DANGEROUS,
                context=context,
                reason="multiple_matches",
                message="Multiple processes matched. Re-run with --all.",
                targets=matches,
            )

        def action() -> None:
            for target in matches:
                process = self._psutil.Process(target.pid)
                process.terminate()

        return self._run_process_action("kill-name", metadata, context, matches, action)

    def suspend_process(
        self,
        pid: int,
        context: SafetyContext,
    ) -> ProcessActionResult:
        process, target, failure = self._load_action_target(
            pid,
            "suspend",
            RiskLevel.DANGEROUS,
            context,
        )
        if failure:
            return failure

        metadata = self._command_risk(
            name="process.suspend",
            action="suspend",
            risk=RiskLevel.DANGEROUS,
            targets=[target],
            requires_confirmation=True,
        )
        return self._run_process_action("suspend", metadata, context, [target], process.suspend)

    def resume_process(
        self,
        pid: int,
        context: SafetyContext,
    ) -> ProcessActionResult:
        process, target, failure = self._load_action_target(
            pid,
            "resume",
            RiskLevel.NORMAL_WRITE,
            context,
        )
        if failure:
            return failure

        metadata = self._command_risk(
            name="process.resume",
            action="resume",
            risk=RiskLevel.NORMAL_WRITE,
            targets=[target],
            requires_confirmation=False,
        )
        return self._run_process_action("resume", metadata, context, [target], process.resume)

    def set_priority(
        self,
        pid: int,
        level: str,
        context: SafetyContext,
    ) -> ProcessActionResult:
        process, target, failure = self._load_action_target(
            pid,
            "priority",
            RiskLevel.ELEVATED_WRITE,
            context,
        )
        if failure:
            return failure

        priority_value = self._priority_value(level)
        if priority_value is None:
            return self._failure_result(
                action="priority",
                risk=RiskLevel.ELEVATED_WRITE,
                context=context,
                reason="invalid_priority",
                message=(
                    "Invalid priority level. Use low, below, normal, above, or high."
                ),
                targets=[target],
            )

        metadata = self._command_risk(
            name="process.priority",
            action="priority",
            risk=RiskLevel.ELEVATED_WRITE,
            targets=[target],
            requires_confirmation=True,
            details={"level": level},
        )
        return self._run_process_action(
            "priority",
            metadata,
            context,
            [target],
            lambda: process.nice(priority_value),
        )

    def _process_info_from_iter(self, raw: dict[str, Any]) -> ProcessInfo:
        return ProcessInfo(
            pid=int(raw["pid"]),
            name=str(raw.get("name") or ""),
            username=raw.get("username"),
            cpu_percent=float(raw.get("cpu_percent") or 0.0),
            memory_percent=float(raw.get("memory_percent") or 0.0),
            status=raw.get("status"),
            ppid=raw.get("ppid"),
        )

    def _matches_filter(self, process: ProcessInfo, filter_text: str | None) -> bool:
        if not filter_text:
            return True
        needle = filter_text.casefold()
        return needle in process.name.casefold() or needle in str(process.pid)

    def _sort_key(self, sort_by: ProcessSortKey):
        sorters = {
            "cpu": lambda process: process.cpu_percent,
            "mem": lambda process: process.memory_percent,
            "name": lambda process: process.name.casefold(),
            "pid": lambda process: process.pid,
        }
        return sorters[sort_by]

    def _safe_call(self, function, default=None, **kwargs):
        try:
            return function(**kwargs)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            return default

    def _load_action_target(
        self,
        pid: int,
        action: str,
        risk: RiskLevel,
        context: SafetyContext,
    ) -> tuple[Any | None, ProcessInfo | None, ProcessActionResult | None]:
        try:
            process = self._psutil.Process(pid)
            target = self.get_process_info(pid)
            return process, target, None
        except psutil.NoSuchProcess:
            return (
                None,
                None,
                self._failure_result(
                    action=action,
                    risk=risk,
                    context=context,
                    reason="not_found",
                    message=f"No process found with PID {pid}.",
                    targets=[],
                ),
            )
        except psutil.AccessDenied:
            return (
                None,
                None,
                self._failure_result(
                    action=action,
                    risk=risk,
                    context=context,
                    reason="access_denied",
                    message=f"Access denied for PID {pid}.",
                    targets=[],
                ),
            )

    def _run_process_action(
        self,
        action_name: str,
        metadata: CommandRisk,
        context: SafetyContext,
        targets: list[ProcessInfo],
        action: Callable[[], None],
    ) -> ProcessActionResult:
        try:
            safety_result = run_with_safety(metadata, context, action)
        except psutil.AccessDenied:
            return self._failure_result(
                action=action_name,
                risk=metadata.risk,
                context=context,
                reason="access_denied",
                message="Access denied while applying process action.",
                targets=targets,
            )
        except psutil.NoSuchProcess:
            return self._failure_result(
                action=action_name,
                risk=metadata.risk,
                context=context,
                reason="not_found",
                message="Process disappeared before the action could be applied.",
                targets=targets,
            )

        decision = safety_result.decision
        return ProcessActionResult(
            ok=decision.allowed,
            action=action_name,
            message=decision.message if not decision.executed else f"Process {action_name} applied.",
            reason=decision.reason,
            targets=targets,
            safety=decision,
        )

    def _command_risk(
        self,
        *,
        name: str,
        action: str,
        risk: RiskLevel,
        targets: list[ProcessInfo],
        requires_confirmation: bool,
        details: dict[str, Any] | None = None,
    ) -> CommandRisk:
        return CommandRisk(
            name=name,
            risk=risk,
            requires_confirmation=requires_confirmation,
            preview=self._target_preview(action, targets, details or {}),
        )

    def _target_preview(
        self,
        action: str,
        targets: list[ProcessInfo],
        details: dict[str, Any],
    ) -> TargetPreview:
        if len(targets) == 1:
            target = targets[0]
            return TargetPreview(
                label="Process",
                identifier=str(target.pid),
                details={"name": target.name, **details},
            )
        return TargetPreview(
            label="Processes",
            identifier=action,
            details={"matches": [target.to_dict() for target in targets], **details},
        )

    def _failure_result(
        self,
        *,
        action: str,
        risk: RiskLevel,
        context: SafetyContext,
        reason: str,
        message: str,
        targets: list[ProcessInfo],
    ) -> ProcessActionResult:
        return ProcessActionResult(
            ok=False,
            action=action,
            message=message,
            reason=reason,
            targets=targets,
            safety=SafetyDecision(
                allowed=False,
                executed=False,
                dry_run=context.dry_run,
                confirmed=context.yes,
                forced=context.force,
                risk=risk,
                reason=reason,
                message=message,
                preview=self._target_preview(action, targets, {}) if targets else None,
            ),
        )

    def _priority_value(self, level: str) -> int | None:
        priority_map = {
            "low": self._psutil.IDLE_PRIORITY_CLASS,
            "below": self._psutil.BELOW_NORMAL_PRIORITY_CLASS,
            "normal": self._psutil.NORMAL_PRIORITY_CLASS,
            "above": self._psutil.ABOVE_NORMAL_PRIORITY_CLASS,
            "high": self._psutil.HIGH_PRIORITY_CLASS,
        }
        return priority_map.get(level)
