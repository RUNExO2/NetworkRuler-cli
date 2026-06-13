from __future__ import annotations

from types import SimpleNamespace

import psutil

from networkruler_core.process.service import ProcessService
from networkruler_core.safety import SafetyContext


class FakeProcess:
    def __init__(
        self,
        *,
        pid: int,
        name: str,
        deny_action: bool = False,
    ) -> None:
        self.pid = pid
        self._name = name
        self._deny_action = deny_action
        self.terminated = False
        self.killed = False
        self.suspended = False
        self.resumed = False
        self.priority = None

    @property
    def info(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "name": self._name,
            "username": "user",
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "status": "running",
            "ppid": 0,
        }

    def oneshot(self) -> "FakeProcess":
        return self

    def __enter__(self) -> "FakeProcess":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def name(self) -> str:
        return self._name

    def username(self) -> str:
        return "user"

    def cpu_percent(self, interval: float | None = None) -> float:
        return 0.0

    def memory_percent(self) -> float:
        return 0.0

    def status(self) -> str:
        return "running"

    def ppid(self) -> int:
        return 0

    def cmdline(self) -> list[str]:
        return [self._name]

    def terminate(self) -> None:
        if self._deny_action:
            raise psutil.AccessDenied(pid=self.pid)
        self.terminated = True

    def kill(self) -> None:
        if self._deny_action:
            raise psutil.AccessDenied(pid=self.pid)
        self.killed = True

    def suspend(self) -> None:
        if self._deny_action:
            raise psutil.AccessDenied(pid=self.pid)
        self.suspended = True

    def resume(self) -> None:
        if self._deny_action:
            raise psutil.AccessDenied(pid=self.pid)
        self.resumed = True

    def nice(self, value: int) -> None:
        if self._deny_action:
            raise psutil.AccessDenied(pid=self.pid)
        self.priority = value


def make_psutil_module(processes: list[FakeProcess]) -> SimpleNamespace:
    by_pid = {process.pid: process for process in processes}

    def process_iter(attrs: list[str]) -> list[FakeProcess]:
        return processes

    def process(pid: int) -> FakeProcess:
        try:
            return by_pid[pid]
        except KeyError as error:
            raise psutil.NoSuchProcess(pid=pid) from error

    return SimpleNamespace(
        process_iter=process_iter,
        Process=process,
        IDLE_PRIORITY_CLASS=1,
        BELOW_NORMAL_PRIORITY_CLASS=2,
        NORMAL_PRIORITY_CLASS=3,
        ABOVE_NORMAL_PRIORITY_CLASS=4,
        HIGH_PRIORITY_CLASS=5,
    )


def test_kill_process_dry_run_never_mutates():
    target = FakeProcess(pid=123, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([target]))

    result = service.kill_process(123, SafetyContext(dry_run=True, yes=True))

    assert target.terminated is False
    assert result.ok is True
    assert result.action == "kill"
    assert result.safety.dry_run is True
    assert result.safety.executed is False
    assert result.targets[0].pid == 123


def test_dangerous_kill_requires_confirmation():
    target = FakeProcess(pid=123, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([target]))

    result = service.kill_process(123, SafetyContext())

    assert result.ok is False
    assert target.terminated is False
    assert result.safety.reason == "confirmation_required"
    assert result.targets[0].name == "app.exe"


def test_yes_allows_pid_kill_to_execute():
    target = FakeProcess(pid=123, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([target]))

    result = service.kill_process(123, SafetyContext(yes=True))

    assert result.ok is True
    assert target.terminated is True
    assert result.safety.executed is True


def test_force_uses_kill_instead_of_terminate():
    target = FakeProcess(pid=123, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([target]))

    result = service.kill_process(123, SafetyContext(force=True))

    assert result.ok is True
    assert target.terminated is False
    assert target.killed is True
    assert result.safety.forced is True


def test_kill_name_previews_multiple_matches_and_requires_all():
    first = FakeProcess(pid=1, name="app.exe")
    second = FakeProcess(pid=2, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([first, second]))

    result = service.kill_by_name("app.exe", SafetyContext(yes=True), all_matches=False)

    assert result.ok is False
    assert result.reason == "multiple_matches"
    assert first.terminated is False
    assert second.terminated is False
    assert [target.pid for target in result.targets] == [1, 2]


def test_kill_name_with_all_executes_every_match():
    first = FakeProcess(pid=1, name="app.exe")
    second = FakeProcess(pid=2, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([first, second]))

    result = service.kill_by_name("app.exe", SafetyContext(yes=True), all_matches=True)

    assert result.ok is True
    assert first.terminated is True
    assert second.terminated is True
    assert result.safety.executed is True


def test_suspend_requires_confirmation_and_dry_run_is_safe():
    target = FakeProcess(pid=123, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([target]))

    denied = service.suspend_process(123, SafetyContext())
    preview = service.suspend_process(123, SafetyContext(dry_run=True))

    assert denied.ok is False
    assert denied.safety.reason == "confirmation_required"
    assert preview.ok is True
    assert target.suspended is False


def test_resume_can_execute_without_confirmation():
    target = FakeProcess(pid=123, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([target]))

    result = service.resume_process(123, SafetyContext())

    assert result.ok is True
    assert target.resumed is True
    assert result.safety.executed is True


def test_priority_requires_confirmation_and_applies_known_level():
    target = FakeProcess(pid=123, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([target]))

    denied = service.set_priority(123, "high", SafetyContext())
    assert target.priority is None

    allowed = service.set_priority(123, "high", SafetyContext(yes=True))

    assert denied.ok is False
    assert target.priority == 5
    assert allowed.ok is True
    assert allowed.safety.executed is True


def test_realtime_priority_returns_structured_failure():
    target = FakeProcess(pid=123, name="app.exe")
    service = ProcessService(psutil_module=make_psutil_module([target]))

    result = service.set_priority(123, "realtime", SafetyContext(yes=True))

    assert result.ok is False
    assert result.reason == "invalid_priority"
    assert target.priority is None


def test_access_denied_returns_safe_structured_failure():
    target = FakeProcess(pid=123, name="app.exe", deny_action=True)
    service = ProcessService(psutil_module=make_psutil_module([target]))

    result = service.kill_process(123, SafetyContext(yes=True))

    assert result.ok is False
    assert result.reason == "access_denied"
    assert "Access denied" in result.message


def test_missing_pid_returns_safe_structured_failure():
    service = ProcessService(psutil_module=make_psutil_module([]))

    result = service.kill_process(404, SafetyContext(yes=True))

    assert result.ok is False
    assert result.reason == "not_found"
    assert "No process found" in result.message
