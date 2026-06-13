from __future__ import annotations

from types import SimpleNamespace

import psutil
import pytest

from networkruler_core.process.service import ProcessService


class FakeProcess:
    def __init__(
        self,
        *,
        pid: int,
        name: str,
        username: str = "user",
        cpu: float = 0.0,
        mem: float = 0.0,
        status: str = "running",
        ppid: int = 0,
        cmdline: list[str] | None = None,
        deny_info: bool = False,
    ) -> None:
        self.pid = pid
        self._info = {
            "pid": pid,
            "name": name,
            "username": username,
            "cpu_percent": cpu,
            "memory_percent": mem,
            "status": status,
            "ppid": ppid,
        }
        self._cmdline = cmdline or [name]
        self._deny_info = deny_info

    @property
    def info(self) -> dict[str, object]:
        if self._deny_info:
            raise psutil.AccessDenied(pid=self.pid)
        return self._info

    def oneshot(self) -> "FakeProcess":
        return self

    def __enter__(self) -> "FakeProcess":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def name(self) -> str:
        return str(self._info["name"])

    def username(self) -> str:
        return str(self._info["username"])

    def cpu_percent(self, interval: float | None = None) -> float:
        return float(self._info["cpu_percent"])

    def memory_percent(self) -> float:
        return float(self._info["memory_percent"])

    def status(self) -> str:
        return str(self._info["status"])

    def ppid(self) -> int:
        return int(self._info["ppid"])

    def cmdline(self) -> list[str]:
        return self._cmdline


def make_psutil_module(processes: list[FakeProcess]) -> SimpleNamespace:
    by_pid = {process.pid: process for process in processes}

    def process_iter(attrs: list[str]) -> list[FakeProcess]:
        return processes

    def process(pid: int) -> FakeProcess:
        try:
            return by_pid[pid]
        except KeyError as error:
            raise psutil.NoSuchProcess(pid=pid) from error

    return SimpleNamespace(process_iter=process_iter, Process=process)


def test_list_processes_filters_and_sorts_by_memory():
    psutil_module = make_psutil_module(
        [
            FakeProcess(pid=1, name="System", mem=3.0),
            FakeProcess(pid=20, name="chrome.exe", mem=9.5),
            FakeProcess(pid=10, name="code.exe", mem=2.5),
        ]
    )
    service = ProcessService(psutil_module=psutil_module)

    processes = service.list_processes(filter_text="c", sort_by="mem")

    assert [process.pid for process in processes] == [20, 10]
    assert processes[0].name == "chrome.exe"
    assert processes[0].memory_percent == 9.5


def test_list_processes_skips_access_denied_processes():
    psutil_module = make_psutil_module(
        [
            FakeProcess(pid=1, name="ok.exe"),
            FakeProcess(pid=2, name="denied.exe", deny_info=True),
        ]
    )
    service = ProcessService(psutil_module=psutil_module)

    processes = service.list_processes()

    assert [process.pid for process in processes] == [1]


def test_get_process_info_returns_structured_details():
    service = ProcessService(
        psutil_module=make_psutil_module(
            [
                FakeProcess(
                    pid=42,
                    name="python.exe",
                    username="alice",
                    cpu=4.2,
                    mem=1.5,
                    status="sleeping",
                    ppid=7,
                    cmdline=["python", "-m", "app"],
                )
            ]
        )
    )

    info = service.get_process_info(42)

    assert info.pid == 42
    assert info.name == "python.exe"
    assert info.cmdline == ["python", "-m", "app"]


def test_get_process_info_raises_no_such_process_for_missing_pid():
    service = ProcessService(psutil_module=make_psutil_module([]))

    with pytest.raises(psutil.NoSuchProcess):
        service.get_process_info(404)


def test_process_tree_builds_parent_child_relationships():
    service = ProcessService(
        psutil_module=make_psutil_module(
            [
                FakeProcess(pid=1, name="root.exe", ppid=0),
                FakeProcess(pid=2, name="child.exe", ppid=1),
                FakeProcess(pid=3, name="other.exe", ppid=0),
            ]
        )
    )

    tree = service.process_tree()

    assert [node.process.pid for node in tree] == [1, 3]
    assert tree[0].children[0].process.pid == 2
