from __future__ import annotations

import json
from types import SimpleNamespace

import psutil
from typer.testing import CliRunner

from networkruler_cli.app import app
from networkruler_core.monitor.models import BandwidthSample, ProcessSample
from networkruler_core.monitor.service import MonitorService


class FakePsutil:
    def __init__(self) -> None:
        self.net_calls = 0

    def net_io_counters(self, pernic: bool = False):
        self.net_calls += 1
        first = SimpleNamespace(bytes_sent=100, bytes_recv=200)
        second = SimpleNamespace(bytes_sent=250, bytes_recv=500)
        if pernic:
            return {"Ethernet": first if self.net_calls == 1 else second}
        return first if self.net_calls == 1 else second

    def Process(self, pid: int):
        return FakeProcess(pid)


class FakeProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.calls = 0

    def oneshot(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def name(self) -> str:
        return "python.exe"

    def cpu_percent(self, interval=None) -> float:
        return 12.5

    def memory_percent(self) -> float:
        return 3.25

    def status(self) -> str:
        return "running"


class ExitingPsutil:
    def Process(self, pid: int):
        raise psutil.NoSuchProcess(pid=pid)


def test_bandwidth_sample_generation_with_adapter():
    service = MonitorService(psutil_module=FakePsutil(), sleeper=lambda seconds: None)

    sample = service.sample_bandwidth(interval=1.0, adapter="Ethernet")

    assert sample.adapter == "Ethernet"
    assert sample.bytes_sent_per_sec == 150.0
    assert sample.bytes_recv_per_sec == 300.0
    assert sample.total_bytes_sent == 250
    assert sample.total_bytes_recv == 500


def test_process_sample_generation():
    service = MonitorService(psutil_module=FakePsutil(), sleeper=lambda seconds: None)

    sample = service.sample_process(123, interval=1.0)

    assert sample.pid == 123
    assert sample.name == "python.exe"
    assert sample.cpu_percent == 12.5
    assert sample.memory_percent == 3.25
    assert sample.alive is True


def test_process_exit_handling_is_structured():
    service = MonitorService(psutil_module=ExitingPsutil(), sleeper=lambda seconds: None)

    sample = service.sample_process(404, interval=1.0)

    assert sample.pid == 404
    assert sample.alive is False
    assert sample.message == "Process 404 is no longer running."


def test_monitor_jsonl_bandwidth_output(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.monitor.MonitorService.bandwidth_samples",
        lambda self, interval, adapter=None: iter(
            [
                BandwidthSample(
                    timestamp=1.0,
                    adapter=adapter,
                    bytes_sent_per_sec=10.0,
                    bytes_recv_per_sec=20.0,
                    total_bytes_sent=100,
                    total_bytes_recv=200,
                )
            ]
        ),
    )

    result = CliRunner().invoke(
        app,
        ["monitor", "bandwidth", "--adapter", "Ethernet", "--jsonl", "--samples", "1"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["adapter"] == "Ethernet"
    assert payload["bytes_recv_per_sec"] == 20.0


def test_monitor_jsonl_process_output(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.monitor.MonitorService.process_samples",
        lambda self, pid, interval: iter(
            [
                ProcessSample(
                    timestamp=1.0,
                    pid=pid,
                    name="python.exe",
                    cpu_percent=12.5,
                    memory_percent=3.25,
                    status="running",
                    alive=True,
                )
            ]
        ),
    )

    result = CliRunner().invoke(
        app,
        ["monitor", "process", "123", "--jsonl", "--samples", "1"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["pid"] == 123
    assert payload["cpu_percent"] == 12.5


def test_monitor_interval_validation():
    result = CliRunner().invoke(app, ["monitor", "bandwidth", "--interval", "0"])

    assert result.exit_code != 0
    assert "Interval must be greater than 0" in result.output


def test_monitor_ctrl_c_exits_cleanly(monkeypatch):
    def raise_keyboard_interrupt(self, interval, adapter=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "networkruler_cli.commands.monitor.MonitorService.bandwidth_samples",
        raise_keyboard_interrupt,
    )

    result = CliRunner().invoke(app, ["monitor", "bandwidth", "--jsonl"])

    assert result.exit_code == 0
    assert "Monitoring stopped." in result.output
