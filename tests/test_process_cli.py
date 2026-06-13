from __future__ import annotations

import json

from typer.testing import CliRunner

from networkruler_cli.app import app
from networkruler_core.process.models import ProcessInfo, ProcessTreeNode


def test_process_list_outputs_table(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.list_processes",
        lambda self, filter_text=None, sort_by="cpu": [
            ProcessInfo(pid=10, name="code.exe", cpu_percent=3.5, memory_percent=2.1)
        ],
    )

    result = CliRunner().invoke(app, ["process", "list"])

    assert result.exit_code == 0
    assert "Processes" in result.output
    assert "code.exe" in result.output


def test_process_list_outputs_json(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.list_processes",
        lambda self, filter_text=None, sort_by="cpu": [
            ProcessInfo(pid=10, name="code.exe", cpu_percent=3.5, memory_percent=2.1)
        ],
    )

    result = CliRunner().invoke(app, ["process", "list", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["pid"] == 10
    assert payload[0]["name"] == "code.exe"


def test_process_list_passes_filter_and_sort(monkeypatch):
    seen = {}

    def fake_list(self, filter_text=None, sort_by="cpu"):
        seen["filter_text"] = filter_text
        seen["sort_by"] = sort_by
        return []

    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.list_processes",
        fake_list,
    )

    result = CliRunner().invoke(
        app,
        ["process", "list", "--filter", "chrome", "--sort", "name"],
    )

    assert result.exit_code == 0
    assert seen == {"filter_text": "chrome", "sort_by": "name"}


def test_process_info_outputs_json(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.get_process_info",
        lambda self, pid: ProcessInfo(pid=99, name="python.exe", cmdline=["python"]),
    )

    result = CliRunner().invoke(app, ["process", "info", "99", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["pid"] == 99
    assert payload["cmdline"] == ["python"]


def test_process_info_rejects_invalid_pid():
    result = CliRunner().invoke(app, ["process", "info", "not-a-number"])

    assert result.exit_code != 0
    assert "Invalid value" in result.output


def test_process_tree_outputs_table(monkeypatch):
    monkeypatch.setattr(
        "networkruler_cli.commands.process.ProcessService.process_tree",
        lambda self: [
            ProcessTreeNode(
                process=ProcessInfo(pid=1, name="root.exe"),
                children=[
                    ProcessTreeNode(process=ProcessInfo(pid=2, name="child.exe"))
                ],
            )
        ],
    )

    result = CliRunner().invoke(app, ["process", "tree"])

    assert result.exit_code == 0
    assert "root.exe" in result.output
    assert "child.exe" in result.output
