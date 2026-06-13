from __future__ import annotations

import json
from typing import Annotated

import psutil
import typer
from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from networkruler_core.process.models import (
    ProcessActionResult,
    ProcessInfo,
    ProcessTreeNode,
)
from networkruler_core.process.service import (
    ProcessPriorityLevel,
    ProcessService,
    ProcessSortKey,
)
from networkruler_core.safety import SafetyContext


console = Console()
app = typer.Typer(
    help="Read-only process inspection tools.",
    invoke_without_command=True,
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def process_root(ctx: typer.Context) -> None:
    """Show a useful process view when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        render_process_list(limit=20, title="processes")
        raise typer.Exit()


@app.command("list")
def list_processes(
    filter_text: Annotated[
        str | None,
        typer.Option("--filter", "-f", help="Filter by process name or PID text."),
    ] = None,
    sort_by: Annotated[
        ProcessSortKey,
        typer.Option("--sort", help="Sort by cpu, mem, name, or pid."),
    ] = "cpu",
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit process list as JSON."),
    ] = False,
) -> None:
    """List running processes."""
    render_process_list(
        filter_text=filter_text,
        sort_by=sort_by,
        json_output=json_output,
    )


def render_process_list(
    *,
    filter_text: str | None = None,
    sort_by: ProcessSortKey = "cpu",
    json_output: bool = False,
    limit: int | None = None,
    title: str = "Processes",
) -> None:
    processes = ProcessService().list_processes(filter_text=filter_text, sort_by=sort_by)
    if limit is not None:
        processes = processes[:limit]

    if json_output:
        console.print(json.dumps([process.to_dict() for process in processes], indent=2))
        return

    table = Table(title=title)
    table.add_column("PID", justify="right")
    table.add_column("Name")
    table.add_column("CPU %", justify="right")
    table.add_column("MEM %", justify="right")
    table.add_column("Status")
    table.add_column("User")
    for process in processes:
        table.add_row(
            str(process.pid),
            process.name,
            f"{process.cpu_percent:.1f}",
            f"{process.memory_percent:.1f}",
            process.status or "",
            process.username or "",
        )
    console.print(table)


@app.command("info")
def process_info(
    pid: Annotated[int, typer.Argument(help="Process ID to inspect.")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit process details as JSON."),
    ] = False,
) -> None:
    """Show details for one process."""
    render_process_info(pid=pid, json_output=json_output)


def render_process_info(*, pid: int, json_output: bool = False) -> None:
    try:
        info = ProcessService().get_process_info(pid)
    except psutil.NoSuchProcess:
        raise typer.BadParameter(f"No process found with PID {pid}.") from None
    except psutil.AccessDenied:
        raise typer.BadParameter(f"Access denied for PID {pid}.") from None

    if json_output:
        console.print(json.dumps(info.to_dict(), indent=2))
        return

    table = Table(title=f"Process {pid}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("PID", str(info.pid))
    table.add_row("Name", info.name)
    table.add_row("User", info.username or "")
    table.add_row("CPU %", f"{info.cpu_percent:.1f}")
    table.add_row("MEM %", f"{info.memory_percent:.1f}")
    table.add_row("Status", info.status or "")
    table.add_row("Parent PID", str(info.ppid or ""))
    table.add_row("Command", " ".join(info.cmdline))
    console.print(table)


@app.command("kill")
def kill_process(
    pid: Annotated[int, typer.Argument(help="Process ID to terminate.")],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview the target without mutating it."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Confirm the dangerous action."),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Force-kill instead of graceful terminate."),
    ] = False,
) -> None:
    """Terminate a process by PID."""
    render_kill_pid(pid=pid, dry_run=dry_run, yes=yes, force=force)


def render_kill_pid(
    *,
    pid: int,
    dry_run: bool = False,
    yes: bool = False,
    force: bool = False,
) -> None:
    result = ProcessService().kill_process(
        pid,
        SafetyContext(dry_run=dry_run, yes=yes, force=force),
    )
    _render_action_result(result)


@app.command("kill-name")
def kill_name(
    name: Annotated[str, typer.Argument(help="Exact process name to terminate.")],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview matched processes without mutation."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Confirm the dangerous action."),
    ] = False,
    all_matches: Annotated[
        bool,
        typer.Option("--all", help="Apply to every matching process."),
    ] = False,
) -> None:
    """Terminate processes by exact name."""
    render_kill_name(
        name=name,
        dry_run=dry_run,
        yes=yes,
        all_matches=all_matches,
    )


def render_kill_name(
    *,
    name: str,
    dry_run: bool = False,
    yes: bool = False,
    all_matches: bool = False,
) -> None:
    result = ProcessService().kill_by_name(
        name,
        SafetyContext(dry_run=dry_run, yes=yes),
        all_matches=all_matches,
    )
    _render_action_result(result)


def render_kill_target(
    *,
    target: str,
    dry_run: bool = False,
    yes: bool = False,
    force: bool = False,
    all_matches: bool = False,
) -> None:
    if target.isdecimal():
        render_kill_pid(
            pid=int(target),
            dry_run=dry_run,
            yes=yes,
            force=force,
        )
        return

    render_kill_name(
        name=target,
        dry_run=dry_run,
        yes=yes,
        all_matches=all_matches,
    )


@app.command("suspend")
def suspend_process(
    pid: Annotated[int, typer.Argument(help="Process ID to suspend.")],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview the target without mutating it."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Confirm the dangerous action."),
    ] = False,
) -> None:
    """Suspend a process by PID."""
    result = ProcessService().suspend_process(
        pid,
        SafetyContext(dry_run=dry_run, yes=yes),
    )
    _render_action_result(result)


@app.command("resume")
def resume_process(
    pid: Annotated[int, typer.Argument(help="Process ID to resume.")],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview the target without mutating it."),
    ] = False,
) -> None:
    """Resume a suspended process by PID."""
    result = ProcessService().resume_process(pid, SafetyContext(dry_run=dry_run))
    _render_action_result(result)


@app.command("priority")
def set_priority(
    pid: Annotated[int, typer.Argument(help="Process ID to update.")],
    level: Annotated[
        ProcessPriorityLevel,
        typer.Argument(help="Priority level: low, below, normal, above, high."),
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview the target without mutating it."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Confirm the write action."),
    ] = False,
) -> None:
    """Set process priority."""
    result = ProcessService().set_priority(
        pid,
        level,
        SafetyContext(dry_run=dry_run, yes=yes),
    )
    _render_action_result(result)


@app.command("tree")
def process_tree(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit process tree as JSON."),
    ] = False,
) -> None:
    """Show a parent-child process tree."""
    render_process_tree(json_output=json_output)


def render_process_tree(*, json_output: bool = False) -> None:
    tree = ProcessService().process_tree()

    if json_output:
        console.print(json.dumps([node.to_dict() for node in tree], indent=2))
        return

    root = Tree("Processes")
    for node in tree:
        _add_tree_node(root, node)
    console.print(root)


def _add_tree_node(parent, node: ProcessTreeNode) -> None:
    branch = parent.add(_format_tree_label(node.process))
    for child in node.children:
        _add_tree_node(branch, child)


def _format_tree_label(process: ProcessInfo) -> str:
    return f"{process.pid} {process.name}"


def _render_action_result(result: ProcessActionResult) -> None:
    status = "DRY-RUN" if result.safety.dry_run else "OK" if result.ok else "BLOCKED"
    console.print(f"[bold]{status}[/] {result.action}: {result.message}")

    if result.targets:
        table = Table(title="Target Preview")
        table.add_column("PID", justify="right")
        table.add_column("Name")
        table.add_column("Status")
        table.add_column("User")
        for target in result.targets:
            table.add_row(
                str(target.pid),
                target.name,
                target.status or "",
                target.username or "",
            )
        console.print(table)

    if not result.ok:
        raise typer.Exit(code=1)
