from __future__ import annotations

import json
from typing import Annotated, Iterable

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from networkruler_core.monitor.models import BandwidthSample, ProcessSample
from networkruler_core.monitor.service import MonitorService


console = Console()
app = typer.Typer(
    help="Live monitoring tools.",
    invoke_without_command=True,
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def monitor_root(ctx: typer.Context) -> None:
    """Show monitor shortcuts when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        table = Table.grid(padding=(0, 2))
        table.add_column("Command", style="bold cyan")
        table.add_column("Use")
        table.add_row("nr bw", "live bandwidth")
        table.add_row("nr watch", "live bandwidth")
        table.add_row("nr watch <pid>", "watch one process")
        table.add_row("nr monitor bandwidth", "structured bandwidth monitor")
        table.add_row("nr monitor process <pid>", "structured process monitor")
        console.print(Panel.fit(table, title="monitor", border_style="cyan"))
        raise typer.Exit()


@app.command("bandwidth")
def bandwidth(
    interval: Annotated[
        float,
        typer.Option("--interval", help="Sampling interval in seconds."),
    ] = 1.0,
    adapter: Annotated[
        str | None,
        typer.Option("--adapter", help="Network adapter name."),
    ] = None,
    jsonl: Annotated[
        bool,
        typer.Option("--jsonl", help="Emit one JSON object per sample."),
    ] = False,
    samples: Annotated[
        int | None,
        typer.Option("--samples", help="Internal finite sample count.", hidden=True),
    ] = None,
) -> None:
    """Monitor bandwidth rates."""
    render_bandwidth(
        interval=interval,
        adapter=adapter,
        jsonl=jsonl,
        samples=samples,
    )


def render_bandwidth(
    *,
    interval: float = 1.0,
    adapter: str | None = None,
    jsonl: bool = False,
    samples: int | None = None,
) -> None:
    _validate_interval_cli(interval)
    try:
        stream = MonitorService().bandwidth_samples(interval=interval, adapter=adapter)
        if jsonl:
            _emit_jsonl(stream, samples)
        else:
            _render_bandwidth_live(stream, samples)
    except KeyboardInterrupt:
        console.print("Monitoring stopped.")
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None


@app.command("process")
def process(
    pid: Annotated[int, typer.Argument(help="Process ID to monitor.")],
    interval: Annotated[
        float,
        typer.Option("--interval", help="Sampling interval in seconds."),
    ] = 1.0,
    jsonl: Annotated[
        bool,
        typer.Option("--jsonl", help="Emit one JSON object per sample."),
    ] = False,
    samples: Annotated[
        int | None,
        typer.Option("--samples", help="Internal finite sample count.", hidden=True),
    ] = None,
) -> None:
    """Monitor one process."""
    render_process_monitor(
        pid=pid,
        interval=interval,
        jsonl=jsonl,
        samples=samples,
    )


def render_process_monitor(
    *,
    pid: int,
    interval: float = 1.0,
    jsonl: bool = False,
    samples: int | None = None,
) -> None:
    _validate_interval_cli(interval)
    try:
        stream = MonitorService().process_samples(pid=pid, interval=interval)
        if jsonl:
            _emit_jsonl(stream, samples)
        else:
            _render_process_live(stream, samples)
    except KeyboardInterrupt:
        console.print("Monitoring stopped.")


def _emit_jsonl(stream: Iterable[BandwidthSample | ProcessSample], samples: int | None) -> None:
    for index, sample in enumerate(stream, start=1):
        console.print(json.dumps(sample.to_dict()))
        if samples is not None and index >= samples:
            return


def _render_bandwidth_live(
    stream: Iterable[BandwidthSample],
    samples: int | None,
) -> None:
    with Live(refresh_per_second=4, console=console) as live:
        for index, sample in enumerate(stream, start=1):
            live.update(_bandwidth_table(sample))
            if samples is not None and index >= samples:
                return


def _render_process_live(stream: Iterable[ProcessSample], samples: int | None) -> None:
    with Live(refresh_per_second=4, console=console) as live:
        for index, sample in enumerate(stream, start=1):
            live.update(_process_table(sample))
            if not sample.alive:
                return
            if samples is not None and index >= samples:
                return


def _bandwidth_table(sample: BandwidthSample) -> Table:
    table = Table(title="Bandwidth Monitor")
    table.add_column("Adapter")
    table.add_column("Sent/s", justify="right")
    table.add_column("Recv/s", justify="right")
    table.add_column("Total Sent", justify="right")
    table.add_column("Total Recv", justify="right")
    table.add_row(
        sample.adapter or "all",
        f"{sample.bytes_sent_per_sec:.0f} B/s",
        f"{sample.bytes_recv_per_sec:.0f} B/s",
        str(sample.total_bytes_sent),
        str(sample.total_bytes_recv),
    )
    return table


def _process_table(sample: ProcessSample) -> Table:
    table = Table(title=f"Process Monitor: {sample.pid}")
    table.add_column("Name")
    table.add_column("CPU %", justify="right")
    table.add_column("MEM %", justify="right")
    table.add_column("Status")
    table.add_column("Message")
    table.add_row(
        sample.name or "",
        f"{sample.cpu_percent:.1f}",
        f"{sample.memory_percent:.1f}",
        sample.status or "",
        sample.message or "",
    )
    return table


def _validate_interval_cli(interval: float) -> None:
    if interval <= 0:
        raise typer.BadParameter("Interval must be greater than 0.")
