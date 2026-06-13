from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from networkruler_cli.commands import monitor as monitor_commands
from networkruler_cli.commands import network as network_commands
from networkruler_cli.commands import process as process_commands
from networkruler_core.config.paths import get_user_paths
from networkruler_core.process.service import ProcessSortKey


console = Console()


def register_fast_commands(root_app: typer.Typer) -> None:
    """Attach human-first shortcut commands to the root Typer app."""

    @root_app.command("dash")
    def dashboard() -> None:
        """Open the quick Network Ruler launcher."""
        render_launcher()

    @root_app.command("help")
    def compact_help() -> None:
        """Show the compact command map."""
        render_launcher()

    @root_app.command("ps")
    def ps(
        query: Annotated[
            str | None,
            typer.Argument(help="Optional process name or PID filter."),
        ] = None,
        sort_by: Annotated[
            ProcessSortKey,
            typer.Option("--sort", help="Sort by cpu, mem, name, or pid."),
        ] = "cpu",
        limit: Annotated[
            int | None,
            typer.Option("--limit", "-n", min=1, help="Maximum rows to show."),
        ] = None,
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit JSON."),
        ] = False,
    ) -> None:
        """List processes fast."""
        process_commands.render_process_list(
            filter_text=query,
            sort_by=sort_by,
            json_output=json_output,
            limit=limit,
            title="ps",
        )

    @root_app.command("top")
    def top(
        limit: Annotated[
            int,
            typer.Option("--limit", "-n", min=1, help="Maximum rows to show."),
        ] = 20,
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit JSON."),
        ] = False,
    ) -> None:
        """Show busiest processes."""
        process_commands.render_process_list(
            sort_by="cpu",
            json_output=json_output,
            limit=limit,
            title="top",
        )

    @root_app.command("stat")
    def stat(
        pid: Annotated[int, typer.Argument(help="Process ID.")],
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit JSON."),
        ] = False,
    ) -> None:
        """Show one process."""
        process_commands.render_process_info(pid=pid, json_output=json_output)

    @root_app.command("tree")
    def tree(
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit JSON."),
        ] = False,
    ) -> None:
        """Show process tree."""
        process_commands.render_process_tree(json_output=json_output)

    @root_app.command("kill")
    def kill(
        target: Annotated[str, typer.Argument(help="PID or exact process name.")],
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Preview only."),
        ] = False,
        yes: Annotated[
            bool,
            typer.Option("--yes", help="Confirm the dangerous action."),
        ] = False,
        force: Annotated[
            bool,
            typer.Option("--force", help="Force-kill a PID target."),
        ] = False,
        all_matches: Annotated[
            bool,
            typer.Option("--all", help="Apply to every process matching a name."),
        ] = False,
    ) -> None:
        """Kill by PID, or by exact name with --all when needed."""
        process_commands.render_kill_target(
            target=target,
            dry_run=dry_run,
            yes=yes,
            force=force,
            all_matches=all_matches,
        )

    @root_app.command("if")
    def interfaces(
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit JSON."),
        ] = False,
    ) -> None:
        """Show network interfaces."""
        network_commands.interfaces(json_output=json_output)

    @root_app.command("net")
    def net(
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit JSON."),
        ] = False,
    ) -> None:
        """Show a quick network summary."""
        network_commands.render_network_summary(json_output=json_output)

    @root_app.command("wifi")
    def wifi(
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit JSON."),
        ] = False,
    ) -> None:
        """Show Wi-Fi signal."""
        network_commands.wifi_signal(json_output=json_output)

    @root_app.command("ports")
    def ports(
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit JSON."),
        ] = False,
    ) -> None:
        """Show active connections."""
        network_commands.connections(json_output=json_output)

    @root_app.command("bw")
    def bandwidth(
        interval: Annotated[
            float,
            typer.Option("--interval", "-i", help="Sampling interval in seconds."),
        ] = 1.0,
        adapter: Annotated[
            str | None,
            typer.Option("--adapter", "-a", help="Network adapter name."),
        ] = None,
        jsonl: Annotated[
            bool,
            typer.Option("--jsonl", help="Emit one JSON object per sample."),
        ] = False,
        samples: Annotated[
            int | None,
            typer.Option("--samples", help="Finite sample count."),
        ] = None,
    ) -> None:
        """Watch bandwidth."""
        monitor_commands.render_bandwidth(
            interval=interval,
            adapter=adapter,
            jsonl=jsonl,
            samples=samples,
        )

    @root_app.command("watch")
    def watch(
        pid: Annotated[
            int | None,
            typer.Argument(help="Optional process ID. Omit for bandwidth."),
        ] = None,
        interval: Annotated[
            float,
            typer.Option("--interval", "-i", help="Sampling interval in seconds."),
        ] = 1.0,
        adapter: Annotated[
            str | None,
            typer.Option("--adapter", "-a", help="Bandwidth adapter name."),
        ] = None,
        jsonl: Annotated[
            bool,
            typer.Option("--jsonl", help="Emit one JSON object per sample."),
        ] = False,
        samples: Annotated[
            int | None,
            typer.Option("--samples", help="Finite sample count."),
        ] = None,
    ) -> None:
        """Watch bandwidth, or one process when PID is given."""
        if pid is None:
            monitor_commands.render_bandwidth(
                interval=interval,
                adapter=adapter,
                jsonl=jsonl,
                samples=samples,
            )
            return

        monitor_commands.render_process_monitor(
            pid=pid,
            interval=interval,
            jsonl=jsonl,
            samples=samples,
        )

    @root_app.command("dns")
    def dns(
        action: Annotated[
            str | None,
            typer.Argument(help="flush or register."),
        ] = None,
        dry_run: Annotated[
            bool,
            typer.Option("--dry-run", help="Preview only."),
        ] = False,
        yes: Annotated[
            bool,
            typer.Option("--yes", help="Confirm the write action."),
        ] = False,
    ) -> None:
        """DNS shortcuts."""
        if action is None:
            _render_dns_launcher()
            return

        normalized = action.lower()
        if normalized == "flush":
            network_commands.dns_flush(dry_run=dry_run, yes=yes)
            return
        if normalized == "register":
            network_commands.dns_register(dry_run=dry_run, yes=yes)
            return

        raise typer.BadParameter("Use flush or register.")

    @root_app.command("paths")
    def paths() -> None:
        """Show config/cache/log locations."""
        user_paths = get_user_paths()
        table = Table(title="paths")
        table.add_column("Name")
        table.add_column("Path")
        table.add_row("config", str(user_paths.config_dir))
        table.add_row("cache", str(user_paths.cache_dir))
        table.add_row("logs", str(user_paths.log_dir))
        console.print(table)


def render_launcher() -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column("Command", style="bold cyan", no_wrap=True)
    table.add_column("Use")
    table.add_row("nr ps [text]", "find processes")
    table.add_row("nr top", "busiest processes")
    table.add_row("nr bw", "live bandwidth")
    table.add_row("nr if", "network interfaces")
    table.add_row("nr wifi", "Wi-Fi signal")
    table.add_row("nr ports", "active connections")
    table.add_row("nr kill <pid|name>", "guarded process kill")
    table.add_row("nr dns flush", "guarded DNS flush")

    advanced = Table.grid(padding=(0, 2))
    advanced.add_column("Command", style="bold")
    advanced.add_column("Use")
    advanced.add_row("nr process ...", "full process tools")
    advanced.add_row("nr network ...", "full network tools")
    advanced.add_row("nr monitor ...", "full monitors")
    advanced.add_row("nr profile ...", "structured profiles")
    advanced.add_row("nr alias ...", "saved shortcuts")

    console.print(
        Panel.fit(
            table,
            title="Network Ruler",
            subtitle="Fast lane",
            border_style="cyan",
        )
    )
    console.print(Panel.fit(advanced, title="Power tools", border_style="dim"))


def _render_dns_launcher() -> None:
    table = Table(title="dns")
    table.add_column("Command", style="bold cyan")
    table.add_column("Use")
    table.add_row("nr dns flush --dry-run", "Preview DNS cache flush")
    table.add_row("nr dns flush --yes", "Flush DNS cache")
    table.add_row("nr dns register --dry-run", "Preview DNS registration")
    console.print(table)
