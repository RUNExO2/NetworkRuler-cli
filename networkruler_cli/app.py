from __future__ import annotations

import logging
import platform
import sys
from typing import Annotated

import psutil
import typer
from rich.console import Console
from rich.table import Table
from typer.main import get_command

from networkruler_core import __version__
from networkruler_core.aliases.service import AliasService
from networkruler_core.config.paths import get_user_paths
from networkruler_core.logging_config import configure_logging
from networkruler_cli.commands.alias import app as alias_app
from networkruler_cli.commands.fast import register_fast_commands, render_launcher
from networkruler_cli.commands.monitor import app as monitor_app
from networkruler_cli.commands.network import app as network_app
from networkruler_cli.commands.process import app as process_app
from networkruler_cli.commands.profile import app as profile_app


console = Console()
app = typer.Typer(
    name="nr",
    help="Network Ruler v2. Fast commands at the root; structured tools underneath.",
    invoke_without_command=True,
    no_args_is_help=False,
)
config_app = typer.Typer(help="Inspect NetworkRuler configuration.")
app.add_typer(alias_app, name="alias")
app.add_typer(config_app, name="config")
app.add_typer(monitor_app, name="monitor")
app.add_typer(network_app, name="network")
app.add_typer(process_app, name="process")
app.add_typer(profile_app, name="profile")
register_fast_commands(app)


@app.callback(invoke_without_command=True)
def root(ctx: typer.Context) -> None:
    """Network Ruler fast launcher."""
    if ctx.invoked_subcommand is None:
        render_launcher()
        raise typer.Exit()


@app.command()
def version() -> None:
    """Show the NetworkRuler version."""
    console.print(__version__)


@app.command()
def doctor() -> None:
    """Run read-only environment checks."""
    paths = get_user_paths()
    table = Table(title="NetworkRuler doctor")
    table.add_column("Check")
    table.add_column("Value")
    table.add_row("Version", __version__)
    table.add_row("Platform", platform.platform())
    table.add_row("Python", platform.python_version())
    table.add_row("psutil", psutil.__version__)
    table.add_row("Runtime paths", "outside repository")
    table.add_row("Config dir", str(paths.config_dir))
    table.add_row("Cache dir", str(paths.cache_dir))
    table.add_row("Log dir", str(paths.log_dir))
    console.print(table)


@config_app.command("paths")
def config_paths(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit paths as JSON."),
    ] = False,
) -> None:
    """Show user-scoped config, cache, data, and log paths."""
    paths = get_user_paths()
    data = {
        "config_dir": str(paths.config_dir),
        "config_file": str(paths.config_file),
        "cache_dir": str(paths.cache_dir),
        "data_dir": str(paths.data_dir),
        "log_dir": str(paths.log_dir),
        "log_file": str(paths.log_file),
    }

    if json_output:
        console.print_json(data=data)
        return

    table = Table(title="NetworkRuler paths")
    table.add_column("Name")
    table.add_column("Path")
    for name, path in data.items():
        table.add_row(name, path)
    console.print(table)


def known_command_names() -> set[str]:
    """Command and group names Typer/Click recognises on the root app.

    Derived from the live app so the alias resolver can never shadow a real
    command, and so the set stays correct as commands are added or removed.
    """
    command = get_command(app)
    return set(getattr(command, "commands", {}).keys())


def _expand_leading_alias() -> None:
    """Rewrite argv when the first token is a saved alias rather than a command."""
    if len(sys.argv) <= 1:
        return

    first_arg = sys.argv[1]
    if first_arg.startswith("-") or first_arg in known_command_names():
        return

    resolution = AliasService().resolve_alias(first_arg)
    if resolution.ok and resolution.command:
        sys.argv = [sys.argv[0], *resolution.command, *sys.argv[2:]]


def main() -> None:
    configure_logging()
    logging.getLogger("networkruler.cli").info("Network Ruler CLI started")
    _expand_leading_alias()
    app()
