from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from typer.main import get_command

from networkruler_core.aliases.service import AliasResult, AliasService


console = Console()
app = typer.Typer(
    help="Manage command aliases.",
    invoke_without_command=True,
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def alias_root(ctx: typer.Context) -> None:
    """List aliases when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        list_aliases()
        raise typer.Exit()


@app.command("list")
def list_aliases() -> None:
    """List configured aliases."""
    aliases = AliasService().list_aliases()
    table = Table(title="Aliases")
    table.add_column("Name")
    table.add_column("Command")
    for name, command in aliases.items():
        table.add_row(name, " ".join(command))
    console.print(table)


@app.command("set")
def set_alias(
    name: Annotated[str, typer.Argument(help="Alias name.")],
    command: Annotated[list[str], typer.Argument(help="Command tokens.")],
) -> None:
    """Set an alias shortcut."""
    _render_result(AliasService().set_alias(name, command))


@app.command("create")
def create_alias(
    name: Annotated[str, typer.Argument(help="Alias name.")],
    command: Annotated[list[str], typer.Argument(help="Command tokens.")],
) -> None:
    """Create an alias shortcut."""
    _render_result(AliasService().set_alias(name, command))


@app.command("remove")
def remove_alias(name: Annotated[str, typer.Argument(help="Alias name.")]) -> None:
    """Remove an alias."""
    _render_result(AliasService().remove_alias(name))


@app.command("resolve")
def resolve_alias(name: Annotated[str, typer.Argument(help="Alias name.")]) -> None:
    """Resolve an alias without executing it."""
    result = AliasService().resolve_alias(name)
    if result.command:
        console.print(" ".join(result.command))
    else:
        _render_result(result)


@app.command(
    "execute",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def execute_alias(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Alias name.")],
) -> None:
    """Execute an alias through the normal CLI command tree."""
    result = AliasService().resolve_alias(name)
    if not result.ok or not result.command:
        _render_result(result)
        return

    from networkruler_cli.app import app as root_app

    command = [*result.command, *ctx.args]
    click_command = get_command(root_app)
    click_command.main(args=command, prog_name="nr", standalone_mode=False)


def _render_result(result: AliasResult) -> None:
    console.print(result.message)
    if not result.ok:
        raise typer.Exit(code=1)
