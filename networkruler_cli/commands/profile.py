from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from networkruler_core.profiles.models import (
    ProfileAction,
    ProfileApplyResult,
    ProfileValidationResult,
)
from networkruler_core.profiles.service import ProfileService
from networkruler_core.safety import SafetyContext


console = Console()
app = typer.Typer(
    help="Manage structured v2 profiles.",
    invoke_without_command=True,
    no_args_is_help=False,
)


@app.callback(invoke_without_command=True)
def profile_root(ctx: typer.Context) -> None:
    """List profiles when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        list_profiles()
        raise typer.Exit()


@app.command("list")
def list_profiles() -> None:
    """List profiles."""
    table = Table(title="Profiles")
    table.add_column("Name")
    for name in ProfileService().list_profiles():
        table.add_row(name)
    console.print(table)


@app.command("show")
def show_profile(name: Annotated[str, typer.Argument(help="Profile name.")]) -> None:
    """Show raw structured profile JSON."""
    payload = ProfileService().show_profile(name)
    if payload is None:
        console.print(f"Profile '{name}' not found or invalid JSON.")
        raise typer.Exit(code=1)
    console.print(json.dumps(payload, indent=2))


@app.command("validate")
def validate_profile(name: Annotated[str, typer.Argument(help="Profile name.")]) -> None:
    """Validate a profile without applying it."""
    result = ProfileService().validate_profile(name)
    _render_validation(result)
    if not result.ok:
        raise typer.Exit(code=1)


@app.command("apply")
def apply_profile(
    name: Annotated[str, typer.Argument(help="Profile name.")],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show the full execution plan."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Confirm profile execution."),
    ] = False,
) -> None:
    """Apply a validated structured profile."""
    result = ProfileService().apply_profile(name, SafetyContext(dry_run=dry_run, yes=yes))
    _render_apply_result(result)
    if not result.ok:
        raise typer.Exit(code=1)


@app.command("create")
def create_profile(name: Annotated[str, typer.Argument(help="Profile name.")]) -> None:
    """Create an empty v2 profile."""
    result = ProfileService().create_profile(name)
    _render_validation(result)
    if not result.ok:
        raise typer.Exit(code=1)


@app.command("delete")
def delete_profile(
    name: Annotated[str, typer.Argument(help="Profile name.")],
    yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion.")] = False,
) -> None:
    """Delete a profile."""
    result = ProfileService().delete_profile(name, yes=yes)
    _render_validation(result)
    if not result.ok:
        raise typer.Exit(code=1)


def _render_validation(result: ProfileValidationResult) -> None:
    status = "OK" if result.ok else "INVALID"
    console.print(f"{status} profile {result.name}: {result.reason}")
    if result.errors:
        for error in result.errors:
            console.print(f"- {error}")
    if result.actions:
        _render_plan(result.actions)


def _render_apply_result(result: ProfileApplyResult) -> None:
    console.print(result.message)
    if result.errors:
        for error in result.errors:
            console.print(f"- {error}")
    _render_plan(result.plan)


def _render_plan(actions: list[ProfileAction]) -> None:
    table = Table(title="Execution Plan")
    table.add_column("#", justify="right")
    table.add_column("Type")
    table.add_column("Risk")
    table.add_column("Admin")
    table.add_column("Params")
    for index, action in enumerate(actions, start=1):
        table.add_row(
            str(index),
            action.type,
            action.risk_level.value,
            "yes" if action.requires_admin else "no",
            json.dumps(action.params, sort_keys=True),
        )
    console.print(table)
