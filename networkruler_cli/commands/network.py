from __future__ import annotations

import json
from collections.abc import Callable
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from networkruler_core.exceptions import UnsupportedPlatformError
from networkruler_core.network.models import (
    FirewallStatus,
    InterfaceInfo,
    IpConfig,
    NetworkActionResult,
    NetworkConnection,
    ProxyStatus,
    WifiSignal,
)
from networkruler_core.network.service import NetworkService
from networkruler_core.safety import SafetyContext


console = Console()
app = typer.Typer(
    help="Read-only network inspection tools.",
    invoke_without_command=True,
    no_args_is_help=False,
)
dns_app = typer.Typer(help="DNS actions.")
ip_app = typer.Typer(help="Inspect IP configuration.")
proxy_app = typer.Typer(help="Inspect proxy configuration.")
firewall_app = typer.Typer(help="Inspect firewall configuration.")
wifi_app = typer.Typer(help="Inspect Wi-Fi state.")
winsock_app = typer.Typer(help="Winsock actions.")
tcp_app = typer.Typer(help="TCP/IP actions.")
app.add_typer(dns_app, name="dns")
app.add_typer(ip_app, name="ip")
app.add_typer(proxy_app, name="proxy")
app.add_typer(firewall_app, name="firewall")
app.add_typer(wifi_app, name="wifi")
app.add_typer(winsock_app, name="winsock")
app.add_typer(tcp_app, name="tcp")


@app.callback(invoke_without_command=True)
def network_root(ctx: typer.Context) -> None:
    """Show a useful network view when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        render_network_summary()
        raise typer.Exit()


@app.command("interfaces")
def interfaces(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show network interfaces."""
    _run_read_only(lambda: _render_interfaces(NetworkService().list_interfaces(), json_output))


def render_network_summary(json_output: bool = False) -> None:
    """Render a compact read-only network overview for the fast layer."""
    def action() -> None:
        service = NetworkService()
        data = {
            "interfaces": [item.to_dict() for item in service.list_interfaces()],
            "wifi": service.wifi_signal().to_dict(),
            "proxy": service.show_proxy().to_dict(),
        }
        if json_output:
            _print_json(data)
            return

        table = Table(title="Network")
        table.add_column("Area")
        table.add_column("Summary")
        connected = [
            item["name"]
            for item in data["interfaces"]
            if str(item.get("state", "")).lower() in {"up", "connected"}
        ]
        table.add_row("Interfaces", ", ".join(connected) or "none connected")
        wifi = data["wifi"]
        signal = wifi.get("signal_percent")
        wifi_summary = wifi.get("ssid") or "not connected"
        if signal is not None:
            wifi_summary = f"{wifi_summary} ({signal}%)"
        table.add_row("Wi-Fi", wifi_summary)
        proxy = data["proxy"]
        table.add_row("Proxy", _format_optional_bool(proxy.get("enabled")))
        console.print(table)

    _run_read_only(action)


@ip_app.command("show")
def ip_show(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show IP configuration."""
    _run_read_only(lambda: _render_raw(NetworkService().show_ip_config(), json_output))


@proxy_app.command("show")
def proxy_show(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show WinHTTP proxy configuration."""
    _run_read_only(lambda: _render_proxy(NetworkService().show_proxy(), json_output))


@firewall_app.command("show")
def firewall_show(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show firewall profiles."""
    _run_read_only(lambda: _render_firewall(NetworkService().show_firewall(), json_output))


@wifi_app.command("signal")
def wifi_signal(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show current Wi-Fi signal details."""
    _run_read_only(lambda: _render_wifi(NetworkService().wifi_signal(), json_output))


@app.command("connections")
def connections(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show active network connections."""
    _run_read_only(
        lambda: _render_connections(NetworkService().list_connections(), json_output)
    )


@dns_app.command("flush")
def dns_flush(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Flush the DNS resolver cache."""
    _run_write(lambda: NetworkService().flush_dns(SafetyContext(dry_run=dry_run, yes=yes)))


@dns_app.command("register")
def dns_register(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Register DNS records."""
    _run_write(
        lambda: NetworkService().register_dns(SafetyContext(dry_run=dry_run, yes=yes))
    )


@ip_app.command("release")
def ip_release(
    adapter: Annotated[
        str | None,
        typer.Option("--adapter", help="Adapter name to release."),
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Release an IP address."""
    _run_write(
        lambda: NetworkService().release_ip(
            SafetyContext(dry_run=dry_run, yes=yes),
            adapter=adapter,
        )
    )


@ip_app.command("renew")
def ip_renew(
    adapter: Annotated[
        str | None,
        typer.Option("--adapter", help="Adapter name to renew."),
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Renew an IP address."""
    _run_write(
        lambda: NetworkService().renew_ip(
            SafetyContext(dry_run=dry_run, yes=yes),
            adapter=adapter,
        )
    )


@proxy_app.command("reset")
def proxy_reset(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Reset WinHTTP proxy settings."""
    _run_write(
        lambda: NetworkService().reset_proxy(SafetyContext(dry_run=dry_run, yes=yes))
    )


@firewall_app.command("enable")
def firewall_enable(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Enable Windows Firewall for all profiles."""
    _run_write(
        lambda: NetworkService().set_firewall_enabled(
            True,
            SafetyContext(dry_run=dry_run, yes=yes),
        )
    )


@firewall_app.command("disable")
def firewall_disable(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Disable Windows Firewall for all profiles."""
    _run_write(
        lambda: NetworkService().set_firewall_enabled(
            False,
            SafetyContext(dry_run=dry_run, yes=yes),
        )
    )


@firewall_app.command("reset")
def firewall_reset(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Reset Windows Firewall policy."""
    _run_write(
        lambda: NetworkService().reset_firewall(SafetyContext(dry_run=dry_run, yes=yes))
    )


@winsock_app.command("reset")
def winsock_reset(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Reset the Winsock catalog."""
    _run_write(
        lambda: NetworkService().reset_winsock(SafetyContext(dry_run=dry_run, yes=yes))
    )


@tcp_app.command("reset")
def tcp_reset(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview only.")] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the write action.")] = False,
) -> None:
    """Reset the TCP/IP stack."""
    _run_write(
        lambda: NetworkService().reset_tcp(SafetyContext(dry_run=dry_run, yes=yes))
    )


def _run_read_only(action: Callable[[], None]) -> None:
    try:
        action()
    except UnsupportedPlatformError as error:
        console.print(f"[red]{error}[/]")
        raise typer.Exit(code=1) from None
    except RuntimeError as error:
        console.print(f"[red]{error}[/]")
        raise typer.Exit(code=1) from None


def _run_write(action: Callable[[], NetworkActionResult]) -> None:
    try:
        result = action()
    except UnsupportedPlatformError as error:
        console.print(f"[red]{error}[/]")
        raise typer.Exit(code=1) from None
    _render_action_result(result)
    if not result.ok:
        raise typer.Exit(code=1)


def _render_interfaces(items: list[InterfaceInfo], json_output: bool) -> None:
    if json_output:
        _print_json([item.to_dict() for item in items])
        return
    table = Table(title="Interfaces")
    table.add_column("Name")
    table.add_column("Admin")
    table.add_column("State")
    table.add_column("Type")
    for item in items:
        table.add_row(item.name, item.admin_state or "", item.state or "", item.type or "")
    console.print(table)


def _render_raw(item: IpConfig, json_output: bool) -> None:
    if json_output:
        _print_json(item.to_dict())
        return
    console.print(item.raw)


def _render_proxy(item: ProxyStatus, json_output: bool) -> None:
    if json_output:
        _print_json(item.to_dict())
        return
    table = Table(title="Proxy")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Enabled", _format_optional_bool(item.enabled))
    table.add_row("Raw", item.raw)
    console.print(table)


def _render_firewall(item: FirewallStatus, json_output: bool) -> None:
    if json_output:
        _print_json(item.to_dict())
        return
    table = Table(title="Firewall")
    table.add_column("Output")
    table.add_row(item.raw)
    console.print(table)


def _render_wifi(item: WifiSignal, json_output: bool) -> None:
    if json_output:
        _print_json(item.to_dict())
        return
    table = Table(title="Wi-Fi Signal")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("SSID", item.ssid or "")
    table.add_row(
        "Signal",
        f"{item.signal_percent}%" if item.signal_percent is not None else "",
    )
    console.print(table)


def _render_connections(items: list[NetworkConnection], json_output: bool) -> None:
    if json_output:
        _print_json([item.to_dict() for item in items])
        return
    table = Table(title="Network Connections")
    table.add_column("Protocol")
    table.add_column("Local")
    table.add_column("Remote")
    table.add_column("Status")
    table.add_column("PID", justify="right")
    for item in items:
        table.add_row(
            item.protocol,
            item.local_address,
            item.remote_address or "",
            item.status or "",
            str(item.pid or ""),
        )
    console.print(table)


def _format_optional_bool(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def _print_json(data: Any) -> None:
    console.print(json.dumps(data, indent=2))


def _render_action_result(result: NetworkActionResult) -> None:
    status = "DRY-RUN" if result.safety.dry_run else "OK" if result.ok else "BLOCKED"
    console.print(f"[bold]{status}[/] {result.action}: {result.message}")
    console.print(f"Command: {' '.join(result.command)}")

    if result.current_state:
        table = Table(title="Current State")
        table.add_column("Field")
        table.add_column("Value")
        for key, value in result.current_state.items():
            table.add_row(str(key), str(value))
        console.print(table)

    if result.output:
        console.print(result.output)
