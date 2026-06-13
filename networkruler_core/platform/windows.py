from __future__ import annotations

import platform
import re
import socket
import subprocess
from typing import Any

import psutil


DEFAULT_TIMEOUT_SECONDS = 10


class WindowsNetworkPlatform:
    @property
    def is_supported(self) -> bool:
        return platform.system().lower() == "windows"

    def list_interfaces(self) -> list[dict[str, Any]]:
        output = self._run(["netsh", "interface", "show", "interface"])
        interfaces = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[0] in {"Admin", "---"}:
                continue
            interfaces.append(
                {
                    "admin_state": parts[0],
                    "state": parts[1],
                    "type": parts[2],
                    "name": " ".join(parts[3:]),
                }
            )
        return interfaces

    def show_ip_config(self) -> dict[str, str]:
        return {"raw": self._run(["ipconfig", "/all"])}

    def show_proxy(self) -> dict[str, Any]:
        raw = self._run(["netsh", "winhttp", "show", "proxy"])
        lowered = raw.lower()
        enabled = None
        if "direct access" in lowered or "no proxy" in lowered:
            enabled = False
        elif "proxy server" in lowered:
            enabled = True
        return {"raw": raw, "enabled": enabled}

    def show_firewall(self) -> dict[str, str]:
        return {"raw": self._run(["netsh", "advfirewall", "show", "allprofiles"])}

    def wifi_signal(self) -> dict[str, Any]:
        raw = self._run(["netsh", "wlan", "show", "interfaces"])
        return {
            "raw": raw,
            "ssid": self._extract_value(raw, "SSID"),
            "signal_percent": self._extract_percent(raw, "Signal"),
        }

    def list_connections(self) -> list[dict[str, Any]]:
        connections = []
        for conn in psutil.net_connections(kind="inet"):
            connections.append(
                {
                    "protocol": self._socket_type_name(conn.type),
                    "local_address": self._format_address(conn.laddr),
                    "remote_address": self._format_address(conn.raddr),
                    "status": conn.status or None,
                    "pid": conn.pid,
                }
            )
        return connections

    def flush_dns(self) -> dict[str, str]:
        return {"raw": self._run(["ipconfig", "/flushdns"])}

    def register_dns(self) -> dict[str, str]:
        return {"raw": self._run(["ipconfig", "/registerdns"])}

    def release_ip(self, adapter: str | None = None) -> dict[str, str]:
        return {"raw": self._run(self._with_optional_adapter(["ipconfig", "/release"], adapter))}

    def renew_ip(self, adapter: str | None = None) -> dict[str, str]:
        return {"raw": self._run(self._with_optional_adapter(["ipconfig", "/renew"], adapter))}

    def reset_proxy(self) -> dict[str, str]:
        return {"raw": self._run(["netsh", "winhttp", "reset", "proxy"])}

    def set_firewall_state(self, enabled: bool) -> dict[str, str]:
        state = "on" if enabled else "off"
        return {
            "raw": self._run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", state]
            )
        }

    def reset_firewall(self) -> dict[str, str]:
        return {"raw": self._run(["netsh", "advfirewall", "reset"])}

    def reset_winsock(self) -> dict[str, str]:
        return {"raw": self._run(["netsh", "winsock", "reset"])}

    def reset_tcp(self) -> dict[str, str]:
        return {"raw": self._run(["netsh", "int", "ip", "reset"])}

    def _run(self, command: list[str]) -> str:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"Command timed out after {error.timeout} seconds: {' '.join(command)}"
            ) from error
        if result.returncode != 0:
            details = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(details or f"Command failed: {' '.join(command)}")
        return result.stdout.strip()

    def _extract_value(self, raw: str, key: str) -> str | None:
        pattern = re.compile(rf"^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", re.MULTILINE)
        for match in pattern.finditer(raw):
            value = match.group(1).strip()
            if value:
                return value
        return None

    def _extract_percent(self, raw: str, key: str) -> int | None:
        value = self._extract_value(raw, key)
        if value is None:
            return None
        match = re.search(r"(\d+)", value)
        return int(match.group(1)) if match else None

    def _format_address(self, address) -> str | None:
        if not address:
            return None
        host = getattr(address, "ip", None)
        port = getattr(address, "port", None)
        if host is None:
            return str(address)
        return f"{host}:{port}" if port is not None else str(host)

    def _socket_type_name(self, socket_type: int) -> str:
        if socket_type == socket.SOCK_STREAM:
            return "tcp"
        if socket_type == socket.SOCK_DGRAM:
            return "udp"
        return str(socket_type)

    def _with_optional_adapter(self, command: list[str], adapter: str | None) -> list[str]:
        if adapter:
            return [*command, adapter]
        return command
