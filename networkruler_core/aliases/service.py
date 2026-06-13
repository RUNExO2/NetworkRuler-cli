from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from networkruler_core.config.paths import get_user_paths


@dataclass(frozen=True)
class AliasResult:
    ok: bool
    message: str
    reason: str
    name: str | None = None
    command: list[str] | None = None


class AliasService:
    def __init__(self, alias_file: Path | None = None) -> None:
        self.storage_path = alias_file or get_user_paths().config_dir / "aliases.json"

    def list_aliases(self) -> dict[str, list[str]]:
        return self._load()

    def set_alias(self, name: str, command: list[str]) -> AliasResult:
        aliases = self._load()
        proposed = dict(aliases)
        proposed[name] = command
        if self._has_cycle(name, proposed):
            return AliasResult(
                ok=False,
                message=f"Alias '{name}' would create a recursive alias.",
                reason="recursive_alias",
                name=name,
                command=command,
            )
        self._save(proposed)
        return AliasResult(
            ok=True,
            message=f"Alias '{name}' set.",
            reason="ok",
            name=name,
            command=command,
        )

    def remove_alias(self, name: str) -> AliasResult:
        aliases = self._load()
        if name not in aliases:
            return AliasResult(
                ok=False,
                message=f"Alias '{name}' not found.",
                reason="not_found",
                name=name,
            )
        command = aliases.pop(name)
        self._save(aliases)
        return AliasResult(
            ok=True,
            message=f"Alias '{name}' removed.",
            reason="ok",
            name=name,
            command=command,
        )

    def resolve_alias(self, name: str) -> AliasResult:
        aliases = self._load()
        command = aliases.get(name)
        if command is None:
            return AliasResult(
                ok=False,
                message=f"Alias '{name}' not found.",
                reason="not_found",
                name=name,
            )
        return AliasResult(
            ok=True,
            message=" ".join(command),
            reason="ok",
            name=name,
            command=command,
        )

    def _load(self) -> dict[str, list[str]]:
        if not self.storage_path.exists():
            return {}
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        if not isinstance(raw, dict):
            return {}
        aliases: dict[str, list[str]] = {}
        for name, command in raw.items():
            if isinstance(name, str) and isinstance(command, list):
                aliases[name] = [str(part) for part in command]
        return aliases

    def _save(self, aliases: dict[str, list[str]]) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_path.write_text(
            json.dumps(aliases, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _has_cycle(self, start: str, aliases: dict[str, list[str]]) -> bool:
        seen: set[str] = set()
        current = start
        while current in aliases:
            if current in seen:
                return True
            seen.add(current)
            command = aliases[current]
            if not command:
                return False
            current = command[0]
        return False

