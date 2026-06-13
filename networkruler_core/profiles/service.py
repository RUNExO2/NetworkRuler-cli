from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from networkruler_core.config.paths import get_user_paths
from networkruler_core.network.service import NetworkService
from networkruler_core.profiles.models import (
    ProfileAction,
    ProfileApplyResult,
    ProfileValidationResult,
)
from networkruler_core.safety import RiskLevel, SafetyContext


ActionHandler = Callable[[dict[str, Any], SafetyContext], object]


class ProfileService:
    def __init__(
        self,
        profile_dir: Path | None = None,
        action_handlers: dict[str, ActionHandler] | None = None,
    ) -> None:
        self.profile_dir = profile_dir or get_user_paths().config_dir / "profiles"
        self._action_handlers = action_handlers or self._default_action_handlers()

    def list_profiles(self) -> list[str]:
        if not self.profile_dir.exists():
            return []
        return sorted(path.stem for path in self.profile_dir.glob("*.json"))

    def show_profile(self, name: str) -> dict[str, Any] | None:
        path = self._profile_path(name)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def create_profile(self, name: str) -> ProfileValidationResult:
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        path = self._profile_path(name)
        if path.exists():
            return ProfileValidationResult(
                ok=False,
                name=name,
                reason="already_exists",
                errors=[f"Profile '{name}' already exists."],
            )
        payload = {"version": 2, "name": name, "actions": []}
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return ProfileValidationResult(ok=True, name=name, reason="valid")

    def delete_profile(self, name: str, *, yes: bool = False) -> ProfileValidationResult:
        path = self._profile_path(name)
        if not path.exists():
            return ProfileValidationResult(
                ok=False,
                name=name,
                reason="not_found",
                errors=[f"Profile '{name}' not found."],
            )
        if not yes:
            return ProfileValidationResult(
                ok=False,
                name=name,
                reason="confirmation_required",
                errors=["Deleting a profile requires --yes."],
            )
        path.unlink()
        return ProfileValidationResult(ok=True, name=name, reason="deleted")

    def validate_profile(self, name: str) -> ProfileValidationResult:
        payload = self.show_profile(name)
        if payload is None:
            return ProfileValidationResult(
                ok=False,
                name=name,
                reason="not_found",
                errors=[f"Profile '{name}' not found or is not valid JSON."],
            )
        return self._validate_payload(name, payload)

    def apply_profile(self, name: str, context: SafetyContext) -> ProfileApplyResult:
        validation = self.validate_profile(name)
        if not validation.ok:
            return ProfileApplyResult(
                ok=False,
                name=name,
                reason=validation.reason,
                message="Profile is not valid.",
                dry_run=context.dry_run,
                plan=validation.actions,
                errors=validation.errors,
            )
        if context.dry_run:
            return ProfileApplyResult(
                ok=True,
                name=name,
                reason="dry_run",
                message="Dry-run only. No profile action executed.",
                dry_run=True,
                plan=validation.actions,
            )

        executed = []
        for action in validation.actions:
            handler = self._action_handlers[action.type]
            result = handler(action.params, context)
            executed.append(result)
            if getattr(result, "ok", True) is False:
                return ProfileApplyResult(
                    ok=False,
                    name=name,
                    reason="action_failed",
                    message=f"Profile action '{action.type}' failed.",
                    dry_run=False,
                    plan=validation.actions,
                    executed=executed,
                )

        return ProfileApplyResult(
            ok=True,
            name=name,
            reason="applied",
            message="Profile applied.",
            dry_run=False,
            plan=validation.actions,
            executed=executed,
        )

    def _validate_payload(
        self,
        name: str,
        payload: dict[str, Any],
    ) -> ProfileValidationResult:
        if "commands" in payload or "settings" in payload or "profile_name" in payload:
            return ProfileValidationResult(
                ok=False,
                name=name,
                reason="legacy_unsupported",
                legacy=True,
                errors=["Legacy command-replay profiles are unsupported in v2."],
            )

        errors: list[str] = []
        actions: list[ProfileAction] = []
        if payload.get("version") != 2:
            errors.append("version must be 2")
        raw_actions = payload.get("actions")
        if not isinstance(raw_actions, list):
            errors.append("actions must be a list")
            raw_actions = []

        for index, raw_action in enumerate(raw_actions):
            if not isinstance(raw_action, dict):
                errors.append(f"actions[{index}] must be an object")
                continue
            action_type = raw_action.get("type")
            if not action_type:
                errors.append(f"actions[{index}].type is required")
                continue
            if action_type not in self._action_handlers:
                errors.append(f"actions[{index}].type is unsupported: {action_type}")
                continue
            params = raw_action.get("params", {})
            if not isinstance(params, dict):
                errors.append(f"actions[{index}].params must be an object")
                continue
            risk_level = self._parse_risk(raw_action.get("risk_level"), index, errors)
            if risk_level is None:
                continue
            actions.append(
                ProfileAction(
                    type=str(action_type),
                    params=params,
                    risk_level=risk_level,
                    requires_admin=bool(raw_action.get("requires_admin", False)),
                    supports_dry_run=bool(raw_action.get("supports_dry_run", True)),
                )
            )

        if errors:
            return ProfileValidationResult(
                ok=False,
                name=name,
                reason="invalid",
                errors=errors,
                actions=actions,
            )
        return ProfileValidationResult(ok=True, name=name, reason="valid", actions=actions)

    def _parse_risk(
        self,
        value: object,
        index: int,
        errors: list[str],
    ) -> RiskLevel | None:
        try:
            return RiskLevel(str(value))
        except ValueError:
            errors.append(f"actions[{index}].risk_level is invalid")
            return None

    def _profile_path(self, name: str) -> Path:
        return self.profile_dir / f"{name}.json"

    def _default_action_handlers(self) -> dict[str, ActionHandler]:
        service = NetworkService()
        return {
            "network.dns.flush": lambda params, context: service.flush_dns(context),
            "network.dns.register": lambda params, context: service.register_dns(context),
            "network.ip.release": lambda params, context: service.release_ip(
                context,
                adapter=params.get("adapter"),
            ),
            "network.ip.renew": lambda params, context: service.renew_ip(
                context,
                adapter=params.get("adapter"),
            ),
            "network.proxy.reset": lambda params, context: service.reset_proxy(context),
            "network.firewall.enable": lambda params, context: service.set_firewall_enabled(
                True,
                context,
            ),
            "network.firewall.disable": lambda params, context: service.set_firewall_enabled(
                False,
                context,
            ),
            "network.firewall.reset": lambda params, context: service.reset_firewall(context),
            "network.winsock.reset": lambda params, context: service.reset_winsock(context),
            "network.tcp.reset": lambda params, context: service.reset_tcp(context),
        }
