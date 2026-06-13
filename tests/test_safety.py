from __future__ import annotations

from networkruler_core.safety import (
    CommandRisk,
    RiskLevel,
    SafetyContext,
    SafetyDecision,
    TargetPreview,
    check_windows_admin,
    evaluate_safety,
    run_with_safety,
)


def test_dry_run_never_executes_action():
    executed = False
    metadata = CommandRisk(
        name="process.kill",
        risk=RiskLevel.DANGEROUS,
        requires_confirmation=True,
        preview=TargetPreview(label="Process", identifier="123", details={"name": "app.exe"}),
    )

    def action():
        nonlocal executed
        executed = True
        return "killed"

    result = run_with_safety(
        metadata,
        SafetyContext(dry_run=True),
        action,
        is_admin=lambda: True,
    )

    assert executed is False
    assert result.executed is False
    assert result.dry_run is True
    assert result.allowed is True
    assert result.preview.identifier == "123"


def test_dangerous_command_requires_confirmation():
    metadata = CommandRisk(
        name="firewall.disable",
        risk=RiskLevel.DANGEROUS,
        requires_confirmation=True,
    )

    decision = evaluate_safety(
        metadata,
        SafetyContext(yes=False),
        is_admin=lambda: True,
    )

    assert decision.allowed is False
    assert decision.reason == "confirmation_required"
    assert "requires confirmation" in decision.message


def test_yes_bypasses_confirmation_prompt():
    metadata = CommandRisk(
        name="firewall.disable",
        risk=RiskLevel.DANGEROUS,
        requires_confirmation=True,
    )

    decision = evaluate_safety(
        metadata,
        SafetyContext(yes=True),
        is_admin=lambda: True,
    )

    assert decision.allowed is True
    assert decision.confirmed is True
    assert decision.reason == "allowed"


def test_force_bypasses_confirmation_but_is_recorded():
    metadata = CommandRisk(
        name="profile.apply-unsafe",
        risk=RiskLevel.DANGEROUS,
        requires_confirmation=True,
    )

    decision = evaluate_safety(
        metadata,
        SafetyContext(force=True),
        is_admin=lambda: True,
    )

    assert decision.allowed is True
    assert decision.forced is True
    assert decision.confirmed is False


def test_admin_requirement_detected():
    metadata = CommandRisk(
        name="network.winsock.reset",
        risk=RiskLevel.DANGEROUS,
        requires_admin=True,
        requires_confirmation=True,
    )

    decision = evaluate_safety(
        metadata,
        SafetyContext(yes=True),
        is_admin=lambda: False,
    )

    assert decision.allowed is False
    assert decision.reason == "admin_required"
    assert "administrator" in decision.message.lower()


def test_structured_safety_decision_result():
    preview = TargetPreview(
        label="Interface",
        identifier="Ethernet",
        details={"state": "Connected"},
    )
    metadata = CommandRisk(
        name="network.interface.inspect",
        risk=RiskLevel.READ,
        preview=preview,
    )

    decision = evaluate_safety(metadata, SafetyContext())
    payload = decision.to_dict()

    assert isinstance(decision, SafetyDecision)
    assert payload == {
        "allowed": True,
        "executed": False,
        "dry_run": False,
        "confirmed": False,
        "forced": False,
        "risk": "READ",
        "reason": "allowed",
        "message": "Safety checks passed.",
        "preview": {
            "label": "Interface",
            "identifier": "Ethernet",
            "details": {"state": "Connected"},
        },
    }


def test_check_windows_admin_uses_injected_platform_hooks():
    assert check_windows_admin(system_name=lambda: "Windows", admin_probe=lambda: True) is True
    assert check_windows_admin(system_name=lambda: "Windows", admin_probe=lambda: False) is False
    assert check_windows_admin(system_name=lambda: "Linux", admin_probe=lambda: True) is False
