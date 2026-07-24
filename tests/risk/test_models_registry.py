from dataclasses import FrozenInstanceError

import pytest

from hackbot.risk.models import ActionDefinition, ActionRequest, RiskLevel
from hackbot.risk.registry import ActionRegistry, RegistryError


def test_risk_levels_are_ordered():
    assert RiskLevel.L0 < RiskLevel.L1 < RiskLevel.L2 < RiskLevel.L3


def test_action_definition_is_frozen_and_characteristics_raise_floor():
    action = ActionDefinition("fixture.write", RiskLevel.L1, state_changing=True)
    assert action.effective_floor == RiskLevel.L2
    with pytest.raises(FrozenInstanceError):
        action.action_id = "changed"


def test_request_cannot_lower_registered_floor():
    action = ActionDefinition("fixture.scan", RiskLevel.L2)
    request = ActionRequest(
        engagement_id="sample",
        engagement_path="/tmp/sample",
        action_id="fixture.scan",
        target="https://example.com",
        argv=("fixture", "scan"),
        hypothesis_id="hyp-1",
        rationale="Validate one authorized hypothesis.",
        rate=1,
        concurrency=1,
        data_touched="Public response headers.",
        expected_impact="One low-rate request.",
        stop_condition="Stop on any rate limit.",
        cleanup_plan="No state is created.",
        program_rule="Automated testing rule.",
        requested_risk=RiskLevel.L0,
    )
    assert request.effective_risk(action) == RiskLevel.L2


@pytest.mark.parametrize("field", ["hypothesis_id", "stop_condition", "cleanup_plan"])
def test_active_request_requires_reviewed_safety_fields(field):
    values = {
        "engagement_id": "sample",
        "engagement_path": "/tmp/sample",
        "action_id": "fixture.scan",
        "target": "https://example.com",
        "argv": ("fixture", "scan"),
        "hypothesis_id": "hyp-1",
        "rationale": "Validate one authorized hypothesis.",
        "rate": 1,
        "concurrency": 1,
        "data_touched": "Public response headers.",
        "expected_impact": "One low-rate request.",
        "stop_condition": "Stop on any rate limit.",
        "cleanup_plan": "No state is created.",
        "program_rule": "Automated testing rule.",
    }
    values[field] = ""

    with pytest.raises(ValueError, match=field):
        ActionRequest(**values)


def test_registry_rejects_duplicate_and_unknown_actions():
    action = ActionDefinition("fixture.passive", RiskLevel.L0)
    with pytest.raises(RegistryError):
        ActionRegistry([action, action])
    registry = ActionRegistry([action])
    with pytest.raises(RegistryError):
        registry.require("missing")
