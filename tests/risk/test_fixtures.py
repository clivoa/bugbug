"""The fixture action registry must stay inert and code-owned."""

import pytest

from hackbot.risk.fixtures import FIXTURE_ACTIONS
from hackbot.risk.models import RiskLevel
from hackbot.risk.registry import RegistryError


def test_fixture_ids_are_exactly_the_four_gate_probes():
    for action_id, level in (
        ("fixture.passive", RiskLevel.L0),
        ("fixture.low-impact", RiskLevel.L1),
        ("fixture.intrusive", RiskLevel.L2),
        ("fixture.prohibited", RiskLevel.L3),
    ):
        definition = FIXTURE_ACTIONS.require(action_id)
        assert definition.minimum_risk is level
        assert definition.network_access is True


def test_fixture_actions_execute_nothing():
    for action_id in (
        "fixture.passive",
        "fixture.low-impact",
        "fixture.intrusive",
        "fixture.prohibited",
    ):
        definition = FIXTURE_ACTIONS.require(action_id)
        assert definition.uses_external_tool is False
        assert definition.tool_id is None
        assert definition.executable is None
        assert definition.shell_execution is False
        assert definition.argv_template == ()


def test_unknown_fixture_action_is_rejected():
    with pytest.raises(RegistryError):
        FIXTURE_ACTIONS.require("fixture.unknown")
