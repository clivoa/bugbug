"""Inert, code-owned fixture actions that exercise the gate without executing.

These definitions exist solely so the risk/approval CLI can be driven end to end
against the policy engine. None of them names a tool, executable, shell, or argv
template, so none can ever run anything. Real action definitions arrive later
with reviewed tool adapters; CLI input can never register or mutate an action.
"""

from __future__ import annotations

from hackbot.risk.models import ActionDefinition, RiskLevel
from hackbot.risk.registry import ActionRegistry

FIXTURE_ACTIONS = ActionRegistry(
    [
        ActionDefinition("fixture.passive", RiskLevel.L0, network_access=True),
        ActionDefinition(
            "fixture.low-impact",
            RiskLevel.L1,
            network_access=True,
            low_impact_allowlisted=True,
        ),
        ActionDefinition(
            "fixture.intrusive",
            RiskLevel.L2,
            network_access=True,
            high_volume=True,
        ),
        ActionDefinition("fixture.prohibited", RiskLevel.L3, network_access=True),
    ]
)

__all__ = ["FIXTURE_ACTIONS"]
