"""Policy v2: a pure, deterministic, deny-wins ALLOW/DENY decision.

The engine reads only the materialized snapshot (scope, testing_rules,
authorization) and the request, so identical materialized inputs yield identical
decisions regardless of profile name. It resolves no secret and creates no
resource; `REQUIRES_APPROVAL` is never returned for schema v2. On `ALLOW` it also
returns the bound command produced by the binder.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

from hackbot.engagement_v2.binder import BoundCommand, bind
from hackbot.engagement_v2.constants import RiskLevel
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.manifest import CAPABILITY_TO_FIELD, ActionDefinition
from hackbot.engagement_v2.scope import ScopeDenyReason, ScopeV2

_RISK_ORDER = {
    RiskLevel.L0.value: 0,
    RiskLevel.L1.value: 1,
    RiskLevel.L2.value: 2,
    RiskLevel.L3.value: 3,
}
# Capabilities that imply finite-rate network volume; a not-applicable rate
# control cannot enforce them.
_NETWORK_RATED_CAPABILITIES = frozenset({"automated-scanning"})


class DecisionKind(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class PolicyDecision:
    kind: DecisionKind
    reason: str
    effective_risk: str
    bound: BoundCommand | None = None


def _deny(reason: str, effective_risk: str) -> PolicyDecision:
    return PolicyDecision(DecisionKind.DENY, reason, effective_risk)


def _request_targets(request: Mapping[str, object], name: str) -> tuple[str, ...]:
    parameters = request.get("parameters")
    if not isinstance(parameters, Mapping):
        raise ContractError(ReasonCode.INVALID_REQUEST)
    value = parameters.get(name)
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        items = tuple(value)
        if any(not isinstance(item, str) for item in items):
            raise ContractError(ReasonCode.INVALID_REQUEST)
        return tuple(str(item) for item in items)
    raise ContractError(ReasonCode.INVALID_REQUEST)


def _effective_risk(action: ActionDefinition, request: Mapping[str, object]) -> str:
    level = action.risk
    requested = request.get("requested_risk")
    # A request can only raise, never lower, the level.
    if isinstance(requested, str) and requested in _RISK_ORDER:
        if _RISK_ORDER[requested] > _RISK_ORDER[level]:
            level = requested
    return level


def decide(
    request: Mapping[str, object],
    snapshot: object,
    registry: Mapping[str, ActionDefinition],
    *,
    platform: str,
) -> PolicyDecision:
    """Return a deterministic ALLOW/DENY decision for a request."""

    action_id = request.get("action_id")
    if not isinstance(action_id, str) or action_id not in registry:
        raise ContractError(ReasonCode.INVALID_REQUEST)
    action = registry[action_id]

    authorization = getattr(snapshot, "authorization", None)
    program = getattr(snapshot, "program", None)
    scope_document = getattr(snapshot, "scope", None)
    if not isinstance(authorization, Mapping) or not isinstance(program, Mapping):
        raise ContractError(ReasonCode.INVALID_REQUEST)

    effective_risk = _effective_risk(action, request)

    # 1. Confirmed authorization.
    if authorization.get("confirmed") is not True:
        return _deny(ReasonCode.DENY_AUTHORIZATION_UNCONFIRMED.value, effective_risk)

    testing_rules = program.get("testing_rules")
    if not isinstance(testing_rules, Mapping):
        raise ContractError(ReasonCode.INVALID_REQUEST)

    # 2. Sensitive-capability gate (absent or non-true denies).
    for capability in action.capabilities:
        field = CAPABILITY_TO_FIELD[capability]
        if testing_rules.get(field) is not True:
            return _deny(ReasonCode.DENY_CAPABILITY_NOT_ALLOWED.value, effective_risk)

    # 3. All-target scope: every target checked before any output.
    scope = ScopeV2(scope_document if isinstance(scope_document, Mapping) else {})
    resolved: dict[str, tuple[str, ...]] = {}
    total_targets = 0
    for name in sorted(action.target_bindings):
        targets = _request_targets(request, name)
        if not targets:
            raise ContractError(ReasonCode.INVALID_REQUEST)
        for target in targets:
            outcome = scope.check(target)
            if not outcome.authorized:
                return _deny(outcome.reason.value, effective_risk)
        # Duplicate targets within a binding conflict.
        if len(set(targets)) != len(targets):
            return _deny(ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH.value, effective_risk)
        resolved[name] = targets
        total_targets += len(targets)

    # 4. Numeric limits: target count.
    max_targets = testing_rules.get("max_targets_per_action")
    if isinstance(max_targets, int) and not isinstance(max_targets, bool):
        if total_targets > max_targets:
            return _deny(ReasonCode.DENY_POLICY_LIMIT.value, effective_risk)

    # 5. Rate enforceability.
    if action.rate_control.kind == "not-applicable" and (
        action.capabilities & _NETWORK_RATED_CAPABILITIES
    ):
        max_rate = testing_rules.get("max_requests_per_second")
        if isinstance(max_rate, int) and not isinstance(max_rate, bool):
            return _deny(ReasonCode.DENY_RATE_UNENFORCEABLE.value, effective_risk)

    # 6. Bind and allow. Binding resolves no secret and creates no resource.
    bound = bind(action, request, resolved, platform=platform)
    return PolicyDecision(DecisionKind.ALLOW, "ALLOW", effective_risk, bound)
