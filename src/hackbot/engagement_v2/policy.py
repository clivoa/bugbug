"""Policy v2: a pure, deterministic, deny-wins ALLOW/DENY decision.

The engine reads only the materialized snapshot (scope, testing_rules,
authorization) and the request, so identical materialized inputs yield identical
decisions regardless of profile name. It resolves no secret and creates no
resource; `REQUIRES_APPROVAL` is never returned for schema v2. On `ALLOW` it also
returns the bound command produced by the binder.
"""

from __future__ import annotations

import posixpath
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
_NETWORK_RATED_CAPABILITIES = frozenset({"automated-scanning", "authenticated-testing"})

# Inferred risk floor per capability. The effective level is never below this.
_CAPABILITY_RISK_FLOOR: dict[str, str] = {
    "authenticated-testing": "L1",
    "automated-scanning": "L2",
    "state-changing": "L2",
    "account-creation": "L2",
    "multiple-accounts": "L2",
    "out-of-band": "L2",
    "sensitive-data-access": "L2",
    "autonomous-progression": "L2",
    "exploit-execution": "L3",
    "payload-execution": "L3",
    "credential-access": "L3",
    "credential-capture": "L3",
    "privileged-execution": "L3",
    "lateral-movement": "L3",
    "persistence": "L3",
    "data-exfiltration": "L3",
    "social-engineering": "L3",
    "denial-of-service": "L3",
    "destructive-testing": "L3",
}


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
    # Inferred floor from declared capabilities; a request can only raise, never
    # lower, the effective level.
    for capability in action.capabilities:
        floor = _CAPABILITY_RISK_FLOOR.get(capability)
        if floor is not None and _RISK_ORDER[floor] > _RISK_ORDER[level]:
            level = floor
    requested = request.get("requested_risk")
    if isinstance(requested, str) and requested in _RISK_ORDER:
        if _RISK_ORDER[requested] > _RISK_ORDER[level]:
            level = requested
    return level


def _int_param(request: Mapping[str, object], name: str | None) -> int | None:
    if name is None:
        return None
    parameters = request.get("parameters")
    if not isinstance(parameters, Mapping):
        return None
    value = parameters.get(name)
    if type(value) is int:
        return value
    return None


def _string_set(value: object) -> frozenset[str]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return frozenset(item for item in value if isinstance(item, str))
    return frozenset()


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

    # 4. Prohibited tools, vulnerability types, and excluded impacts.
    executable = action.executables.get(platform)
    if executable is not None:
        basename = posixpath.basename(executable.replace("\\", "/")).lower()
        if basename in {
            tool.lower() for tool in _string_set(testing_rules.get("prohibited_tools"))
        }:
            return _deny(ReasonCode.DENY_POLICY_LIMIT.value, effective_risk)
    if action.vulnerability_types & _string_set(
        testing_rules.get("prohibited_vulnerability_types")
    ):
        return _deny(ReasonCode.DENY_POLICY_LIMIT.value, effective_risk)
    if action.impacts & _string_set(testing_rules.get("excluded_impacts")):
        return _deny(ReasonCode.DENY_POLICY_LIMIT.value, effective_risk)

    # 5. Numeric limits: target count, concurrency, and rate.
    max_targets = testing_rules.get("max_targets_per_action")
    if type(max_targets) is int and total_targets > max_targets:
        return _deny(ReasonCode.DENY_POLICY_LIMIT.value, effective_risk)
    concurrency = _int_param(request, action.rate_control.concurrency_parameter)
    max_concurrency = testing_rules.get("concurrency")
    if concurrency is not None and type(max_concurrency) is int and concurrency > max_concurrency:
        return _deny(ReasonCode.DENY_POLICY_LIMIT.value, effective_risk)
    rate = _int_param(request, action.rate_control.rate_parameter)
    max_rate = testing_rules.get("max_requests_per_second")
    if rate is not None and type(max_rate) is int and rate > max_rate:
        return _deny(ReasonCode.DENY_POLICY_LIMIT.value, effective_risk)

    # 6. Rate enforceability: a not-applicable rate control cannot bound a
    # network-rated or fan-out action under a finite request rate.
    has_fanout = any(token.startswith("{targets_file:") for token in action.argv_template)
    if action.rate_control.kind == "not-applicable" and (
        bool(action.capabilities & _NETWORK_RATED_CAPABILITIES) or has_fanout
    ):
        if type(max_rate) is int:
            return _deny(ReasonCode.DENY_RATE_UNENFORCEABLE.value, effective_risk)

    # 7. Bind and allow. Binding resolves no secret and creates no resource.
    bound = bind(action, request, resolved, platform=platform)
    return PolicyDecision(DecisionKind.ALLOW, "ALLOW", effective_risk, bound)
