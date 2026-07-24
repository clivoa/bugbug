"""Pure, ordered, fail-closed risk-policy evaluation tests."""

from dataclasses import replace
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from hackbot.risk.context import load_policy_context
from hackbot.risk.models import (
    ActionDefinition,
    ActionRequest,
    AuthorizationState,
    DecisionKind,
    RiskLevel,
)
from hackbot.risk.policy import RiskEngine
from hackbot.risk.registry import ActionRegistry


@pytest.fixture
def context(sample_engagement):
    return load_policy_context(sample_engagement, profile="bug-bounty")


@pytest.fixture
def action_request(context):
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id="fixture.l0-network",
        target="https://acme-corp.example/app",
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
    )


@pytest.fixture
def engine():
    return RiskEngine(
        ActionRegistry(
            [
                ActionDefinition("fixture.l0-network", RiskLevel.L0, network_access=True),
                ActionDefinition(
                    "fixture.l1-allowlisted",
                    RiskLevel.L1,
                    network_access=True,
                    low_impact_allowlisted=True,
                ),
                ActionDefinition("fixture.l1-unlisted", RiskLevel.L1, network_access=True),
                ActionDefinition("fixture.l2", RiskLevel.L2, network_access=True),
                ActionDefinition("fixture.prohibited", RiskLevel.L3, network_access=True),
                ActionDefinition("fixture.local", RiskLevel.L0),
            ]
        )
    )


def _context(context, **policy_changes):
    return replace(context, testing_policy=replace(context.testing_policy, **policy_changes))


def test_unknown_action_is_denied(engine, context, action_request):
    decision = engine.evaluate(replace(action_request, action_id="unknown"), context)
    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_UNKNOWN_ACTION"


def test_l0_network_action_requires_exact_scope(engine, context, action_request):
    decision = engine.evaluate(replace(action_request, target="https://evil.example"), context)
    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_SCOPE"


def test_scope_precedes_l1_program_permissions(engine, context, action_request):
    decision = engine.evaluate(
        replace(action_request, action_id="fixture.l1-unlisted", target="https://evil.example"),
        context,
    )
    assert decision.reason_code == "DENY_SCOPE"


def test_l1_requires_allowlist_and_automated_scanning_permission(engine, context, action_request):
    unlisted = engine.evaluate(replace(action_request, action_id="fixture.l1-unlisted"), context)
    assert unlisted.reason_code == "DENY_L1_NOT_ALLOWLISTED"

    scanning = engine.evaluate(replace(action_request, action_id="fixture.l1-allowlisted"), context)
    assert scanning.reason_code == "DENY_L1_AUTOMATED_SCANNING_NOT_ALLOWED"

    allowed_context = _context(context, automated_scanning_allowed=True)
    allowed = engine.evaluate(
        replace(action_request, action_id="fixture.l1-allowlisted"), allowed_context
    )
    assert allowed.kind is DecisionKind.ALLOW
    assert allowed.effective_risk is RiskLevel.L1


def test_l0_is_not_blocked_by_automated_scanning_permission(engine, context, action_request):
    decision = engine.evaluate(action_request, context)
    assert decision.kind is DecisionKind.ALLOW


def test_rate_and_concurrency_cannot_exceed_program(engine, context, action_request):
    assert engine.evaluate(replace(action_request, rate=3), context).reason_code == "DENY_RATE"
    assert (
        engine.evaluate(replace(action_request, concurrency=2), context).reason_code
        == "DENY_CONCURRENCY"
    )


@pytest.mark.parametrize("field", ["rate", "concurrency"])
def test_network_and_active_actions_require_rate_and_concurrency(
    engine, context, action_request, field
):
    malformed = replace(action_request)
    object.__setattr__(malformed, field, None)
    decision = engine.evaluate(malformed, context)
    assert decision.reason_code == ("DENY_RATE" if field == "rate" else "DENY_CONCURRENCY")


def test_l3_is_denied_even_with_grant(engine, context, action_request):
    decision = engine.evaluate(
        replace(action_request, action_id="fixture.prohibited", requested_risk=RiskLevel.L0),
        context,
        grant=object(),
    )
    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_PROHIBITED"


def test_request_cannot_lower_registered_floor(engine, context, action_request):
    decision = engine.evaluate(
        replace(action_request, action_id="fixture.l2", requested_risk=RiskLevel.L0), context
    )
    assert decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert decision.effective_risk is RiskLevel.L2
    assert decision.reason_code == "REQUIRES_APPROVAL"


def test_l2_ignores_grants_in_this_task(engine, context, action_request):
    decision = engine.evaluate(
        replace(action_request, action_id="fixture.l2"), context, grant=object()
    )
    assert decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert decision.reason_code == "REQUIRES_APPROVAL"
    assert decision.challenge is None


def test_requires_matching_engagement_id_and_canonical_path(engine, context, action_request):
    bad_id = replace(action_request)
    bad_path = replace(action_request)
    object.__setattr__(bad_id, "engagement_id", "different")
    object.__setattr__(bad_path, "engagement_path", "/another/canonical/path")

    assert engine.evaluate(bad_id, context).reason_code == "DENY_ENGAGEMENT_MISMATCH"
    assert engine.evaluate(bad_path, context).reason_code == "DENY_ENGAGEMENT_MISMATCH"


@pytest.mark.parametrize(
    "authorization",
    [
        AuthorizationState(False, None, None),
        AuthorizationState(True, None, "operator"),
        AuthorizationState(True, datetime(2026, 7, 24), "operator"),
        AuthorizationState(True, datetime(2026, 7, 24, tzinfo=UTC), ""),
    ],
)
def test_evaluation_defensively_requires_confirmed_authorization(
    engine, context, action_request, authorization
):
    decision = engine.evaluate(action_request, replace(context, authorization=authorization))
    assert decision.reason_code == "DENY_AUTHORIZATION"


def test_required_profile_must_match(engine, context, action_request):
    profile_engine = RiskEngine(
        ActionRegistry(
            [ActionDefinition("fixture.l0-network", RiskLevel.L0, required_profile="lab")]
        )
    )
    decision = profile_engine.evaluate(action_request, context)
    assert decision.reason_code == "DENY_PROGRAM_PROFILE"


def test_prohibited_tool_matches_only_action_id_or_normalized_argv_basename(
    engine, context, action_request
):
    action_id_denied = engine.evaluate(
        action_request, _context(context, prohibited_tools=("fixture.l0-network",))
    )
    assert action_id_denied.reason_code == "DENY_PROGRAM_PROHIBITED_TOOL"

    argv_denied = engine.evaluate(
        replace(action_request, argv=("C:\\Tools\\NMAP.EXE", "-sV")),
        _context(context, prohibited_tools=("nmap.exe",)),
    )
    assert argv_denied.reason_code == "DENY_PROGRAM_PROHIBITED_TOOL"

    substring_not_denied = engine.evaluate(
        replace(action_request, argv=("safe-nmap-wrapper",)),
        _context(context, prohibited_tools=("nmap",)),
    )
    assert substring_not_denied.kind is DecisionKind.ALLOW


def test_vulnerability_and_impact_restrictions_use_typed_names_only(
    engine, context, action_request
):
    vulnerability_denied = engine.evaluate(
        replace(action_request, vulnerability_type=" XSS "),
        _context(context, prohibited_vulnerability_types=("xss",)),
    )
    assert vulnerability_denied.reason_code == "DENY_PROGRAM_PROHIBITED_VULNERABILITY_TYPE"

    impact_denied = engine.evaluate(
        replace(action_request, impact=" Availability "),
        _context(context, excluded_impacts=("availability",)),
    )
    assert impact_denied.reason_code == "DENY_PROGRAM_EXCLUDED_IMPACT"

    unspecified_vulnerability = engine.evaluate(
        action_request, _context(context, prohibited_vulnerability_types=("xss",))
    )
    assert unspecified_vulnerability.reason_code == "DENY_PROGRAM_VULNERABILITY_TYPE_UNSPECIFIED"

    unspecified_impact = engine.evaluate(
        action_request, _context(context, excluded_impacts=("availability",))
    )
    assert unspecified_impact.reason_code == "DENY_PROGRAM_IMPACT_UNSPECIFIED"


def test_required_program_headers_are_a_subset_of_request_declared_names(
    engine, context, action_request
):
    denied = engine.evaluate(action_request, _context(context, required_headers=("x-research-id",)))
    assert denied.reason_code == "DENY_PROGRAM_REQUIRED_HEADERS"

    allowed = engine.evaluate(
        replace(action_request, required_headers=("X-Research-ID", "X-Optional")),
        _context(context, required_headers=("x-research-id",)),
    )
    assert allowed.kind is DecisionKind.ALLOW


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (datetime(2026, 7, 24, 8, 59, tzinfo=UTC), DecisionKind.ALLOW),
        (datetime(2026, 7, 24, 9, 0, tzinfo=UTC), DecisionKind.DENY),
        (datetime(2026, 7, 24, 9, 59, tzinfo=UTC), DecisionKind.DENY),
        (datetime(2026, 7, 24, 10, 0, tzinfo=UTC), DecisionKind.ALLOW),
    ],
)
def test_restricted_hours_are_start_inclusive_and_end_exclusive(
    engine, context, action_request, now, expected
):
    restricted = _context(
        context,
        restricted_hours=("09:00-10:00",),
        restricted_hours_timezone="UTC",
    )
    decision = engine.evaluate(action_request, restricted, now=now)
    assert decision.kind is expected
    if expected is DecisionKind.DENY:
        assert decision.reason_code == "DENY_PROGRAM_RESTRICTED_HOURS"


@pytest.mark.parametrize(
    "now",
    [
        None,
        datetime(2026, 7, 24, 9, 0),
        datetime(2026, 7, 24, 9, 0, tzinfo=ZoneInfo("Europe/Madrid")),
    ],
)
def test_restricted_hours_reject_missing_naive_or_non_utc_clocks(
    engine, context, action_request, now
):
    restricted = _context(
        context,
        restricted_hours=("09:00-10:00",),
        restricted_hours_timezone="UTC",
    )
    decision = engine.evaluate(action_request, restricted, now=now)
    assert decision.reason_code == "DENY_PROGRAM_INVALID_CLOCK"


def test_scope_boundary_error_fails_closed_without_swallowing_programming_errors(
    engine, context, action_request
):
    class InvalidScope:
        def check(self, _target):
            raise ValueError

    decision = engine.evaluate(action_request, replace(context, scope=InvalidScope()))
    assert decision.reason_code == "DENY_SCOPE"
