"""Pure, ordered, fail-closed risk-policy evaluation tests."""

from dataclasses import replace
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from hackbot.risk.context import (
    _canonical_policy_data,
    _policy_digest,
    _scope_snapshot,
    load_policy_context,
)
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
        argv=(),
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
                    automated=True,
                ),
                ActionDefinition("fixture.l1-unlisted", RiskLevel.L1, network_access=True),
                ActionDefinition(
                    "fixture.l1-manual",
                    RiskLevel.L1,
                    network_access=True,
                    low_impact_allowlisted=True,
                ),
                ActionDefinition("fixture.l2", RiskLevel.L2, network_access=True),
                ActionDefinition("fixture.prohibited", RiskLevel.L3, network_access=True),
                ActionDefinition("fixture.local", RiskLevel.L0),
            ]
        )
    )


def _context(context, **policy_changes):
    testing_policy = replace(context.testing_policy, **policy_changes)
    scope_in, scope_out = _scope_snapshot(context.scope.in_scope, context.scope.out_of_scope)
    digest = _policy_digest(
        _canonical_policy_data(
            engagement_id=context.engagement_id,
            engagement_path=context.engagement_path,
            program_id=context.program_id,
            authorization=context.authorization,
            scope_in=scope_in,
            scope_out=scope_out,
            testing_policy=testing_policy,
            active_profile=context.active_profile,
        )
    )
    return replace(context, testing_policy=testing_policy, policy_digest=digest)


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
    assert scanning.reason_code == "DENY_PROGRAM_AUTOMATED_NOT_ALLOWED"

    allowed_context = _context(context, automated_scanning_allowed=True)
    allowed = engine.evaluate(
        replace(action_request, action_id="fixture.l1-allowlisted"), allowed_context
    )
    assert allowed.kind is DecisionKind.ALLOW
    assert allowed.effective_risk is RiskLevel.L1


def test_manual_allowlisted_l1_does_not_require_automated_scanning_permission(
    engine, context, action_request
):
    decision = engine.evaluate(replace(action_request, action_id="fixture.l1-manual"), context)
    assert decision.kind is DecisionKind.ALLOW


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
        replace(action_request, action_id="fixture.l2", requested_risk=RiskLevel.L0),
        context,
        now=datetime(2026, 7, 24, 12, 0, tzinfo=UTC),
    )
    assert decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert decision.effective_risk is RiskLevel.L2
    assert decision.reason_code == "REQUIRES_APPROVAL"
    assert decision.challenge is not None


def test_l2_rejects_an_invalid_grant(engine, context, action_request):
    decision = engine.evaluate(
        replace(action_request, action_id="fixture.l2"),
        context,
        grant=object(),
        now=datetime(2026, 7, 24, 12, 0, tzinfo=UTC),
    )
    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_APPROVAL_MISMATCH"
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


def test_prohibited_tool_uses_only_code_owned_tool_identity(engine, context, action_request):
    trusted_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l0-network",
                    RiskLevel.L0,
                    network_access=True,
                    uses_external_tool=True,
                    tool_id="nmap",
                    executable="/opt/reviewed/nmap",
                    argv_template=("/opt/reviewed/nmap",),
                )
            ]
        )
    )
    action_id_denied = trusted_engine.evaluate(
        action_request, _context(context, prohibited_tools=("nmap",))
    )
    assert action_id_denied.reason_code == "DENY_PROGRAM_PROHIBITED_TOOL"

    path_denied = trusted_engine.evaluate(
        replace(action_request, argv=("safe-nmap-wrapper",)),
        _context(context, prohibited_tools=("/opt/reviewed/nmap",)),
    )
    assert path_denied.reason_code == "DENY_PROGRAM_PROHIBITED_TOOL"

    wrapper_cannot_bypass = trusted_engine.evaluate(
        replace(action_request, argv=("safe-nmap-wrapper",)),
        _context(context, prohibited_tools=("nmap",)),
    )
    assert wrapper_cannot_bypass.reason_code == "DENY_PROGRAM_PROHIBITED_TOOL"

    executable_mismatch = trusted_engine.evaluate(
        replace(action_request, argv=("safe-nmap-wrapper",)), context
    )
    assert executable_mismatch.reason_code == "DENY_EXECUTABLE_MISMATCH"


def test_prohibited_tool_allows_an_explicit_no_tool_action(engine, context, action_request):
    no_tool = engine.evaluate(action_request, _context(context, prohibited_tools=("nmap",)))
    assert no_tool.kind is DecisionKind.ALLOW

    directly_prohibited = engine.evaluate(
        action_request,
        _context(context, prohibited_tools=("fixture.l0-network",)),
    )
    assert directly_prohibited.reason_code == "DENY_PROGRAM_PROHIBITED_TOOL"


def test_prohibited_tool_paths_use_lexical_canonicalization(context, action_request):
    path_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l0-network",
                    RiskLevel.L0,
                    network_access=True,
                    uses_external_tool=True,
                    executable="c:/tools/nmap.exe",
                    argv_template=("c:/tools/nmap.exe",),
                )
            ]
        )
    )
    decision = path_engine.evaluate(
        replace(action_request, argv=("c:/tools/nmap.exe",)),
        _context(context, prohibited_tools=("C:\\TOOLS\\NMAP.EXE",)),
    )
    assert decision.reason_code == "DENY_PROGRAM_PROHIBITED_TOOL"

    malformed = path_engine.evaluate(
        replace(action_request, argv=("c:/tools/nmap.exe",)),
        _context(context, prohibited_tools=("c:/tools//nmap.exe",)),
    )
    assert malformed.reason_code == "DENY_PROGRAM_INVALID_POLICY"


def test_external_action_requires_its_exact_code_owned_executable(context, action_request):
    external_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l0-network",
                    RiskLevel.L0,
                    network_access=True,
                    uses_external_tool=True,
                    executable="/usr/bin/sqlmap",
                    argv_template=("/usr/bin/sqlmap", "--batch"),
                )
            ]
        )
    )
    mismatch = external_engine.evaluate(replace(action_request, argv=("/usr/bin/nmap",)), context)
    assert mismatch.reason_code == "DENY_EXECUTABLE_MISMATCH"

    shell_argv = external_engine.evaluate(replace(action_request, argv=("/bin/sh",)), context)
    assert shell_argv.reason_code == "DENY_EXECUTABLE_MISMATCH"

    exact = external_engine.evaluate(
        replace(action_request, argv=("/usr/bin/sqlmap", "--batch")), context
    )
    assert exact.kind is DecisionKind.ALLOW


def test_external_argv_must_exactly_match_the_code_owned_template(context, action_request):
    template_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l0-network",
                    RiskLevel.L0,
                    network_access=True,
                    uses_external_tool=True,
                    executable="/usr/bin/sqlmap",
                    argv_template=(
                        "/usr/bin/sqlmap",
                        "--url",
                        "{target}",
                        "--rate",
                        "{rate}",
                        "--threads",
                        "{concurrency}",
                    ),
                )
            ]
        )
    )
    expected = (
        "/usr/bin/sqlmap",
        "--url",
        action_request.target,
        "--rate",
        "1",
        "--threads",
        "1",
    )
    allowed = template_engine.evaluate(replace(action_request, argv=expected), context)
    assert allowed.kind is DecisionKind.ALLOW

    extra = template_engine.evaluate(replace(action_request, argv=expected + ("--batch",)), context)
    assert extra.reason_code == "DENY_ARGV_TEMPLATE_MISMATCH"

    reordered = template_engine.evaluate(
        replace(
            action_request,
            argv=(
                "/usr/bin/sqlmap",
                "--rate",
                "1",
                "--url",
                action_request.target,
                "--threads",
                "1",
            ),
        ),
        context,
    )
    assert reordered.reason_code == "DENY_ARGV_TEMPLATE_MISMATCH"

    injected = template_engine.evaluate(
        replace(
            action_request,
            argv=(
                "/usr/bin/sqlmap",
                "--url",
                action_request.target,
                "--batch",
                "--rate",
                "1",
                "--threads",
                "1",
            ),
        ),
        context,
    )
    assert injected.reason_code == "DENY_ARGV_TEMPLATE_MISMATCH"


def test_env_shell_dispatch_template_requires_l3_shell_execution():
    with pytest.raises(ValueError, match="shell_execution"):
        ActionDefinition(
            "fixture.env-shell",
            RiskLevel.L0,
            uses_external_tool=True,
            executable="/usr/bin/env",
            argv_template=("/usr/bin/env", "sh", "-c", "{target}"),
        )


def test_no_tool_action_requires_empty_argv(engine, context, action_request):
    valid = engine.evaluate(action_request, context)
    assert valid.kind is DecisionKind.ALLOW

    invalid = engine.evaluate(replace(action_request, argv=("/bin/sh",)), context)
    assert invalid.reason_code == "DENY_NO_TOOL_ARGV"


def test_vulnerability_and_impact_restrictions_use_code_owned_classifications(
    engine, context, action_request
):
    trusted_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l0-network",
                    RiskLevel.L0,
                    network_access=True,
                    vulnerability_types=("xss",),
                    impacts=("availability",),
                )
            ]
        )
    )
    vulnerability_denied = trusted_engine.evaluate(
        action_request,
        _context(context, prohibited_vulnerability_types=("xss",)),
    )
    assert vulnerability_denied.reason_code == "DENY_PROGRAM_PROHIBITED_VULNERABILITY_TYPE"

    impact_denied = trusted_engine.evaluate(
        action_request,
        _context(context, excluded_impacts=("availability",)),
    )
    assert impact_denied.reason_code == "DENY_PROGRAM_EXCLUDED_IMPACT"

    unspecified_vulnerability = engine.evaluate(
        action_request,
        _context(context, prohibited_vulnerability_types=("xss",)),
    )
    assert unspecified_vulnerability.reason_code == "DENY_PROGRAM_VULNERABILITY_TYPE_UNSPECIFIED"

    unspecified_impact = engine.evaluate(
        action_request,
        _context(context, excluded_impacts=("availability",)),
    )
    assert unspecified_impact.reason_code == "DENY_PROGRAM_IMPACT_UNSPECIFIED"


def test_required_program_headers_are_a_subset_of_request_declared_names(
    engine, context, action_request
):
    denied = engine.evaluate(action_request, _context(context, required_headers=("x-research-id",)))
    assert denied.reason_code == "DENY_PROGRAM_REQUIRED_HEADERS_UNSUPPORTED"

    request_declaration_does_not_authorize = engine.evaluate(
        replace(action_request, required_headers=("X-Research-ID", "X-Optional")),
        _context(context, required_headers=("x-research-id",)),
    )
    assert (
        request_declaration_does_not_authorize.reason_code
        == "DENY_PROGRAM_REQUIRED_HEADERS_UNSUPPORTED"
    )


def test_required_program_headers_need_code_owned_adapter_capability(context, action_request):
    headers_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l0-network",
                    RiskLevel.L0,
                    network_access=True,
                    honors_required_headers=True,
                )
            ]
        )
    )
    decision = headers_engine.evaluate(
        action_request,
        _context(context, required_headers=("x-research-id",)),
    )
    assert decision.kind is DecisionKind.ALLOW


@pytest.mark.parametrize(
    ("field", "permission", "reason_code"),
    [
        ("automated", "automated_scanning_allowed", "DENY_PROGRAM_AUTOMATED_NOT_ALLOWED"),
        (
            "authenticated",
            "authenticated_testing_allowed",
            "DENY_PROGRAM_AUTHENTICATED_NOT_ALLOWED",
        ),
        (
            "creates_account",
            "account_creation_allowed",
            "DENY_PROGRAM_ACCOUNT_CREATION_NOT_ALLOWED",
        ),
        (
            "uses_multiple_accounts",
            "multiple_accounts_allowed",
            "DENY_PROGRAM_MULTIPLE_ACCOUNTS_NOT_ALLOWED",
        ),
        ("out_of_band", "out_of_band_testing_allowed", "DENY_PROGRAM_OUT_OF_BAND_NOT_ALLOWED"),
    ],
)
def test_applicable_program_permissions_deny_l2_actions(
    context, action_request, field, permission, reason_code
):
    permissions = {permission: False}
    permission_context = _context(context, **permissions)
    definition = ActionDefinition(
        "fixture.l2",
        RiskLevel.L1,
        network_access=True,
        state_changing=True,
        **{field: True},
    )
    permission_engine = RiskEngine(ActionRegistry([definition]))
    decision = permission_engine.evaluate(
        replace(action_request, action_id="fixture.l2"), permission_context, grant=object()
    )
    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == reason_code


def test_source_ip_requirements_fail_closed_without_a_trusted_runtime_fact(
    engine, context, action_request
):
    decision = engine.evaluate(
        action_request,
        _context(context, source_ip_requirements=("office-ip",)),
    )
    assert decision.reason_code == "DENY_PROGRAM_SOURCE_IP_UNVERIFIED"


def test_unverified_source_ip_precedes_other_program_permission_denials(context, action_request):
    constrained_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l2",
                    RiskLevel.L2,
                    network_access=True,
                    automated=True,
                )
            ]
        )
    )
    decision = constrained_engine.evaluate(
        replace(action_request, action_id="fixture.l2"),
        _context(
            context,
            automated_scanning_allowed=False,
            source_ip_requirements=("office-ip",),
        ),
    )
    assert decision.reason_code == "DENY_PROGRAM_SOURCE_IP_UNVERIFIED"


def test_shell_execution_definition_is_absolute_l3(context, action_request):
    shell_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l0-network",
                    RiskLevel.L0,
                    network_access=True,
                    uses_external_tool=True,
                    executable="/bin/sh",
                    argv_template=("/bin/sh",),
                    shell_execution=True,
                )
            ]
        )
    )
    decision = shell_engine.evaluate(action_request, context, grant=object())
    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_PROHIBITED"


def test_automated_l0_action_is_elevated_and_cannot_bypass_permission(context, action_request):
    automated_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l0-network",
                    RiskLevel.L0,
                    network_access=True,
                    low_impact_allowlisted=True,
                    automated=True,
                )
            ]
        )
    )
    denied = automated_engine.evaluate(action_request, context)
    assert denied.reason_code == "DENY_PROGRAM_AUTOMATED_NOT_ALLOWED"

    allowed = automated_engine.evaluate(
        action_request,
        _context(context, automated_scanning_allowed=True),
    )
    assert allowed.kind is DecisionKind.ALLOW
    assert allowed.effective_risk is RiskLevel.L1


def test_out_of_band_l0_action_is_elevated_to_l2_and_still_requires_approval(
    context, action_request
):
    out_of_band_engine = RiskEngine(
        ActionRegistry(
            [
                ActionDefinition(
                    "fixture.l0-network",
                    RiskLevel.L0,
                    network_access=True,
                    out_of_band=True,
                )
            ]
        )
    )
    permission_denied = out_of_band_engine.evaluate(action_request, context, grant=object())
    assert permission_denied.reason_code == "DENY_PROGRAM_OUT_OF_BAND_NOT_ALLOWED"

    approval = out_of_band_engine.evaluate(
        action_request,
        _context(context, out_of_band_testing_allowed=True),
        now=datetime(2026, 7, 24, 12, 0, tzinfo=UTC),
    )
    assert approval.kind is DecisionKind.REQUIRES_APPROVAL
    assert approval.effective_risk is RiskLevel.L2


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
