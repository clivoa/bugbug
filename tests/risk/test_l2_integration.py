"""End-to-end policy integration for exact, single-use L2 approvals."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from shutil import copytree

import pytest

from hackbot.risk.approvals import ApprovalStore
from hackbot.risk.context import load_policy_context
from hackbot.risk.models import (
    ActionDefinition,
    ActionRequest,
    ApprovalGrant,
    DecisionKind,
    RiskLevel,
)
from hackbot.risk.policy import RiskEngine
from hackbot.risk.registry import ActionRegistry


@pytest.fixture
def fixed_now() -> datetime:
    return datetime(2026, 7, 24, 12, 0, tzinfo=UTC)


@pytest.fixture
def context(sample_engagement):
    return load_policy_context(sample_engagement, profile="bug-bounty")


@pytest.fixture
def definition() -> ActionDefinition:
    return ActionDefinition(
        "fixture.l2.integration",
        RiskLevel.L2,
        network_access=True,
        high_volume=True,
        uses_external_tool=True,
        executable="/opt/reviewed/probe",
        argv_template=(
            "/opt/reviewed/probe",
            "--target",
            "{target}",
            "--rate",
            "{rate}",
            "--concurrency",
            "{concurrency}",
        ),
        vulnerability_types=("exposure",),
        impacts=("low",),
    )


@pytest.fixture
def l2_request(context, definition) -> ActionRequest:
    return _request(context, definition)


@pytest.fixture
def store(context):
    with ApprovalStore(context.engagement_path) as approval_store:
        yield approval_store


@pytest.fixture
def engine(definition, store):
    return RiskEngine(ActionRegistry([definition]), approval_store=store)


def _request(
    context,
    definition,
    *,
    target: str = "https://acme-corp.example/app",
    rate: int = 1,
) -> ActionRequest:
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id=definition.action_id,
        target=target,
        argv=(
            "/opt/reviewed/probe",
            "--target",
            target,
            "--rate",
            str(rate),
            "--concurrency",
            "1",
        ),
        hypothesis_id="hyp-l2-integration",
        rationale="Confirm the reviewed intrusive behavior.",
        rate=rate,
        concurrency=1,
        data_touched="Public endpoint metadata.",
        expected_impact="Limited authorized probe traffic.",
        stop_condition="Stop immediately on errors or rate limiting.",
        cleanup_plan="No persistent state is created.",
        program_rule="Approved testing rule.",
    )


def _grant(engine, store, definition, request, context, fixed_now):
    pending = engine.evaluate(request, context, now=fixed_now)
    assert pending.kind is DecisionKind.REQUIRES_APPROVAL
    assert pending.challenge is not None
    store.create_pending(
        definition,
        request,
        context,
        now=fixed_now,
        nonce=pending.challenge.nonce,
    )
    return store.grant(pending.challenge, approved_by="operator", now=fixed_now)


def _last_audit_reason(store) -> str:
    event_path = Path(store.root) / "events.jsonl"
    return json.loads(event_path.read_text(encoding="utf-8").splitlines()[-1])["reason_code"]


def test_l2_without_grant_returns_complete_challenge(engine, context, l2_request, fixed_now):
    decision = engine.evaluate(l2_request, context, now=fixed_now)

    assert decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert decision.reason_code == "REQUIRES_APPROVAL"
    assert decision.challenge is not None
    assert decision.challenge.argv == l2_request.argv
    assert decision.challenge.target == l2_request.target
    assert decision.challenge.cleanup_plan == l2_request.cleanup_plan
    assert decision.challenge.program_rule == l2_request.program_rule
    assert decision.challenge.policy_digest == context.policy_digest


def test_l2_without_store_still_returns_a_complete_pure_challenge(
    definition, context, l2_request, fixed_now
):
    engine = RiskEngine(ActionRegistry([definition]))

    decision = engine.evaluate(l2_request, context, now=fixed_now)

    assert decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert decision.challenge is not None
    assert decision.challenge.action_id == definition.action_id


def test_l2_without_injected_clock_fails_closed_deterministically(definition, context, l2_request):
    engine = RiskEngine(ActionRegistry([definition]))

    decision = engine.evaluate(l2_request, context)

    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_APPROVAL_INVALID_CLOCK"
    assert decision.challenge is None


def test_exact_grant_allows_once(engine, store, definition, context, l2_request, fixed_now):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)

    allowed = engine.evaluate(l2_request, context, grant=grant, now=fixed_now)
    replay = engine.evaluate(l2_request, context, grant=grant, now=fixed_now)

    assert allowed.kind is DecisionKind.ALLOW
    assert allowed.effective_risk is RiskLevel.L2
    assert replay.kind is DecisionKind.DENY
    assert replay.reason_code == "DENY_APPROVAL_CONSUMED"


@pytest.mark.parametrize("changed_field", ("target", "rate"))
def test_grant_does_not_cover_changed_otherwise_authorized_action(
    changed_field,
    engine,
    store,
    definition,
    context,
    l2_request,
    fixed_now,
):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)
    changed = (
        _request(
            context,
            definition,
            target="https://one.api.acme-corp.example",
        )
        if changed_field == "target"
        else _request(context, definition, rate=2)
    )

    decision = engine.evaluate(changed, context, grant=grant, now=fixed_now)

    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_APPROVAL_MISMATCH"
    assert store.status(grant.challenge_digest) == "granted"
    assert _last_audit_reason(store) == "APPROVAL_MISMATCH"


def test_template_denial_precedes_grant_handling(
    engine, store, definition, context, l2_request, fixed_now
):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)
    changed = replace(l2_request, argv=(*l2_request.argv, "--extra"))

    decision = engine.evaluate(changed, context, grant=grant, now=fixed_now)

    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_ARGV_TEMPLATE_MISMATCH"
    assert store.status(grant.challenge_digest) == "granted"


def test_grant_does_not_cover_a_new_code_owned_template_and_argv(
    engine, store, definition, context, l2_request, fixed_now
):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)
    changed_definition = replace(
        definition,
        argv_template=(*definition.argv_template, "--reviewed-mode"),
    )
    changed_request = replace(l2_request, argv=(*l2_request.argv, "--reviewed-mode"))
    changed_engine = RiskEngine(
        ActionRegistry([changed_definition]),
        approval_store=store,
    )

    decision = changed_engine.evaluate(
        changed_request,
        context,
        grant=grant,
        now=fixed_now,
    )

    assert decision.reason_code == "DENY_APPROVAL_MISMATCH"
    assert store.status(grant.challenge_digest) == "granted"


def test_scope_denial_precedes_grant_handling(
    engine, store, definition, context, l2_request, fixed_now
):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)
    outside = _request(context, definition, target="https://outside.example")

    decision = engine.evaluate(outside, context, grant=grant, now=fixed_now)

    assert decision.reason_code == "DENY_SCOPE"
    assert store.status(grant.challenge_digest) == "granted"


def test_program_denial_precedes_grant_handling(
    engine, store, definition, context, l2_request, fixed_now
):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)
    restricted = replace(
        context,
        testing_policy=replace(
            context.testing_policy,
            prohibited_vulnerability_types=("exposure",),
        ),
    )

    decision = engine.evaluate(l2_request, restricted, grant=grant, now=fixed_now)

    assert decision.reason_code == "DENY_PROGRAM_PROHIBITED_VULNERABILITY_TYPE"
    assert store.status(grant.challenge_digest) == "granted"


def test_l3_denial_without_authorization(store, context, l2_request, fixed_now):
    """L3 is no longer blanket-denied. It requires confirmed authorization.
    With authorization confirmed (default context), it flows past the L3 gate
    and may be denied by capability or scope gates instead."""
    l3_definition = ActionDefinition(l2_request.action_id, RiskLevel.L3, network_access=True)
    engine = RiskEngine(ActionRegistry([l3_definition]), approval_store=store)
    forged = ApprovalGrant("a" * 64, context.policy_digest, "operator", fixed_now, fixed_now)

    decision = engine.evaluate(l2_request, context, grant=forged, now=fixed_now)

    # L3 now flows through the gate. It'll be denied by scope or capability gates.
    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code != "DENY_PROHIBITED"  # no longer blanket-denied


def test_policy_change_invalidates_grant(
    engine,
    store,
    definition,
    context,
    l2_request,
    fixed_now,
    sample_engagement,
):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)
    changed_context = load_policy_context(sample_engagement, profile="local-lab")

    decision = engine.evaluate(l2_request, changed_context, grant=grant, now=fixed_now)

    assert decision.reason_code == "DENY_APPROVAL_POLICY_MISMATCH"
    assert store.status(grant.challenge_digest) == "granted"
    assert _last_audit_reason(store) == "APPROVAL_POLICY_MISMATCH"


def test_engagement_change_invalidates_grant(
    engine,
    store,
    definition,
    context,
    l2_request,
    fixed_now,
    sample_engagement,
    tmp_path,
):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)
    other_path = tmp_path / "other-engagement"
    copytree(sample_engagement, other_path)
    other_context = load_policy_context(other_path, profile="bug-bounty")
    other_request = _request(other_context, definition)

    decision = engine.evaluate(other_request, other_context, grant=grant, now=fixed_now)

    assert decision.reason_code == "DENY_APPROVAL_ENGAGEMENT_MISMATCH"
    assert store.status(grant.challenge_digest) == "granted"
    assert _last_audit_reason(store) == "APPROVAL_ENGAGEMENT_MISMATCH"


def test_expired_grant_is_denied_and_moved_to_expired(
    engine, store, definition, context, l2_request, fixed_now
):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)

    decision = engine.evaluate(l2_request, context, grant=grant, now=grant.expires_at)

    assert decision.reason_code == "DENY_APPROVAL_EXPIRED"
    assert store.status(grant.challenge_digest) == "expired"


def test_unknown_grant_is_denied_as_missing(engine, context, l2_request, fixed_now):
    unknown = ApprovalGrant(
        "a" * 64,
        context.policy_digest,
        "operator",
        fixed_now,
        fixed_now.replace(minute=4),
    )

    decision = engine.evaluate(l2_request, context, grant=unknown, now=fixed_now)

    assert decision.reason_code == "DENY_APPROVAL_MISSING"


def test_concurrent_engine_consumers_allow_exactly_once(
    engine, store, definition, context, l2_request, fixed_now
):
    grant = _grant(engine, store, definition, l2_request, context, fixed_now)

    def evaluate_once() -> str:
        return engine.evaluate(
            l2_request,
            context,
            grant=grant,
            now=fixed_now,
        ).reason_code

    with ThreadPoolExecutor(max_workers=8) as executor:
        reasons = list(executor.map(lambda _index: evaluate_once(), range(8)))

    assert reasons.count("ALLOW") == 1
    assert reasons.count("DENY_APPROVAL_CONSUMED") == 7


def test_grant_without_bound_store_is_denied(definition, context, l2_request, fixed_now):
    engine = RiskEngine(ActionRegistry([definition]))
    grant = ApprovalGrant(
        "a" * 64,
        context.policy_digest,
        "operator",
        fixed_now,
        fixed_now.replace(minute=4),
    )

    decision = engine.evaluate(l2_request, context, grant=grant, now=fixed_now)

    assert decision.reason_code == "DENY_APPROVAL_STORE_UNAVAILABLE"
