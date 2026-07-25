"""Digest-only pending reconstruction for the descriptor-owned approval store."""

from datetime import UTC, datetime

import pytest

from hackbot.risk.approvals import ApprovalError, ApprovalStore
from hackbot.risk.context import load_policy_context
from hackbot.risk.fixtures import FIXTURE_ACTIONS
from hackbot.risk.models import ActionRequest


def _l2_request(context) -> ActionRequest:
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id="fixture.intrusive",
        target="https://acme-corp.example/app",
        argv=(),
        hypothesis_id="hyp-1",
        rationale="Validate one authorized hypothesis with a single low-rate probe.",
        rate=1,
        concurrency=1,
        data_touched="Public response headers only.",
        expected_impact="One low-rate intrusive probe against an in-scope asset.",
        stop_condition="Stop on any rate limit, block, or unexpected scope change.",
        cleanup_plan="No state is created; nothing to clean up.",
        program_rule="Authorized intrusive testing rule.",
        required_headers=(),
        requested_risk=None,
    )


def _pending(engagement):
    context = load_policy_context(engagement)
    definition = FIXTURE_ACTIONS.require("fixture.intrusive")
    request = _l2_request(context)
    now = datetime.now(UTC)
    store = ApprovalStore(engagement)
    path = store.create_pending(definition, request, context, now=now)
    digest = path.stem
    return store, context, digest


def test_pending_rebuild_returns_matching_challenge(sample_engagement):
    store, context, digest = _pending(sample_engagement)
    try:
        now = datetime.now(UTC)
        challenge = store.challenge_for_pending(digest, FIXTURE_ACTIONS, context, now=now)
        assert challenge.challenge_digest == digest
        assert challenge.action_id == "fixture.intrusive"
        assert challenge.argv == ()
    finally:
        store.close()


@pytest.mark.parametrize(
    "bad_id",
    ["../escape", "not-a-digest", "0" * 63, "0" * 65, "g" * 64, "/etc/passwd"],
)
def test_pending_rebuild_rejects_non_digest_ids(sample_engagement, bad_id):
    store, context, _digest = _pending(sample_engagement)
    try:
        now = datetime.now(UTC)
        with pytest.raises(ApprovalError):
            store.challenge_for_pending(bad_id, FIXTURE_ACTIONS, context, now=now)
    finally:
        store.close()


def test_pending_rebuild_missing_digest_is_reported(sample_engagement):
    context = load_policy_context(sample_engagement)
    store = ApprovalStore(sample_engagement)
    try:
        now = datetime.now(UTC)
        with pytest.raises(ApprovalError) as excinfo:
            store.challenge_for_pending("0" * 64, FIXTURE_ACTIONS, context, now=now)
        assert excinfo.value.code == "APPROVAL_MISSING"
    finally:
        store.close()


def test_pending_rebuild_after_grant_is_not_pending(sample_engagement):
    store, context, digest = _pending(sample_engagement)
    try:
        now = datetime.now(UTC)
        challenge = store.challenge_for_pending(digest, FIXTURE_ACTIONS, context, now=now)
        store.grant(challenge, approved_by="test-operator", now=now)
        with pytest.raises(ApprovalError) as excinfo:
            store.challenge_for_pending(digest, FIXTURE_ACTIONS, context, now=now)
        assert excinfo.value.code != "APPROVAL_MISSING"
    finally:
        store.close()
