"""Canonical L2 challenge and single-use approval-store tests."""

from __future__ import annotations

import json
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hackbot.risk.approvals import (
    ApprovalError,
    ApprovalStore,
    build_challenge,
    canonical_bytes,
)
from hackbot.risk.context import load_policy_context
from hackbot.risk.models import ActionDefinition, ActionRequest, RiskLevel


@pytest.fixture
def fixed_now() -> datetime:
    return datetime(2026, 7, 24, 12, 0, tzinfo=UTC)


@pytest.fixture
def context(sample_engagement):
    return load_policy_context(sample_engagement, profile="bug-bounty")


@pytest.fixture
def definition() -> ActionDefinition:
    return ActionDefinition(
        "fixture.l2.approval",
        RiskLevel.L2,
        network_access=True,
        high_volume=True,
        uses_external_tool=True,
        executable="/opt/reviewed/probe",
        argv_template=("/opt/reviewed/probe", "--target", "{target}", "--rate", "{rate}"),
        vulnerability_types=("exposure",),
        impacts=("low",),
    )


@pytest.fixture
def action_request(context, definition) -> ActionRequest:
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id=definition.action_id,
        target="https://acme-corp.example/app",
        argv=(
            "/opt/reviewed/probe",
            "--target",
            "https://acme-corp.example/app",
            "--rate",
            "1",
        ),
        hypothesis_id="hyp-approval",
        rationale="Confirm the reviewed high-volume behavior.",
        rate=1,
        concurrency=1,
        data_touched="Public endpoint metadata.",
        expected_impact="Limited authorized probe traffic.",
        stop_condition="Stop immediately on errors.",
        cleanup_plan="No persistent state is created.",
        program_rule="Approved automated testing rule.",
    )


@pytest.fixture
def challenge(definition, action_request, context, fixed_now):
    return build_challenge(definition, action_request, context, now=fixed_now, nonce="abc123")


@pytest.fixture
def store(context):
    return ApprovalStore(context.engagement_path)


@pytest.fixture
def issue(definition, action_request, context, fixed_now):
    def _issue(store: ApprovalStore):
        return store.create_pending(
            definition, action_request, context, now=fixed_now, nonce="abc123"
        )

    return _issue


def test_canonical_bytes_are_deterministic_and_reject_nonfinite_values():
    assert canonical_bytes({"b": ["x"], "a": "é"}) == b'{"a":"\xc3\xa9","b":["x"]}'
    with pytest.raises(ValueError):
        canonical_bytes({"invalid": float("nan")})


def test_challenge_hash_is_deterministic_and_expires_after_exactly_five_minutes(
    definition, action_request, context, fixed_now
):
    first = build_challenge(definition, action_request, context, now=fixed_now, nonce="abc123")
    second = build_challenge(definition, action_request, context, now=fixed_now, nonce="abc123")
    assert first.challenge_digest == second.challenge_digest
    assert first.expires_at - first.created_at == timedelta(minutes=5)


@pytest.mark.parametrize(
    ("changed", "value"),
    [
        ("target", "https://acme-corp.example/other"),
        ("rate", 2),
        ("program_rule", "Different authorizing rule."),
    ],
)
def test_challenge_binds_request_fields(
    definition, action_request, context, fixed_now, changed, value
):
    base = build_challenge(definition, action_request, context, now=fixed_now, nonce="abc123")
    changes = {changed: value}
    if changed == "target":
        changes["argv"] = (
            "/opt/reviewed/probe",
            "--target",
            value,
            "--rate",
            "1",
        )
    if changed == "rate":
        changes["argv"] = (
            "/opt/reviewed/probe",
            "--target",
            action_request.target,
            "--rate",
            "2",
        )
    altered = build_challenge(
        definition, replace(action_request, **changes), context, now=fixed_now, nonce="abc123"
    )
    assert altered.challenge_digest != base.challenge_digest


def test_challenge_binds_policy_scope_identity_and_definition_metadata(
    definition, action_request, context, fixed_now
):
    base = build_challenge(definition, action_request, context, now=fixed_now, nonce="abc123")
    with pytest.raises(ApprovalError, match="policy context"):
        build_challenge(
            definition,
            action_request,
            replace(context, policy_digest="f" * 64),
            now=fixed_now,
            nonce="abc123",
        )
    changed_definition = build_challenge(
        replace(definition, impacts=("medium",)),
        action_request,
        context,
        now=fixed_now,
        nonce="abc123",
    )
    assert changed_definition.challenge_digest != base.challenge_digest


@pytest.mark.parametrize(
    "clock",
    [datetime(2026, 7, 24, 12, 0), datetime(2026, 7, 24, 12, 0, tzinfo=UTC).astimezone()],
)
def test_challenge_rejects_non_utc_or_naive_clock(definition, action_request, context, clock):
    with pytest.raises(ApprovalError, match="UTC"):
        build_challenge(definition, action_request, context, now=clock, nonce="abc123")


@pytest.mark.parametrize("nonce", ["", "x" * 129, "contains space"])
def test_challenge_rejects_unbounded_or_noncanonical_nonce(
    definition, action_request, context, fixed_now, nonce
):
    with pytest.raises(ApprovalError, match="nonce"):
        build_challenge(definition, action_request, context, now=fixed_now, nonce=nonce)


def test_challenge_requires_definition_argv_template_match(
    definition, action_request, context, fixed_now
):
    with pytest.raises(ApprovalError, match="argv"):
        build_challenge(
            definition,
            replace(action_request, argv=("/opt/reviewed/probe", "--unsafe")),
            context,
            now=fixed_now,
            nonce="abc123",
        )


def test_challenge_requires_otherwise_authorized_l2_action(
    definition, action_request, context, fixed_now
):
    with pytest.raises(ApprovalError, match="authorized"):
        build_challenge(
            definition,
            replace(
                action_request,
                target="https://outside.example",
                argv=(
                    "/opt/reviewed/probe",
                    "--target",
                    "https://outside.example",
                    "--rate",
                    "1",
                ),
            ),
            context,
            now=fixed_now,
            nonce="abc123",
        )


def test_challenge_rejects_secret_bearing_review_text(
    definition, action_request, context, fixed_now
):
    with pytest.raises(ApprovalError, match="secret"):
        build_challenge(
            definition,
            replace(action_request, rationale="Use Authorization: Bearer top-secret-value"),
            context,
            now=fixed_now,
            nonce="abc123",
        )


def test_create_pending_requires_trusted_inputs(store, challenge):
    with pytest.raises(ApprovalError, match="trusted"):
        store.create_pending(challenge)


def test_create_pending_is_exclusive_durable_and_secret_free(store, challenge, issue):
    pending = issue(store)
    assert pending.is_file()
    assert stat.S_IMODE(pending.stat().st_mode) == 0o600
    with pytest.raises(ApprovalError, match="already exists"):
        issue(store)
    payload = pending.read_text(encoding="utf-8")
    assert '"approved_by"' not in payload


def test_concurrent_pending_issuance_keeps_the_winner_artifact(
    store, definition, action_request, context, fixed_now, challenge
):
    def create() -> str:
        try:
            store.create_pending(definition, action_request, context, now=fixed_now, nonce="abc123")
            return "created"
        except ApprovalError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: create(), range(8)))
    assert results.count("created") == 1
    assert (Path(store.root) / "pending" / f"{challenge.challenge_digest}.json").is_file()


def test_grant_and_consume_are_single_use_with_exact_expiry_boundary(
    store, challenge, fixed_now, issue
):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    assert (
        store.consume(grant, challenge, now=challenge.expires_at - timedelta(microseconds=1)).status
        == "consumed"
    )
    with pytest.raises(ApprovalError, match="already consumed"):
        store.consume(grant, challenge, now=fixed_now)


def test_expiry_at_exact_boundary_moves_grant_to_expired(store, challenge, fixed_now, issue):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    with pytest.raises(ApprovalError, match="expired"):
        store.consume(grant, challenge, now=challenge.expires_at)
    assert store.status(challenge.challenge_digest) == "expired"


def test_grant_rejects_timestamp_before_challenge_creation(store, challenge, fixed_now, issue):
    issue(store)
    with pytest.raises(ApprovalError, match="before"):
        store.grant(
            challenge,
            approved_by="operator",
            now=fixed_now - timedelta(microseconds=1),
        )


def test_concurrent_consumers_have_exactly_one_success(store, challenge, fixed_now, issue):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)

    def consume_once() -> str:
        try:
            return store.consume(grant, challenge, now=fixed_now).status
        except ApprovalError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: consume_once(), range(8)))
    assert results.count("consumed") == 1
    assert len(results) - results.count("consumed") == 7


def test_tampered_or_unknown_or_duplicate_json_artifacts_fail_closed(
    store, challenge, fixed_now, issue
):
    pending = issue(store)
    pending.write_text('{"kind":"pending","kind":"pending"}', encoding="utf-8")
    with pytest.raises(ApprovalError, match="malformed"):
        store.grant(challenge, approved_by="operator", now=fixed_now)

    pending.unlink()
    pending.write_text('{"kind":"pending","unknown":true}', encoding="utf-8")
    with pytest.raises(ApprovalError, match="malformed"):
        store.grant(challenge, approved_by="operator", now=fixed_now)


def test_grant_rejects_policy_or_challenge_mismatch(store, challenge, fixed_now, issue):
    issue(store)
    with pytest.raises(ApprovalError, match="policy"):
        store.grant(
            replace(challenge, policy_digest="a" * 64), approved_by="operator", now=fixed_now
        )
    with pytest.raises(ApprovalError, match="challenge"):
        store.grant(
            replace(challenge, target="https://acme-corp.example/other"),
            approved_by="operator",
            now=fixed_now,
        )


def test_store_rejects_symlinked_paths_and_non_local_engagement(
    store, challenge, context, tmp_path, definition, action_request, fixed_now
):
    external = tmp_path / "external"
    external.mkdir()
    approvals = Path(context.engagement_path) / "approvals"
    approvals.symlink_to(external, target_is_directory=True)
    with pytest.raises(ApprovalError, match="symlink"):
        store.create_pending(definition, action_request, context, now=fixed_now, nonce="abc123")

    with pytest.raises(ApprovalError, match="engagement"):
        ApprovalStore(tmp_path).create_pending(
            definition, action_request, context, now=fixed_now, nonce="abc123"
        )


def test_corrupt_or_oversized_artifact_is_rejected(store, challenge, fixed_now, issue):
    pending = issue(store)
    pending.write_bytes(b"{" + b"x" * 200_000)
    with pytest.raises(ApprovalError, match="malformed"):
        store.grant(challenge, approved_by="operator", now=fixed_now)


def test_status_rejects_malformed_artifact(store, challenge, issue):
    pending = issue(store)
    pending.write_text("{}", encoding="utf-8")
    with pytest.raises(ApprovalError, match="malformed"):
        store.status(challenge.challenge_digest)


def test_status_rejects_wrong_artifact_mode(store, challenge, issue):
    pending = issue(store)
    pending.chmod(0o644)
    with pytest.raises(ApprovalError, match="malformed"):
        store.status(challenge.challenge_digest)


def test_append_event_has_only_strict_safe_fields_and_mode(store, challenge, fixed_now, issue):
    issue(store)
    store.append_event(challenge, result="created", reason_code="CREATED", now=fixed_now)
    event_path = Path(store.root) / "events.jsonl"
    assert stat.S_IMODE(event_path.stat().st_mode) == 0o600
    event = json.loads(event_path.read_text(encoding="utf-8").splitlines()[-1])
    assert set(event) == {
        "action_id",
        "challenge_digest",
        "effective_risk",
        "engagement_id",
        "reason_code",
        "result",
        "timestamp",
    }
    assert "target" not in event
    assert "argv" not in event


def test_append_event_rejects_symlink(store, challenge, fixed_now, tmp_path, issue):
    issue(store)
    event_path = Path(store.root) / "events.jsonl"
    event_path.unlink()
    event_path.symlink_to(tmp_path / "outside-events.jsonl")
    with pytest.raises(ApprovalError, match="audit"):
        store.append_event(challenge, result="created", reason_code="CREATED", now=fixed_now)


def test_write_failure_creates_no_partial_success_record(store, issue, monkeypatch):
    import hackbot.risk.approvals as approvals

    def fail_write(_fd: int, _payload: bytes) -> int:
        raise OSError("simulated write failure")

    monkeypatch.setattr(approvals.os, "write", fail_write)
    with pytest.raises(ApprovalError, match="write"):
        issue(store)
    assert not list((Path(store.root) / "pending").glob("*"))
