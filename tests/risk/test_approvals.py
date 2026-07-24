"""Canonical L2 challenge and single-use approval-store tests."""

from __future__ import annotations

import json
import os
import shutil
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
from hackbot.risk.models import ActionDefinition, ActionRequest, ApprovalGrant, RiskLevel


class SimulatedCrash(BaseException):
    """Model process death without letting production exception handlers run."""


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


@pytest.mark.parametrize(
    "field",
    (
        "rationale",
        "hypothesis_id",
        "expected_impact",
        "stop_condition",
        "cleanup_plan",
        "program_rule",
    ),
)
def test_challenge_rejects_secret_bearing_review_text(
    definition, action_request, context, fixed_now, field
):
    with pytest.raises(ApprovalError, match="secret"):
        build_challenge(
            definition,
            replace(
                action_request,
                **{field: "Use Authorization: Bearer top-secret-value"},
            ),
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


def test_status_recovers_interrupted_transition_without_dual_state(
    store, challenge, fixed_now, issue
):
    issue(store)
    store.grant(challenge, approved_by="operator", now=fixed_now)
    granted = Path(store.root) / "granted" / f"{challenge.challenge_digest}.json"
    consumed = Path(store.root) / "consumed" / granted.name
    shutil.copyfile(granted, consumed)
    consumed.chmod(0o600)
    journal = Path(store.root) / "transactions" / f"{challenge.challenge_digest}.json.json"
    journal.write_bytes(
        canonical_bytes(
            {
                "version": 1,
                "source": "granted",
                "destination": "consumed",
                "challenge_digest": challenge.challenge_digest,
            }
        )
    )
    journal.chmod(0o600)
    assert store.status(challenge.challenge_digest) == "consumed"
    assert not granted.exists()


def _state_paths(store: ApprovalStore, digest: str) -> list[Path]:
    name = f"{digest}.json"
    return [
        path
        for state in ("pending", "granted", "consumed", "expired")
        if (path := Path(store.root) / state / name).exists()
    ]


def _audit_events(store: ApprovalStore) -> list[dict[str, object]]:
    path = Path(store.root) / "events.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_store_keeps_descriptor_owned_root_across_ancestor_symlink_swap(
    store, challenge, fixed_now, issue, tmp_path
):
    issue(store)
    engagement = Path(challenge.engagement_path)
    detached = engagement.with_name(f"{engagement.name}-detached")
    external = tmp_path / "external-engagement"
    external.mkdir()
    engagement.rename(detached)
    engagement.symlink_to(external, target_is_directory=True)

    grant = store.grant(challenge, approved_by="operator", now=fixed_now)

    name = f"{challenge.challenge_digest}.json"
    assert grant.challenge_digest == challenge.challenge_digest
    assert (detached / "approvals" / "granted" / name).is_file()
    assert not (external / "approvals").exists()


def test_transition_uses_open_state_descriptors_across_directory_swap(
    store, challenge, fixed_now, issue, tmp_path, monkeypatch
):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    root = Path(store.root)
    granted_dir = root / "granted"
    detached = root / "granted-detached"
    external = tmp_path / "external-granted"
    external.mkdir()
    swapped = False

    def swap_at_rename(phase: str) -> None:
        nonlocal swapped
        if phase == "before_rename" and not swapped:
            granted_dir.rename(detached)
            granted_dir.symlink_to(external, target_is_directory=True)
            swapped = True

    monkeypatch.setattr(store, "_crash_point", swap_at_rename, raising=False)
    try:
        assert store.consume(grant, challenge, now=fixed_now).status == "consumed"
    finally:
        if swapped:
            granted_dir.unlink()
            detached.rename(granted_dir)

    assert not list(external.iterdir())
    assert store.status(challenge.challenge_digest) == "consumed"


def test_read_to_rename_source_replacement_is_rejected(
    store, challenge, fixed_now, issue, monkeypatch
):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    source = Path(store.root) / "granted" / f"{challenge.challenge_digest}.json"
    displaced = source.with_suffix(".displaced")
    replaced = False

    def replace_at_rename(phase: str) -> None:
        nonlocal replaced
        if phase == "before_rename" and not replaced:
            source.rename(displaced)
            source.write_text('{"kind":"granted","tampered":true}', encoding="utf-8")
            source.chmod(0o600)
            replaced = True

    monkeypatch.setattr(store, "_crash_point", replace_at_rename, raising=False)
    with pytest.raises(ApprovalError, match="changed|tamper|unsafe"):
        store.consume(grant, challenge, now=fixed_now)

    assert replaced
    assert not (Path(store.root) / "consumed" / source.name).exists()


def test_atomic_rename_never_overwrites_a_late_destination(
    store, challenge, fixed_now, issue, monkeypatch
):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    destination = Path(store.root) / "consumed" / f"{challenge.challenge_digest}.json"
    sentinel = b"late-destination"

    def create_late_destination(phase: str) -> None:
        if phase == "after_destination_check" and not destination.exists():
            destination.write_bytes(sentinel)
            destination.chmod(0o600)

    monkeypatch.setattr(store, "_crash_point", create_late_destination)
    with pytest.raises(ApprovalError, match="already|transition"):
        store.consume(grant, challenge, now=fixed_now)

    assert destination.read_bytes() == sentinel


def test_artifact_and_audit_hardlinks_are_rejected(store, challenge, fixed_now, issue, tmp_path):
    pending = issue(store)
    os.link(pending, tmp_path / "pending-hardlink")
    with pytest.raises(ApprovalError, match="malformed|unsafe"):
        store.grant(challenge, approved_by="operator", now=fixed_now)

    pending.unlink()
    (tmp_path / "pending-hardlink").unlink()
    issue(store)
    events = Path(store.root) / "events.jsonl"
    os.link(events, tmp_path / "audit-hardlink")
    with pytest.raises(ApprovalError, match="audit"):
        store.append_event(challenge, result="created", reason_code="CREATED", now=fixed_now)


def test_digest_lock_rejects_symlinks_and_hardlinks(store, challenge, fixed_now, issue, tmp_path):
    issue(store)
    lock = Path(store.root) / "locks" / f"{challenge.challenge_digest}.json.lock"
    outside_lock = tmp_path / "outside-lock"
    outside_lock.touch(mode=0o600)
    lock.unlink()
    lock.symlink_to(outside_lock)
    with pytest.raises(ApprovalError, match="lock"):
        store.grant(challenge, approved_by="operator", now=fixed_now)

    lock.unlink()
    lock.touch(mode=0o600)
    os.link(lock, tmp_path / "lock-hardlink")
    with pytest.raises(ApprovalError, match="lock"):
        store.grant(challenge, approved_by="operator", now=fixed_now)


def test_existing_layout_with_broad_mode_is_rejected(store, challenge, issue):
    issue(store)
    root = Path(store.root)
    root.chmod(0o755)
    with pytest.raises(ApprovalError, match="unsafe"):
        store.status(challenge.challenge_digest)


def test_expired_pending_artifact_has_a_strict_readable_status(store, challenge, fixed_now, issue):
    issue(store)
    with pytest.raises(ApprovalError, match="expired"):
        store.grant(challenge, approved_by="operator", now=challenge.expires_at)
    assert store.status(challenge.challenge_digest) == "expired"
    assert len(_state_paths(store, challenge.challenge_digest)) == 1


def test_grant_consume_and_expire_races_leave_one_terminal_state(
    store, challenge, fixed_now, issue
):
    issue(store)

    def grant_once(at: datetime) -> str:
        try:
            return store.grant(challenge, approved_by="operator", now=at).challenge_digest
        except ApprovalError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        grant_results = list(executor.map(grant_once, (fixed_now, challenge.expires_at)))

    paths = _state_paths(store, challenge.challenge_digest)
    assert len(paths) == 1
    if paths[0].parent.name == "granted":
        artifact = json.loads(paths[0].read_text(encoding="utf-8"))
        persisted_grant = ApprovalGrant(
            challenge_digest=challenge.challenge_digest,
            policy_digest=challenge.policy_digest,
            approved_by=str(artifact["approved_by"]),
            approved_at=datetime.fromisoformat(str(artifact["approved_at"]).replace("Z", "+00:00")),
            expires_at=challenge.expires_at,
        )

        def consume_once(at: datetime) -> str:
            try:
                return store.consume(persisted_grant, challenge, now=at).status
            except ApprovalError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            list(
                executor.map(
                    consume_once,
                    (fixed_now, challenge.expires_at),
                )
            )
        assert len(_state_paths(store, challenge.challenge_digest)) == 1
    assert grant_results


def test_consume_and_expire_race_leaves_one_terminal_state(store, challenge, fixed_now, issue):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)

    def consume_once(at: datetime) -> str:
        try:
            return store.consume(grant, challenge, now=at).status
        except ApprovalError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                consume_once,
                (fixed_now, challenge.expires_at),
            )
        )

    assert len(_state_paths(store, challenge.challenge_digest)) == 1
    assert set(results) & {"consumed", "APPROVAL_CONSUMED", "APPROVAL_EXPIRED"}


@pytest.mark.parametrize(
    ("operation", "phase", "expected_state", "event_result"),
    [
        ("create", "after_wal", "pending", "created"),
        ("create", "after_destination", "pending", "created"),
        ("create", "after_event", "pending", "created"),
        ("create", "after_journal_unlink", "pending", "created"),
        ("grant", "after_wal", "granted", "granted"),
        ("grant", "after_destination", "granted", "granted"),
        ("grant", "after_source_unlink", "granted", "granted"),
        ("grant", "after_event", "granted", "granted"),
        ("grant", "after_journal_unlink", "granted", "granted"),
        ("consume", "after_wal", "consumed", "consumed"),
        ("consume", "after_rename", "consumed", "consumed"),
        ("consume", "after_destination", "consumed", "consumed"),
        ("consume", "after_event", "consumed", "consumed"),
        ("consume", "after_journal_unlink", "consumed", "consumed"),
        ("expire", "after_wal", "expired", "expired"),
        ("expire", "after_rename", "expired", "expired"),
        ("expire", "after_destination", "expired", "expired"),
        ("expire", "after_event", "expired", "expired"),
        ("expire", "after_journal_unlink", "expired", "expired"),
    ],
)
def test_wal_recovery_is_idempotent_at_every_phase(
    store,
    challenge,
    fixed_now,
    issue,
    monkeypatch,
    operation,
    phase,
    expected_state,
    event_result,
):
    grant = None
    if operation in {"grant", "consume", "expire"}:
        issue(store)
    if operation in {"consume", "expire"}:
        grant = store.grant(challenge, approved_by="operator", now=fixed_now)

    def crash(point: str) -> None:
        if point == phase:
            raise SimulatedCrash(point)

    monkeypatch.setattr(store, "_crash_point", crash, raising=False)
    with pytest.raises(SimulatedCrash, match=phase):
        if operation == "create":
            issue(store)
        elif operation == "grant":
            store.grant(challenge, approved_by="operator", now=fixed_now)
        elif operation == "consume":
            assert grant is not None
            store.consume(grant, challenge, now=fixed_now)
        else:
            assert grant is not None
            store.consume(grant, challenge, now=challenge.expires_at)

    monkeypatch.setattr(store, "_crash_point", lambda _phase: None, raising=False)
    assert store.status(challenge.challenge_digest) == expected_state
    assert len(_state_paths(store, challenge.challenge_digest)) == 1
    matching = [
        event
        for event in _audit_events(store)
        if event["challenge_digest"] == challenge.challenge_digest
        and event["result"] == event_result
    ]
    assert len(matching) == 1
    assert not list((Path(store.root) / "transactions").iterdir())


def test_all_local_lifecycle_rejections_are_audited(
    store, definition, action_request, context, fixed_now
):
    def make_challenge(nonce: str):
        return build_challenge(definition, action_request, context, now=fixed_now, nonce=nonce)

    missing = make_challenge("missing")
    with pytest.raises(ApprovalError, match="unavailable"):
        store.grant(missing, approved_by="operator", now=fixed_now)

    invalid_operator = make_challenge("invalid-operator")
    store.create_pending(
        definition, action_request, context, now=fixed_now, nonce="invalid-operator"
    )
    with pytest.raises(ApprovalError, match="operator"):
        store.grant(invalid_operator, approved_by="operator label", now=fixed_now)

    policy_mismatch = make_challenge("policy-mismatch")
    policy_path = store.create_pending(
        definition, action_request, context, now=fixed_now, nonce="policy-mismatch"
    )
    assert policy_path.is_file()
    with pytest.raises(ApprovalError, match="policy"):
        store.grant(
            replace(policy_mismatch, policy_digest="f" * 64),
            approved_by="operator",
            now=fixed_now,
        )

    mismatch = make_challenge("mismatch")
    store.create_pending(definition, action_request, context, now=fixed_now, nonce="mismatch")
    mismatch_grant = store.grant(mismatch, approved_by="operator", now=fixed_now)
    with pytest.raises(ApprovalError, match="grant"):
        store.consume(
            replace(mismatch_grant, approved_by="different"),
            mismatch,
            now=fixed_now,
        )

    tampered = make_challenge("tampered")
    tampered_path = store.create_pending(
        definition, action_request, context, now=fixed_now, nonce="tampered"
    )
    tampered_path.write_text("{}", encoding="utf-8")
    with pytest.raises(ApprovalError, match="malformed"):
        store.grant(tampered, approved_by="operator", now=fixed_now)

    replay = make_challenge("replay")
    store.create_pending(definition, action_request, context, now=fixed_now, nonce="replay")
    replay_grant = store.grant(replay, approved_by="operator", now=fixed_now)
    store.consume(replay_grant, replay, now=fixed_now)
    with pytest.raises(ApprovalError, match="consumed"):
        store.consume(replay_grant, replay, now=fixed_now)

    expired = make_challenge("expired")
    store.create_pending(definition, action_request, context, now=fixed_now, nonce="expired")
    expired_grant = store.grant(expired, approved_by="operator", now=fixed_now)
    with pytest.raises(ApprovalError, match="expired"):
        store.consume(expired_grant, expired, now=expired.expires_at)

    reasons = {str(event["reason_code"]) for event in _audit_events(store)}
    assert {
        "APPROVAL_MISSING",
        "APPROVAL_INVALID_OPERATOR",
        "APPROVAL_POLICY_MISMATCH",
        "APPROVAL_MISMATCH",
        "APPROVAL_MALFORMED",
        "APPROVAL_CONSUMED",
        "APPROVAL_EXPIRED",
    } <= reasons


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
