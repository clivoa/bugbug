"""Canonical L2 challenge and single-use approval-store tests."""

from __future__ import annotations

import errno
import hashlib
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
from hackbot.risk.context import (
    _canonical_policy_data,
    _policy_digest,
    _scope_snapshot,
    load_policy_context,
)
from hackbot.risk.models import ActionDefinition, ActionRequest, ApprovalGrant, RiskLevel
from hackbot.risk.policy import RiskEngine
from hackbot.risk.registry import ActionRegistry
from hackbot.scope import Scope


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


def _replace_context(
    context,
    *,
    scope=None,
    program_id=None,
    testing_policy=None,
):
    current_scope = context.scope if scope is None else scope
    current_program_id = context.program_id if program_id is None else program_id
    current_policy = context.testing_policy if testing_policy is None else testing_policy
    scope_in, scope_out = _scope_snapshot(
        current_scope.in_scope,
        current_scope.out_of_scope,
    )
    digest = _policy_digest(
        _canonical_policy_data(
            engagement_id=context.engagement_id,
            engagement_path=context.engagement_path,
            program_id=current_program_id,
            authorization=context.authorization,
            scope_in=scope_in,
            scope_out=scope_out,
            testing_policy=current_policy,
            active_profile=context.active_profile,
        )
    )
    return replace(
        context,
        scope=current_scope,
        program_id=current_program_id,
        testing_policy=current_policy,
        policy_digest=digest,
    )


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


@pytest.mark.parametrize(
    "secret_text",
    (
        "Cookie: sessionid=0123456789abcdef",
        "Set-Cookie: auth_session=0123456789abcdef; Secure",
        "session_id=0123456789abcdef",
        "auth-session-id: 0123456789abcdef",
        "Authorization: Digest username=operator,response=abcdef",
        "Authorization: Negotiate YIIG7QYGKwYBBQUCoIIG4jCCBuKg",
        "Proxy-Authorization: NTLM TlRMTVNTUAABAAA",
        "X-Auth-Token: 0123456789abcdef",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue",
    ),
)
def test_challenge_rejects_common_auth_and_session_secrets_without_echo(
    definition, action_request, context, fixed_now, secret_text
):
    with pytest.raises(ApprovalError) as captured:
        build_challenge(
            definition,
            replace(action_request, rationale=f"review input {secret_text}"),
            context,
            now=fixed_now,
            nonce="abc123",
        )
    assert captured.value.code == "APPROVAL_SECRET"
    assert secret_text not in str(captured.value)


@pytest.mark.parametrize(
    "header_name",
    (
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-auth-token",
    ),
)
def test_challenge_rejects_sensitive_required_header_names(
    definition, action_request, context, fixed_now, header_name
):
    with pytest.raises(ApprovalError) as captured:
        build_challenge(
            definition,
            replace(action_request, required_headers=(header_name,)),
            context,
            now=fixed_now,
            nonce="abc123",
        )
    assert captured.value.code == "APPROVAL_SECRET"
    assert header_name not in str(captured.value)


_PERSISTED_REQUEST_TEXT_FIELDS = (
    "target",
    "argv",
    "hypothesis_id",
    "rationale",
    "data_touched",
    "expected_impact",
    "stop_condition",
    "cleanup_plan",
    "program_rule",
)

_REVIEW_SECRET_VARIANTS = (
    "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZS1vcGVuc3NoLWtleQ==",
    "client_secret=client-value-0123456789",
    "client-secret: client-value-0123456789",
    "config.client.secret = client-value-0123456789",
    "refresh_token=refresh-value-0123456789",
    "access-token: access-value-0123456789",
    "AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF",
    "aws.secret.access.key=aws-value-0123456789",
    "AWS_SECRET_ACCESS_KEY=aws-value-0123456789",
    "DATABASE_URL=postgresql://dbuser:dbpass@db.example/research",
    "postgresql://dbuser:dbpass@db.example/research",
    "GOOGLE_APPLICATION_CREDENTIALS=/tmp/service-account.json",
    "AZURE_CLIENT_SECRET=azure-value-0123456789",
    "AZURE_STORAGE_CONNECTION_STRING=AccountName=fake;AccountKey=fake",
    "GOOGLE_CLOUD_KEYFILE_JSON=/tmp/provider-key.json",
    "GCLOUD_SERVICE_KEY=provider-value-0123456789",
    "DOCKER_AUTH_CONFIG=provider-value-0123456789",
    "OPENAI_API_KEY=provider-value-0123456789",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyZXNlYXJjaGVyIn0.signaturevalue",
)


def _secret_bearing_request(definition, action_request, field, secret_text):
    if field == "target":
        definition = replace(
            definition,
            argv_template=("/opt/reviewed/probe", "--rate", "{rate}"),
        )
        action_request = replace(
            action_request,
            target=secret_text,
            argv=("/opt/reviewed/probe", "--rate", "1"),
        )
    elif field == "argv":
        definition = replace(
            definition,
            argv_template=(*definition.argv_template, secret_text),
        )
        action_request = replace(action_request, argv=(*action_request.argv, secret_text))
    else:
        action_request = replace(action_request, **{field: secret_text})
    return definition, action_request


@pytest.mark.parametrize("field", _PERSISTED_REQUEST_TEXT_FIELDS)
@pytest.mark.parametrize("secret_text", _REVIEW_SECRET_VARIANTS)
def test_challenge_rejects_credential_variants_in_every_persisted_request_text(
    definition,
    action_request,
    context,
    fixed_now,
    field,
    secret_text,
):
    secret_definition, secret_request = _secret_bearing_request(
        definition, action_request, field, secret_text
    )
    with pytest.raises(ApprovalError) as captured:
        build_challenge(
            secret_definition,
            secret_request,
            context,
            now=fixed_now,
            nonce="abc123",
        )
    assert captured.value.code == "APPROVAL_SECRET"
    assert secret_text not in str(captured.value)


@pytest.mark.parametrize(
    "header_name",
    (
        "client-secret",
        "refresh-token",
        "access-token",
        "aws-access-key-id",
        "aws-secret-access-key",
        "database-url",
    ),
)
def test_challenge_rejects_separator_variant_credential_header_names(
    definition, action_request, context, fixed_now, header_name
):
    with pytest.raises(ApprovalError) as captured:
        build_challenge(
            definition,
            replace(action_request, required_headers=(header_name,)),
            context,
            now=fixed_now,
            nonce="abc123",
        )
    assert captured.value.code == "APPROVAL_SECRET"
    assert header_name not in str(captured.value)


@pytest.mark.parametrize(
    "secret_rule",
    (
        "https://dbuser:dbpass@hidden.example/private",
        "https://opaquecredentialvalue@hidden.example/private",
        "https://:passwordonly@hidden.example/private",
        "https://usernameonly:@hidden.example/private",
    ),
)
@pytest.mark.parametrize("scope_side", ("in_scope", "out_of_scope"))
def test_challenge_rejects_url_userinfo_anywhere_in_scope_snapshot_without_echo(
    definition,
    action_request,
    context,
    fixed_now,
    scope_side,
    secret_rule,
):
    in_scope = context.scope.in_scope
    out_of_scope = context.scope.out_of_scope
    if scope_side == "in_scope":
        in_scope = (*in_scope, secret_rule)
    else:
        out_of_scope = (*out_of_scope, secret_rule)
    secret_scope = Scope(in_scope, out_of_scope)
    secret_context = _replace_context(context, scope=secret_scope)

    with pytest.raises(ApprovalError) as captured:
        build_challenge(
            definition,
            action_request,
            secret_context,
            now=fixed_now,
            nonce="abc123",
        )

    assert captured.value.code == "APPROVAL_SECRET"
    assert secret_rule not in str(captured.value)


def test_engine_maps_canonical_scope_secret_to_stable_denial(
    definition,
    action_request,
    context,
    fixed_now,
):
    secret_rule = "https://opaquecredentialvalue@hidden.example/private"
    secret_scope = Scope((*context.scope.in_scope, secret_rule), context.scope.out_of_scope)
    secret_context = _replace_context(context, scope=secret_scope)
    engine = RiskEngine(ActionRegistry([definition]))

    decision = engine.evaluate(action_request, secret_context, now=fixed_now)

    assert decision.reason_code == "DENY_APPROVAL_SECRET"
    assert decision.challenge is None
    assert secret_rule not in decision.explanation


@pytest.mark.parametrize(
    ("source", "secret_value"),
    (
        ("program_id", "client-secret"),
        ("tool_id", "client-secret"),
    ),
)
def test_challenge_rejects_secret_like_text_in_non_request_canonical_metadata(
    definition,
    action_request,
    context,
    fixed_now,
    source,
    secret_value,
):
    current_definition = definition
    current_context = context
    if source == "program_id":
        current_context = _replace_context(context, program_id=secret_value)
    else:
        current_definition = replace(definition, tool_id=secret_value)

    with pytest.raises(ApprovalError) as captured:
        build_challenge(
            current_definition,
            action_request,
            current_context,
            now=fixed_now,
            nonce="abc123",
        )

    assert captured.value.code == "APPROVAL_SECRET"
    assert secret_value not in str(captured.value)


def test_failed_pending_issue_leaves_no_secret_in_files_or_audit(
    store,
    definition,
    action_request,
    context,
    fixed_now,
):
    secret_rule = "https://opaquecredentialvalue@hidden.example/private"
    secret_scope = Scope((*context.scope.in_scope, secret_rule), context.scope.out_of_scope)
    secret_context = _replace_context(context, scope=secret_scope)

    with pytest.raises(ApprovalError) as captured:
        store.create_pending(
            definition,
            action_request,
            secret_context,
            now=fixed_now,
            nonce="abc123",
        )

    assert captured.value.code == "APPROVAL_SECRET"
    approval_root = Path(store.root)
    pending = approval_root / "pending"
    assert not pending.exists() or not tuple(pending.iterdir())
    if approval_root.exists():
        for path in approval_root.rglob("*"):
            if path.is_file():
                assert secret_rule.encode() not in path.read_bytes()


def test_safe_scope_rule_is_still_allowed_in_canonical_binding(
    definition,
    action_request,
    context,
    fixed_now,
):
    safe_rule = "https://hidden.example/private"
    safe_scope = Scope((*context.scope.in_scope, safe_rule), context.scope.out_of_scope)
    safe_context = _replace_context(context, scope=safe_scope)

    challenge = build_challenge(
        definition,
        action_request,
        safe_context,
        now=fixed_now,
        nonce="abc123",
    )

    assert safe_rule.encode() in challenge.binding


@pytest.mark.parametrize(
    "safe_rule",
    (
        "https://hidden.example/private",
        "https://hidden.example/users/operator@example.test",
        "mailto:operator@example.test",
    ),
)
def test_plain_urls_and_email_like_text_do_not_trigger_uri_userinfo_filter(
    definition,
    action_request,
    context,
    fixed_now,
    safe_rule,
):
    safe_scope = Scope((*context.scope.in_scope, safe_rule), context.scope.out_of_scope)
    safe_context = _replace_context(context, scope=safe_scope)

    challenge = build_challenge(
        definition,
        action_request,
        safe_context,
        now=fixed_now,
        nonce="abc123",
    )

    assert safe_rule.encode() in challenge.binding


def test_nonpersisted_policy_text_remains_digest_only(
    definition,
    action_request,
    context,
    fixed_now,
):
    policy_marker = "client-secret"
    policy = replace(
        context.testing_policy,
        prohibited_vulnerability_types=(policy_marker,),
    )
    changed_context = _replace_context(context, testing_policy=policy)

    challenge = build_challenge(
        definition,
        action_request,
        changed_context,
        now=fixed_now,
        nonce="abc123",
    )

    assert policy_marker.encode() not in challenge.binding
    assert challenge.policy_digest == changed_context.policy_digest


def test_build_challenge_converts_expiry_overflow_to_approval_error(
    definition, action_request, context
):
    with pytest.raises(ApprovalError) as captured:
        build_challenge(
            definition,
            action_request,
            context,
            now=datetime.max.replace(tzinfo=UTC),
            nonce="abc123",
        )
    assert captured.value.code == "APPROVAL_INVALID_CLOCK"


def test_build_challenge_converts_nonfinite_canonical_data_to_approval_error(
    definition, action_request, context, fixed_now, monkeypatch
):
    import hackbot.risk.approvals as approvals

    original = approvals._challenge_fields

    def nonfinite_fields(*args, **kwargs):
        fields = original(*args, **kwargs)
        fields["nonfinite"] = float("nan")
        return fields

    monkeypatch.setattr(approvals, "_challenge_fields", nonfinite_fields)
    with pytest.raises(ApprovalError) as captured:
        build_challenge(
            definition,
            action_request,
            context,
            now=fixed_now,
            nonce="abc123",
        )
    assert captured.value.code == "APPROVAL_INVALID_CHALLENGE"


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


def _nonfinite_binding(challenge):
    raw = b'{"request":NaN}'
    return replace(
        challenge,
        binding=raw,
        challenge_digest=hashlib.sha256(raw).hexdigest(),
    )


def test_grant_and_consume_convert_nonfinite_binding_to_approval_error(
    store, challenge, fixed_now, issue
):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    malformed = _nonfinite_binding(challenge)
    with pytest.raises(ApprovalError):
        store.grant(malformed, approved_by="operator", now=fixed_now)
    with pytest.raises(ApprovalError):
        store.consume(grant, malformed, now=fixed_now)


def test_grant_converts_malformed_binding_types_to_approval_error(
    store, challenge, fixed_now, issue
):
    issue(store)
    raw = json.loads(challenge.binding)
    raw["request"]["argv"] = 1
    malformed_raw = canonical_bytes(raw)
    malformed_argv = replace(
        challenge,
        binding=malformed_raw,
        challenge_digest=hashlib.sha256(malformed_raw).hexdigest(),
    )
    with pytest.raises(ApprovalError):
        store.grant(malformed_argv, approved_by="operator", now=fixed_now)

    nonbytes = replace(challenge, challenge_digest=hashlib.sha256(b"{}").hexdigest())
    object.__setattr__(nonbytes, "binding", "{}")
    with pytest.raises(ApprovalError):
        store.grant(nonbytes, approved_by="operator", now=fixed_now)


def test_status_converts_nonfinite_and_overflowing_artifacts_to_approval_error(
    store, challenge, issue
):
    pending = issue(store)
    value = json.loads(pending.read_text(encoding="utf-8"))
    value["challenge"] = {"request": float("nan")}
    pending.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(ApprovalError):
        store.status(challenge.challenge_digest)

    pending.unlink()
    value = json.loads(
        canonical_bytes(
            {
                **ApprovalStore._artifact(challenge, kind="pending"),
            }
        )
    )
    maximum = "9999-12-31T23:59:59.999999Z"
    value["challenge"]["created_at"] = maximum
    value["challenge"]["expires_at"] = maximum
    digest = hashlib.sha256(canonical_bytes(value["challenge"])).hexdigest()
    value["challenge_digest"] = digest
    value["created_at"] = maximum
    value["expires_at"] = maximum
    overflow_path = pending.with_name(f"{digest}.json")
    overflow_path.write_bytes(canonical_bytes(value))
    overflow_path.chmod(0o600)
    with pytest.raises(ApprovalError):
        store.status(digest)


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


def test_missing_native_no_replace_symbol_fails_closed(
    store, challenge, fixed_now, issue, monkeypatch
):
    import hackbot.risk.approvals as approvals

    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    monkeypatch.setattr(approvals.ctypes, "CDLL", lambda *_args, **_kwargs: object())
    with pytest.raises(ApprovalError) as captured:
        store.consume(grant, challenge, now=fixed_now)
    assert captured.value.code in {"APPROVAL_IO", "APPROVAL_UNSAFE_PATH"}
    name = f"{challenge.challenge_digest}.json"
    assert (Path(store.root) / "granted" / name).is_file()
    assert not (Path(store.root) / "consumed" / name).exists()


def test_unsupported_native_no_replace_syscall_fails_closed(
    store, challenge, fixed_now, issue, monkeypatch
):
    import hackbot.risk.approvals as approvals

    class UnsupportedRename:
        argtypes = None
        restype = None

        def __call__(self, *_args) -> int:
            return -1

    class UnsupportedLibrary:
        renameatx_np = UnsupportedRename()
        renameat2 = UnsupportedRename()

    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    monkeypatch.setattr(
        approvals.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: UnsupportedLibrary(),
    )
    monkeypatch.setattr(approvals.ctypes, "get_errno", lambda: errno.ENOSYS)
    with pytest.raises(ApprovalError) as captured:
        store.consume(grant, challenge, now=fixed_now)
    assert captured.value.code in {"APPROVAL_IO", "APPROVAL_UNSAFE_PATH"}
    name = f"{challenge.challenge_digest}.json"
    assert (Path(store.root) / "granted" / name).is_file()
    assert not (Path(store.root) / "consumed" / name).exists()


@pytest.mark.parametrize("failure_step", ("fstat", "stat"))
def test_constructor_closes_engagement_fd_on_post_open_failure(context, monkeypatch, failure_step):
    import hackbot.risk.approvals as approvals

    real_open = approvals.os.open
    real_close = approvals.os.close
    real_fstat = approvals.os.fstat
    real_stat = approvals.os.stat
    opened: list[int] = []
    closed: list[int] = []
    monkeypatch.setattr(
        approvals,
        "canonical_engagement_identity",
        lambda _path: (context.engagement_path, context.engagement_id),
    )

    def record_open(*args, **kwargs) -> int:
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def record_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    def maybe_fail_fstat(fd: int):
        if failure_step == "fstat":
            raise OSError("simulated fstat failure")
        return real_fstat(fd)

    def maybe_fail_stat(*args, **kwargs):
        if failure_step == "stat":
            raise OSError("simulated stat failure")
        return real_stat(*args, **kwargs)

    monkeypatch.setattr(approvals.os, "open", record_open)
    monkeypatch.setattr(approvals.os, "close", record_close)
    monkeypatch.setattr(approvals.os, "fstat", maybe_fail_fstat)
    monkeypatch.setattr(approvals.os, "stat", maybe_fail_stat)
    with pytest.raises(ApprovalError):
        ApprovalStore(context.engagement_path)
    assert opened
    assert set(opened) <= set(closed)


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


def test_first_use_fsyncs_each_new_directory_parent(store, issue, monkeypatch):
    import hackbot.risk.approvals as approvals

    calls: list[tuple[str, object, int | None]] = []
    real_mkdir = approvals.os.mkdir
    real_fsync = approvals.os.fsync

    def record_mkdir(
        path: str,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        calls.append(("mkdir", path, dir_fd))
        real_mkdir(path, mode, dir_fd=dir_fd)

    def record_fsync(fd: int) -> None:
        calls.append(("fsync", fd, None))
        real_fsync(fd)

    monkeypatch.setattr(approvals.os, "mkdir", record_mkdir)
    monkeypatch.setattr(approvals.os, "fsync", record_fsync)
    issue(store)

    mkdir_indexes = [index for index, call in enumerate(calls) if call[0] == "mkdir"]
    assert [calls[index][1] for index in mkdir_indexes] == [
        "approvals",
        "pending",
        "granted",
        "consumed",
        "expired",
        "locks",
        "transactions",
    ]
    for position, index in enumerate(mkdir_indexes):
        next_index = (
            mkdir_indexes[position + 1] if position + 1 < len(mkdir_indexes) else len(calls)
        )
        parent_fd = calls[index][2]
        assert ("fsync", parent_fd, None) in calls[index + 1 : next_index]


@pytest.mark.parametrize(
    ("directory_name", "next_directory", "parent_label"),
    (
        ("approvals", "pending", "engagement"),
        ("pending", "granted", "root"),
    ),
)
def test_directory_parent_fsync_is_retried_after_mkdir_fsync_failure(
    store,
    monkeypatch,
    directory_name,
    next_directory,
    parent_label,
):
    import hackbot.risk.approvals as approvals

    engagement_fd = store._engagement_fd
    assert engagement_fd is not None
    engagement_inode = os.fstat(engagement_fd).st_ino
    root_inode: int | None = None
    events: list[tuple[str, str]] = []
    failed = False
    real_open = approvals.os.open
    real_fsync = approvals.os.fsync

    def record_open(path, *args, **kwargs) -> int:
        nonlocal root_inode
        fd = real_open(path, *args, **kwargs)
        if path == "approvals":
            root_inode = os.fstat(fd).st_ino
        if isinstance(path, str):
            events.append(("open", path))
        return fd

    def parent_name(fd: int) -> str | None:
        inode = os.fstat(fd).st_ino
        if inode == engagement_inode:
            return "engagement"
        if root_inode is not None and inode == root_inode:
            return "root"
        return None

    def fail_first_parent_fsync(fd: int) -> None:
        nonlocal failed
        label = parent_name(fd)
        if label is not None:
            events.append(("fsync", label))
        if not failed and label == parent_label:
            failed = True
            raise OSError("simulated parent fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(approvals.os, "open", record_open)
    monkeypatch.setattr(approvals.os, "fsync", fail_first_parent_fsync)
    with pytest.raises(ApprovalError):
        with store._layout():
            pass
    assert failed

    events.clear()
    with store._layout():
        pass

    opened_index = events.index(("open", directory_name))
    next_opened_index = events.index(("open", next_directory))
    assert ("fsync", parent_label) in events[opened_index + 1 : next_opened_index]


def _crash_after_transition(
    store: ApprovalStore,
    challenge,
    fixed_now: datetime,
    issue,
    monkeypatch,
    operation: str,
) -> tuple[str, str, str]:
    grant = None
    if operation in {"grant", "consume"}:
        issue(store)
    if operation == "consume":
        grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    crash_phase = "after_source_unlink" if operation == "grant" else "after_rename"

    def crash(point: str) -> None:
        if point == crash_phase:
            raise SimulatedCrash(point)

    monkeypatch.setattr(store, "_crash_point", crash)
    with pytest.raises(SimulatedCrash, match=crash_phase):
        if operation == "grant":
            store.grant(challenge, approved_by="operator", now=fixed_now)
        else:
            assert grant is not None
            store.consume(grant, challenge, now=fixed_now)
    monkeypatch.setattr(store, "_crash_point", lambda _phase: None)
    if operation == "grant":
        return "pending", "granted", "granted"
    return "granted", "consumed", "consumed"


@pytest.mark.parametrize("operation", ("grant", "consume"))
def test_recovery_second_crash_during_state_fsync_keeps_wal(
    store, challenge, fixed_now, issue, monkeypatch, operation
):
    import hackbot.risk.approvals as approvals

    source, destination, expected = _crash_after_transition(
        store, challenge, fixed_now, issue, monkeypatch, operation
    )
    root = Path(store.root)
    state_inodes = {
        (root / source).stat().st_ino,
        (root / destination).stat().st_ino,
    }
    journal = root / "transactions" / f"{challenge.challenge_digest}.json.json"
    real_fsync = approvals.os.fsync
    crashed = False

    def crash_state_fsync(fd: int) -> None:
        nonlocal crashed
        if not crashed and os.fstat(fd).st_ino in state_inodes:
            crashed = True
            raise SimulatedCrash("second recovery crash")
        real_fsync(fd)

    monkeypatch.setattr(approvals.os, "fsync", crash_state_fsync)
    with pytest.raises(SimulatedCrash, match="second recovery crash"):
        store.status(challenge.challenge_digest)
    assert journal.is_file()

    monkeypatch.setattr(approvals.os, "fsync", real_fsync)
    assert store.status(challenge.challenge_digest) == expected
    assert len(_state_paths(store, challenge.challenge_digest)) == 1


@pytest.mark.parametrize("operation", ("grant", "consume"))
def test_recovery_fsyncs_both_state_dirs_before_audit_and_wal_removal(
    store, challenge, fixed_now, issue, monkeypatch, operation
):
    import hackbot.risk.approvals as approvals

    source, destination, expected = _crash_after_transition(
        store, challenge, fixed_now, issue, monkeypatch, operation
    )
    root = Path(store.root)
    inode_labels = {
        (root / source).stat().st_ino: source,
        (root / destination).stat().st_ino: destination,
        (root / "transactions").stat().st_ino: "transactions",
        (root / "events.jsonl").stat().st_ino: "audit",
    }
    calls: list[str] = []
    real_fsync = approvals.os.fsync
    real_write = approvals.os.write
    real_unlink = approvals.os.unlink

    def record_fsync(fd: int) -> None:
        label = inode_labels.get(os.fstat(fd).st_ino)
        if label is not None:
            calls.append(f"fsync:{label}")
        real_fsync(fd)

    def record_write(fd: int, payload: bytes | memoryview) -> int:
        if inode_labels.get(os.fstat(fd).st_ino) == "audit":
            calls.append("audit-write")
        return real_write(fd, payload)

    def record_unlink(path: str, *, dir_fd: int | None = None) -> None:
        if dir_fd is not None and inode_labels.get(os.fstat(dir_fd).st_ino) == "transactions":
            calls.append("wal-unlink")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(approvals.os, "fsync", record_fsync)
    monkeypatch.setattr(approvals.os, "write", record_write)
    monkeypatch.setattr(approvals.os, "unlink", record_unlink)

    assert store.status(challenge.challenge_digest) == expected
    audit_index = calls.index("audit-write")
    wal_index = calls.index("wal-unlink")
    assert calls.index(f"fsync:{source}") < audit_index
    assert calls.index(f"fsync:{destination}") < audit_index
    assert audit_index < wal_index


def test_recovery_fsyncs_an_existing_audit_event_before_wal_removal(
    store, challenge, fixed_now, issue, monkeypatch
):
    import hackbot.risk.approvals as approvals

    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)

    def crash_after_write(point: str) -> None:
        if point == "after_event_write":
            raise SimulatedCrash(point)

    monkeypatch.setattr(store, "_crash_point", crash_after_write)
    with pytest.raises(SimulatedCrash, match="after_event_write"):
        store.consume(grant, challenge, now=fixed_now)

    monkeypatch.setattr(store, "_crash_point", lambda _phase: None)
    root = Path(store.root)
    audit_inode = (root / "events.jsonl").stat().st_ino
    transaction_inode = (root / "transactions").stat().st_ino
    calls: list[str] = []
    real_fsync = approvals.os.fsync
    real_unlink = approvals.os.unlink

    def record_fsync(fd: int) -> None:
        if os.fstat(fd).st_ino == audit_inode:
            calls.append("audit-fsync")
        real_fsync(fd)

    def record_unlink(path: str, *, dir_fd: int | None = None) -> None:
        if dir_fd is not None and os.fstat(dir_fd).st_ino == transaction_inode:
            calls.append("wal-unlink")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(approvals.os, "fsync", record_fsync)
    monkeypatch.setattr(approvals.os, "unlink", record_unlink)
    assert store.status(challenge.challenge_digest) == "consumed"
    assert calls.index("audit-fsync") < calls.index("wal-unlink")


@pytest.mark.parametrize(
    ("field", "forged_value"),
    (
        ("result", "created"),
        ("reason_code", "CREATED"),
        ("engagement_id", "f" * 64),
        ("action_id", "forged.action"),
        ("effective_risk", 3),
        ("timestamp", "2026-07-24T12:00:01Z"),
    ),
)
def test_forged_wal_event_semantics_are_rejected_and_safely_audited(
    store,
    challenge,
    fixed_now,
    issue,
    monkeypatch,
    field,
    forged_value,
):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)

    def crash_after_wal(point: str) -> None:
        if point == "after_wal":
            raise SimulatedCrash(point)

    monkeypatch.setattr(store, "_crash_point", crash_after_wal)
    with pytest.raises(SimulatedCrash, match="after_wal"):
        store.consume(grant, challenge, now=fixed_now)

    journal = Path(store.root) / "transactions" / f"{challenge.challenge_digest}.json.json"
    transaction = json.loads(journal.read_text(encoding="utf-8"))
    transaction["event"][field] = forged_value
    journal.write_bytes(canonical_bytes(transaction))
    monkeypatch.setattr(store, "_crash_point", lambda _phase: None)

    with pytest.raises(ApprovalError) as captured:
        store.consume(grant, challenge, now=fixed_now)
    assert captured.value.code == "APPROVAL_MALFORMED"
    rejection = _audit_events(store)[-1]
    assert rejection["reason_code"] == "APPROVAL_MALFORMED"
    assert rejection["engagement_id"] == challenge.engagement_id
    assert rejection["action_id"] == challenge.action_id
    assert set(rejection) == {
        "action_id",
        "challenge_digest",
        "effective_risk",
        "engagement_id",
        "reason_code",
        "result",
        "timestamp",
    }


def test_wal_operation_requires_exact_source_destination_and_artifact_kind(
    store, challenge, fixed_now, issue, monkeypatch
):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)

    def crash_after_wal(point: str) -> None:
        if point == "after_wal":
            raise SimulatedCrash(point)

    monkeypatch.setattr(store, "_crash_point", crash_after_wal)
    with pytest.raises(SimulatedCrash, match="after_wal"):
        store.consume(grant, challenge, now=fixed_now)
    journal = Path(store.root) / "transactions" / f"{challenge.challenge_digest}.json.json"
    transaction = json.loads(journal.read_text(encoding="utf-8"))
    transaction["operation"] = "expire-pending"
    transaction["source"] = "pending"
    transaction["artifact"]["kind"] = "pending"
    transaction["artifact"].pop("approved_at")
    transaction["artifact"].pop("approved_by")
    journal.write_bytes(canonical_bytes(transaction))
    monkeypatch.setattr(store, "_crash_point", lambda _phase: None)

    with pytest.raises(ApprovalError) as captured:
        store.consume(grant, challenge, now=fixed_now)
    assert captured.value.code == "APPROVAL_MALFORMED"


@pytest.mark.parametrize("field", ("operation", "artifact-kind"))
def test_wal_rejects_non_scalar_operation_and_artifact_kind(
    store, challenge, fixed_now, issue, monkeypatch, field
):
    issue(store)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)

    def crash_after_wal(point: str) -> None:
        if point == "after_wal":
            raise SimulatedCrash(point)

    monkeypatch.setattr(store, "_crash_point", crash_after_wal)
    with pytest.raises(SimulatedCrash, match="after_wal"):
        store.consume(grant, challenge, now=fixed_now)
    journal = Path(store.root) / "transactions" / f"{challenge.challenge_digest}.json.json"
    transaction = json.loads(journal.read_text(encoding="utf-8"))
    if field == "operation":
        transaction["operation"] = []
    else:
        transaction["artifact"]["kind"] = []
    journal.write_bytes(canonical_bytes(transaction))
    monkeypatch.setattr(store, "_crash_point", lambda _phase: None)

    with pytest.raises(ApprovalError) as captured:
        store.consume(grant, challenge, now=fixed_now)
    assert captured.value.code == "APPROVAL_MALFORMED"


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
