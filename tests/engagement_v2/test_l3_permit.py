"""Canonical signed ExecutionPermitV2 authority and binding tests."""

from __future__ import annotations

import copy
import hashlib
import importlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType

import pytest

from hackbot.engagement_v2.canonical import canonical_bytes
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.l3_contracts import activate_catalog, decide_l3
from hackbot.engagement_v2.loader import EngagementSnapshot
from hackbot.engagement_v2.manifest import CAPABILITY_TO_FIELD
from hackbot.engagement_v2.policy import DecisionKind, PolicyDecision

from ._ed25519_sign import public_key, sign
from ._engagement_builders import program_doc, scope_doc

_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_NOW = datetime(2026, 8, 4, 12, 0, 30, tzinfo=UTC)
_ISSUED = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)
_RUN_ID = "11111111-1111-4111-8111-111111111111"
_EXPECTED_FIELDS = frozenset(
    {
        "schema_version",
        "engagement_id",
        "authority_digest",
        "snapshot_identity",
        "profile",
        "action_id",
        "action_definition_digest",
        "runner_identity",
        "runner_helper_digest",
        "image_reference",
        "image_digest",
        "input_digest",
        "resolved_endpoints",
        "network_rules",
        "rate_policy",
        "required_privileges",
        "evidence_schema",
        "run_id",
        "nonce",
        "issued_at",
        "expires_at",
    }
)
_TRUST_FIELDS = frozenset(
    {
        "action_definition_digest",
        "runner_identity",
        "runner_helper_digest",
        "image_reference",
        "image_digest",
    }
)


def _fingerprint(public_key_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_key_bytes).hexdigest()


def _snapshot() -> EngagementSnapshot:
    program = program_doc()
    program["profile"] = "local-lab"
    rules = program["testing_rules"]
    for capability, field in CAPABILITY_TO_FIELD.items():
        rules[field] = capability in {"payload-execution", "state-changing"}
    authority_digest = "sha256:" + "a" * 64
    return EngagementSnapshot(
        program=MappingProxyType(program),
        scope=MappingProxyType(scope_doc()),
        authorization=MappingProxyType(
            {
                "confirmed": True,
                "confirmed_authority_digest": authority_digest,
            }
        ),
        runner=None,
        profile="local-lab",
        authority_digest=authority_digest,
        identity="engagement-v2:synthetic-authority",
    )


def _request() -> dict[str, object]:
    return {
        "schema_version": 2,
        "action_id": "operator.internal.payload.verify",
        "parameters": {"host": "https://app.corp.example/admin"},
        "hypothesis_id": "synthetic-lab-hypothesis",
        "rationale": "validate the isolated example lab control",
        "expected_impact": "minimal synthetic proof only",
        "stop_condition": "stop after one bounded attempt",
        "cleanup_plan": "run the code-owned cleanup action",
    }


def _authority():
    snapshot = _snapshot()
    activation = activate_catalog(
        snapshot,
        internal_recon_confirmed=True,
        project_root=Path.cwd(),
    )
    request = _request()
    decision = decide_l3(request, snapshot, activation, platform="linux")
    assert decision.kind is DecisionKind.ALLOW
    return snapshot, activation, request, decision


def _context(*, lifetime_seconds: int = 300):
    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    snapshot, activation, request, decision = _authority()
    contract = activation.actions["operator.internal.payload.verify"]
    return permit_module.ExecutionPermitContext(
        snapshot=snapshot,
        activation=activation,
        decision=decision,
        request=MappingProxyType(request),
        platform="linux",
        engagement_id="engv2.synthetic",
        runner_identity="kali.node",
        runner_helper_digest="sha256:" + "b" * 64,
        image_reference="registry.example/hackbot/payload-proof@sha256:" + "c" * 64,
        image_digest="sha256:" + "c" * 64,
        typed_input=MappingProxyType(dict(request["parameters"])),
        resolved_endpoints=(
            MappingProxyType(
                {
                    "role": "proof-target",
                    "hostname": "app.corp.example",
                    "ip": "10.20.0.10",
                    "port": 443,
                    "protocol": "tcp",
                }
            ),
        ),
        network_rules=(
            MappingProxyType(
                {
                    "role": "proof-target",
                    "ip": "10.20.0.10",
                    "port": 443,
                    "protocol": "tcp",
                }
            ),
        ),
        rate_policy=contract.rate_policy,
        required_privileges=contract.action.required_privileges,
        evidence_schema=contract.evidence_schema,
        run_id=_RUN_ID,
        nonce="n" * 43,
        issued_at=_ISSUED,
        expires_at=_ISSUED + timedelta(seconds=lifetime_seconds),
    )


def _build(*, lifetime_seconds: int = 300) -> tuple[dict[str, object], object]:
    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    context = _context(lifetime_seconds=lifetime_seconds)
    return permit_module.build_execution_permit_v2(context), context


def _signed(permit: dict[str, object]) -> bytes:
    message = canonical_bytes({"contract": "hackbot-execution-permit-v2", "permit": permit})
    return sign(_SEED, message)


def _verify(permit: dict[str, object], context: object, *, now: datetime = _NOW) -> None:
    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    permit_module.verify_execution_permit_v2(
        permit,
        _signed(permit),
        public_key(_SEED),
        pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
        context=context,
        now=now,
    )


def test_builds_exact_21_field_permit_from_bound_authority() -> None:
    """Catch a partial permit or a caller-controlled definition identity."""

    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    assert callable(getattr(permit_module, "build_execution_permit_v2", None))
    permit, context = _build()
    contract = context.activation.actions["operator.internal.payload.verify"]

    assert set(permit) == _EXPECTED_FIELDS
    assert permit["schema_version"] == 2
    assert permit["authority_digest"] == context.snapshot.authority_digest
    assert permit["snapshot_identity"] == context.snapshot.identity
    assert permit["profile"] == context.snapshot.profile
    assert permit["action_definition_digest"] == contract.definition_digest
    _verify(permit, context)


def test_signer_receives_only_the_v2_domain_separated_canonical_body() -> None:
    """Catch signing under the v1 domain or over a noncanonical envelope."""

    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    permit, _context_value = _build()
    messages: list[bytes] = []

    def signer(message: bytes) -> bytes:
        messages.append(message)
        return sign(_SEED, message)

    signature = permit_module.sign_execution_permit_v2(permit, signer)
    assert signature == _signed(permit)
    assert messages == [
        canonical_bytes({"contract": "hackbot-execution-permit-v2", "permit": permit})
    ]


@pytest.mark.parametrize("lifetime_seconds", [1, 300])
def test_lifetime_boundaries_verify(lifetime_seconds: int) -> None:
    permit, context = _build(lifetime_seconds=lifetime_seconds)
    _verify(permit, context, now=_ISSUED)


@pytest.mark.parametrize("lifetime_seconds", [0, 301])
def test_invalid_lifetime_denies(lifetime_seconds: int) -> None:
    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    with pytest.raises(ContractError) as excinfo:
        permit_module.build_execution_permit_v2(_context(lifetime_seconds=lifetime_seconds))
    assert excinfo.value.reason_code is ReasonCode.EXEC_PROTOCOL_EXPIRED


@pytest.mark.parametrize(
    ("now", "reason"),
    [
        (_ISSUED - timedelta(seconds=1), ReasonCode.EXEC_PROTOCOL_EXPIRED),
        (_ISSUED + timedelta(seconds=300), ReasonCode.EXEC_PROTOCOL_EXPIRED),
    ],
)
def test_expired_or_not_yet_valid_denies(now: datetime, reason: ReasonCode) -> None:
    permit, context = _build()
    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    with pytest.raises(ContractError) as excinfo:
        permit_module.verify_execution_permit_v2(
            permit,
            _signed(permit),
            public_key(_SEED),
            pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
            context=context,
            now=now,
        )
    assert excinfo.value.reason_code is reason


@pytest.mark.parametrize("shape", ["missing", "unknown"])
def test_unknown_or_missing_field_denies_protocol(shape: str) -> None:
    permit, context = _build()
    if shape == "missing":
        permit.pop("input_digest")
    else:
        permit["operator_field"] = "forbidden"
    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    with pytest.raises(ContractError) as excinfo:
        permit_module.verify_execution_permit_v2(
            permit,
            _signed(permit),
            public_key(_SEED),
            pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
            context=context,
            now=_NOW,
        )
    assert excinfo.value.reason_code is ReasonCode.EXEC_PROTOCOL_INVALID


def test_wrong_signer_and_tampered_signature_deny() -> None:
    permit, context = _build()
    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    with pytest.raises(ContractError) as signer_exc:
        permit_module.verify_execution_permit_v2(
            permit,
            _signed(permit),
            public_key(_SEED),
            pinned_signer_fingerprint="sha256:" + "0" * 64,
            context=context,
            now=_NOW,
        )
    assert signer_exc.value.reason_code is ReasonCode.EXEC_TRUST_MISMATCH

    signature = bytearray(_signed(permit))
    signature[0] ^= 1
    with pytest.raises(ContractError) as signature_exc:
        permit_module.verify_execution_permit_v2(
            permit,
            bytes(signature),
            public_key(_SEED),
            pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
            context=context,
            now=_NOW,
        )
    assert signature_exc.value.reason_code is ReasonCode.EXEC_PROTOCOL_INVALID


def _different(field: str, value: object) -> object:
    if field == "schema_version":
        return 3
    if field == "issued_at":
        return "2026-08-04T12:00:31Z"
    if field == "expires_at":
        return "2026-08-04T12:00:00Z"
    if isinstance(value, str):
        return value + ".changed"
    if isinstance(value, list):
        changed = copy.deepcopy(value)
        changed.append("changed")
        return changed
    if isinstance(value, dict):
        changed = copy.deepcopy(value)
        changed["changed"] = True
        return changed
    raise AssertionError(field)


@pytest.mark.parametrize("field", sorted(_EXPECTED_FIELDS))
def test_each_permit_binding_mismatch_denies(field: str) -> None:
    """Catch omission of any one exact verification binding."""

    permit, context = _build()
    permit[field] = _different(field, permit[field])
    expected_reason = ReasonCode.EXEC_PROTOCOL_INVALID
    if field in _TRUST_FIELDS:
        expected_reason = ReasonCode.EXEC_TRUST_MISMATCH
    elif field == "required_privileges":
        expected_reason = ReasonCode.EXEC_PRIVILEGE_MISMATCH
    elif field in {"issued_at", "expires_at"}:
        expected_reason = ReasonCode.EXEC_PROTOCOL_EXPIRED

    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    with pytest.raises(ContractError) as excinfo:
        permit_module.verify_execution_permit_v2(
            permit,
            _signed(permit),
            public_key(_SEED),
            pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
            context=context,
            now=_NOW,
        )
    assert excinfo.value.reason_code is expected_reason


def test_permit_requires_the_recomputed_allow_decision_and_same_snapshot() -> None:
    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    context = _context()
    denied = replace(
        context,
        decision=PolicyDecision(
            DecisionKind.DENY,
            ReasonCode.DENY_POLICY_LIMIT.value,
            "L3",
        ),
    )
    with pytest.raises(ContractError) as decision_exc:
        permit_module.build_execution_permit_v2(denied)
    assert decision_exc.value.reason_code is ReasonCode.EXEC_PROTOCOL_INVALID

    stale = replace(
        context,
        snapshot=replace(context.snapshot, authority_digest="sha256:" + "f" * 64),
    )
    with pytest.raises(ContractError) as stale_exc:
        permit_module.build_execution_permit_v2(stale)
    assert stale_exc.value.reason_code is ReasonCode.DENY_AUTHORIZATION_STALE


def test_signer_must_return_exact_ed25519_signature_bytes() -> None:
    permit_module = importlib.import_module("hackbot.engagement_v2.remote_permit")
    permit, _context_value = _build()
    for bad in (b"short", "not-bytes"):
        with pytest.raises(ContractError) as excinfo:
            permit_module.sign_execution_permit_v2(permit, lambda _message, bad=bad: bad)
        assert excinfo.value.reason_code is ReasonCode.EXEC_PROTOCOL_INVALID
