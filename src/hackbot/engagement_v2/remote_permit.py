"""Ed25519 machine-signed privilege permit verification.

A privileged remote action requires an externally issued permit bound to the
engagement, authority digest, action, runner, executable digest, exact privilege
set, nonce, issue time, and a short expiry. Hackbot only verifies: the permit is
checked against the pinned signer fingerprint, the confirmed authority, and the
request replay tuple. Any mismatch fails closed.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from hackbot.engagement_v2._ed25519 import verify
from hackbot.engagement_v2.canonical import canonical_bytes, digest_value
from hackbot.engagement_v2.constants import (
    ED25519_PUBLIC_KEY_BYTES,
    MAX_REQUEST_LIFETIME_SECONDS,
    MIN_REQUEST_LIFETIME_SECONDS,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.l3_contracts import (
    ActivatedL3Catalog,
    L3ActionContract,
    decide_l3,
)
from hackbot.engagement_v2.loader import EngagementSnapshot
from hackbot.engagement_v2.policy import DecisionKind, PolicyDecision

_PERMIT_DOMAIN = "hackbot-privilege-permit-v1"
_PERMIT_FIELDS = frozenset(
    {
        "engagement_id",
        "authority_digest",
        "action_id",
        "runner_identity",
        "executable_sha256",
        "execution_digest",
        "privileges",
        "run_id",
        "nonce",
        "issued_at",
        "expires_at",
    }
)

_EXECUTION_PERMIT_DOMAIN = "hackbot-execution-permit-v2"
_EXECUTION_INPUT_DOMAIN = "hackbot-l3-input-v1"
_EXECUTION_PERMIT_FIELDS = frozenset(
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
_EXECUTION_TRUST_FIELDS = frozenset(
    {
        "action_definition_digest",
        "runner_identity",
        "runner_helper_digest",
        "image_reference",
        "image_digest",
    }
)
_ED25519_SIGNATURE_BYTES = 64


@dataclass(frozen=True)
class PermitContext:
    engagement_id: str
    authority_digest: str
    action_id: str
    runner_identity: str
    executable_sha256: str
    execution_digest: str
    required_privileges: frozenset[str]
    run_id: str
    nonce: str


@dataclass(frozen=True)
class ExecutionPermitContext:
    """Typed sources for every exact ExecutionPermitV2 claim."""

    snapshot: EngagementSnapshot
    activation: ActivatedL3Catalog
    decision: PolicyDecision
    request: Mapping[str, object]
    platform: str
    engagement_id: str
    runner_identity: str
    runner_helper_digest: str
    image_reference: str
    image_digest: str
    typed_input: Mapping[str, object]
    resolved_endpoints: tuple[Mapping[str, object], ...]
    network_rules: tuple[Mapping[str, object], ...]
    rate_policy: Mapping[str, object]
    required_privileges: frozenset[str]
    evidence_schema: Mapping[str, object]
    run_id: str
    nonce: str
    issued_at: datetime
    expires_at: datetime


def _mismatch() -> ContractError:
    return ContractError(ReasonCode.EXEC_PRIVILEGE_MISMATCH)


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise _mismatch()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _mismatch() from exc
    if parsed.tzinfo is None:
        raise _mismatch()
    return parsed.astimezone(UTC)


def _fingerprint(public_key: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_key).hexdigest()


def verify_permit(
    permit: Mapping[str, object],
    signature: bytes,
    signer_public_key: bytes,
    *,
    pinned_signer_fingerprint: str,
    context: PermitContext,
    now: datetime,
) -> None:
    """Verify a privilege permit or fail closed with an exact reason."""

    # 1. The signer must be the pinned key.
    if len(signer_public_key) != ED25519_PUBLIC_KEY_BYTES:
        raise _mismatch()
    if _fingerprint(signer_public_key) != pinned_signer_fingerprint:
        raise _mismatch()

    # 2. The permit body must be exactly the expected fields.
    if set(permit) != _PERMIT_FIELDS:
        raise _mismatch()

    # 3. The signature must verify over the domain-separated canonical body.
    message = canonical_bytes({"contract": _PERMIT_DOMAIN, "permit": dict(permit)})
    if not verify(signer_public_key, message, signature):
        raise _mismatch()

    # 4. The permit must bind exactly this run: engagement, authority, action,
    # runner, executable, execution digest, and the replay tuple (run_id, nonce).
    if permit["engagement_id"] != context.engagement_id:
        raise _mismatch()
    if permit["authority_digest"] != context.authority_digest:
        raise _mismatch()
    if permit["action_id"] != context.action_id:
        raise _mismatch()
    if permit["runner_identity"] != context.runner_identity:
        raise _mismatch()
    if permit["executable_sha256"] != context.executable_sha256:
        raise _mismatch()
    if permit["execution_digest"] != context.execution_digest:
        raise _mismatch()
    if permit["run_id"] != context.run_id or permit["nonce"] != context.nonce:
        raise _mismatch()

    # 5. The privilege set must match exactly.
    privileges = permit["privileges"]
    if not isinstance(privileges, list) or any(not isinstance(p, str) for p in privileges):
        raise _mismatch()
    if frozenset(privileges) != context.required_privileges or len(set(privileges)) != len(
        privileges
    ):
        raise _mismatch()

    # 6. Expiry window (same 1-300s maximum lifetime as the request).
    issued = _parse_utc(permit["issued_at"])
    expires = _parse_utc(permit["expires_at"])
    lifetime = (expires - issued).total_seconds()
    if not MIN_REQUEST_LIFETIME_SECONDS <= lifetime <= MAX_REQUEST_LIFETIME_SECONDS:
        raise ContractError(ReasonCode.EXEC_PROTOCOL_EXPIRED)
    if now >= expires or now < issued:
        raise ContractError(ReasonCode.EXEC_PROTOCOL_EXPIRED)


def _execution_error(reason: ReasonCode = ReasonCode.EXEC_PROTOCOL_INVALID) -> ContractError:
    return ContractError(reason)


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [_thaw(item) for item in value]
    if isinstance(value, frozenset | set):
        return [_thaw(item) for item in sorted(value, key=str)]
    return value


def _utc_text(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.microsecond != 0
    ):
        raise _execution_error(ReasonCode.EXEC_PROTOCOL_EXPIRED)
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_execution_utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise _execution_error(ReasonCode.EXEC_PROTOCOL_EXPIRED)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _execution_error(ReasonCode.EXEC_PROTOCOL_EXPIRED) from exc
    if parsed.tzinfo is None or parsed.microsecond != 0 or _utc_text(parsed) != value:
        raise _execution_error(ReasonCode.EXEC_PROTOCOL_EXPIRED)
    return parsed.astimezone(UTC)


def _validate_execution_lifetime(issued: datetime, expires: datetime) -> None:
    lifetime = (expires - issued).total_seconds()
    if not MIN_REQUEST_LIFETIME_SECONDS <= lifetime <= MAX_REQUEST_LIFETIME_SECONDS:
        raise _execution_error(ReasonCode.EXEC_PROTOCOL_EXPIRED)


def _validated_execution_context(
    context: ExecutionPermitContext,
) -> tuple[str, L3ActionContract, Mapping[str, object]]:
    if type(context) is not ExecutionPermitContext:
        raise _execution_error()
    request_action_id = context.request.get("action_id")
    if not isinstance(request_action_id, str):
        raise _execution_error()

    # Recompute P3 and binding under the same activation and snapshot. A caller
    # cannot manufacture an ALLOW value and use it to issue a permit.
    expected_decision = decide_l3(
        context.request,
        context.snapshot,
        context.activation,
        platform=context.platform,
    )
    if (
        expected_decision.kind is not DecisionKind.ALLOW
        or expected_decision.bound is None
        or context.decision != expected_decision
    ):
        raise _execution_error()

    contract = context.activation.actions.get(request_action_id)
    if contract is None:
        raise _execution_error()
    parameters = context.request.get("parameters")
    if not isinstance(parameters, Mapping) or dict(parameters) != dict(context.typed_input):
        raise _execution_error()
    if dict(context.rate_policy) != dict(contract.rate_policy):
        raise _execution_error()
    if dict(context.evidence_schema) != dict(contract.evidence_schema):
        raise _execution_error()
    if context.required_privileges != contract.action.required_privileges:
        raise _execution_error(ReasonCode.EXEC_PRIVILEGE_MISMATCH)
    if any(not isinstance(item, Mapping) for item in context.resolved_endpoints):
        raise _execution_error()
    if any(not isinstance(item, Mapping) for item in context.network_rules):
        raise _execution_error()

    issued = _parse_execution_utc(_utc_text(context.issued_at))
    expires = _parse_execution_utc(_utc_text(context.expires_at))
    _validate_execution_lifetime(issued, expires)
    return request_action_id, contract, parameters


def build_execution_permit_v2(context: ExecutionPermitContext) -> dict[str, object]:
    """Build exact claims from a recomputed ALLOW and its activating snapshot."""

    action_id, contract, parameters = _validated_execution_context(context)
    permit = {
        "schema_version": 2,
        "engagement_id": context.engagement_id,
        "authority_digest": context.snapshot.authority_digest,
        "snapshot_identity": context.snapshot.identity,
        "profile": context.snapshot.profile,
        "action_id": action_id,
        "action_definition_digest": contract.definition_digest,
        "runner_identity": context.runner_identity,
        "runner_helper_digest": context.runner_helper_digest,
        "image_reference": context.image_reference,
        "image_digest": context.image_digest,
        "input_digest": digest_value(
            {"contract": _EXECUTION_INPUT_DOMAIN, "value": _thaw(parameters)}
        ),
        "resolved_endpoints": _thaw(context.resolved_endpoints),
        "network_rules": _thaw(context.network_rules),
        "rate_policy": _thaw(context.rate_policy),
        "required_privileges": sorted(context.required_privileges),
        "evidence_schema": _thaw(context.evidence_schema),
        "run_id": context.run_id,
        "nonce": context.nonce,
        "issued_at": _utc_text(context.issued_at),
        "expires_at": _utc_text(context.expires_at),
    }
    try:
        canonical_bytes(permit)
    except ContractError as exc:
        raise _execution_error() from exc
    return permit


def sign_execution_permit_v2(
    permit: Mapping[str, object], signer: Callable[[bytes], bytes]
) -> bytes:
    """Sign only the canonical v2 domain using the injected authority signer."""

    if set(permit) != _EXECUTION_PERMIT_FIELDS or not callable(signer):
        raise _execution_error()
    try:
        body = canonical_bytes({"contract": _EXECUTION_PERMIT_DOMAIN, "permit": _thaw(permit)})
        signature = signer(body)
    except Exception as exc:
        raise _execution_error() from exc
    if type(signature) is not bytes or len(signature) != _ED25519_SIGNATURE_BYTES:
        raise _execution_error()
    return signature


def verify_execution_permit_v2(
    permit: Mapping[str, object],
    signature: bytes,
    signer_public_key: bytes,
    *,
    pinned_signer_fingerprint: str,
    context: ExecutionPermitContext,
    now: datetime,
) -> None:
    """Verify every exact v2 binding before any replay or resource operation."""

    if (
        type(signer_public_key) is not bytes
        or len(signer_public_key) != ED25519_PUBLIC_KEY_BYTES
        or _fingerprint(signer_public_key) != pinned_signer_fingerprint
    ):
        raise _execution_error(ReasonCode.EXEC_TRUST_MISMATCH)
    if set(permit) != _EXECUTION_PERMIT_FIELDS:
        raise _execution_error()
    try:
        message = canonical_bytes({"contract": _EXECUTION_PERMIT_DOMAIN, "permit": _thaw(permit)})
    except ContractError as exc:
        raise _execution_error() from exc
    if (
        type(signature) is not bytes
        or len(signature) != _ED25519_SIGNATURE_BYTES
        or not verify(signer_public_key, message, signature)
    ):
        raise _execution_error()

    issued = _parse_execution_utc(permit["issued_at"])
    expires = _parse_execution_utc(permit["expires_at"])
    _validate_execution_lifetime(issued, expires)
    if now.tzinfo is None or now.utcoffset() is None or now < issued or now >= expires:
        raise _execution_error(ReasonCode.EXEC_PROTOCOL_EXPIRED)

    expected = build_execution_permit_v2(context)
    for field in _EXECUTION_PERMIT_FIELDS:
        if _thaw(permit[field]) == expected[field]:
            continue
        if field == "required_privileges":
            raise _execution_error(ReasonCode.EXEC_PRIVILEGE_MISMATCH)
        if field in _EXECUTION_TRUST_FIELDS:
            raise _execution_error(ReasonCode.EXEC_TRUST_MISMATCH)
        raise _execution_error()


def decode_signature(value: str) -> bytes:
    """Decode a base64url permit signature, failing closed on bad input."""

    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise _mismatch() from exc
