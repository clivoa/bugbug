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
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from hackbot.engagement_v2._ed25519 import verify
from hackbot.engagement_v2.canonical import canonical_bytes
from hackbot.engagement_v2.constants import (
    ED25519_PUBLIC_KEY_BYTES,
    MAX_REQUEST_LIFETIME_SECONDS,
    MIN_REQUEST_LIFETIME_SECONDS,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode

_PERMIT_DOMAIN = "hackbot-privilege-permit-v1"
_PERMIT_FIELDS = frozenset(
    {
        "engagement_id",
        "authority_digest",
        "action_id",
        "runner_identity",
        "executable_sha256",
        "privileges",
        "nonce",
        "issued_at",
        "expires_at",
    }
)


@dataclass(frozen=True)
class PermitContext:
    engagement_id: str
    authority_digest: str
    action_id: str
    runner_identity: str
    executable_sha256: str
    required_privileges: frozenset[str]


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

    # 4. The permit must bind exactly this engagement/authority/action/runner/exe.
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
    if now >= expires:
        raise ContractError(ReasonCode.EXEC_PROTOCOL_EXPIRED)


def decode_signature(value: str) -> bytes:
    """Decode a base64url permit signature, failing closed on bad input."""

    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise _mismatch() from exc
