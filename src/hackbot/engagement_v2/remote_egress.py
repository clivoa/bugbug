"""Typed, fail-closed egress claims.

`direct-interface` and `attested-egress` are distinct claims. A local interface
address asserts nothing about public egress. An observed claim requires a pinned,
Ed25519-signed attestation adapter within a bounded observation age; anything
unverifiable fails closed.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime

from hackbot.engagement_v2._ed25519 import verify
from hackbot.engagement_v2.canonical import canonical_bytes
from hackbot.engagement_v2.constants import (
    ED25519_PUBLIC_KEY_BYTES,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_EGRESS_OBSERVATION_AGE_SECONDS,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode

_EGRESS_DOMAIN = "hackbot-egress-attestation-v1"


def _trust_mismatch() -> ContractError:
    return ContractError(ReasonCode.EXEC_TRUST_MISMATCH)


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise _trust_mismatch()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _trust_mismatch() from exc
    if parsed.tzinfo is None:
        raise _trust_mismatch()
    return parsed.astimezone(UTC)


def verify_egress(
    source_identity: Mapping[str, object],
    egress_attestation: Mapping[str, object] | None,
    *,
    run_id: str | None = None,
    nonce: str | None = None,
    execution_digest: str | None = None,
    signer_public_key: bytes | None = None,
    pinned_signer_fingerprint: str | None = None,
    now: datetime,
) -> str:
    """Return the verified egress claim (`none`/`direct-interface`/`attested-egress`).

    An `attested-egress` claim is bound to this run: the signed observation must
    carry the run ID, nonce, and execution digest matching the request.
    """

    mode = source_identity.get("mode")
    if mode == "none":
        return "none"
    if mode == "direct-interface":
        # A local interface address is recorded as a direct claim only; it makes
        # no public-egress assertion.
        return "direct-interface"
    if mode != "attested-egress":
        raise _trust_mismatch()

    # Observed egress requires a pinned, signed, fresh, run-bound attestation.
    if (
        egress_attestation is None
        or signer_public_key is None
        or pinned_signer_fingerprint is None
        or run_id is None
        or nonce is None
        or execution_digest is None
        or len(signer_public_key) != ED25519_PUBLIC_KEY_BYTES
    ):
        raise _trust_mismatch()
    if "sha256:" + hashlib.sha256(signer_public_key).hexdigest() != pinned_signer_fingerprint:
        raise _trust_mismatch()

    body = egress_attestation.get("attestation")
    signature = egress_attestation.get("signature")
    if not isinstance(body, Mapping) or not isinstance(signature, (bytes, bytearray)):
        raise _trust_mismatch()

    # The observation must bind this exact run.
    if (
        body.get("run_id") != run_id
        or body.get("nonce") != nonce
        or body.get("execution_digest") != execution_digest
    ):
        raise _trust_mismatch()

    observed_at = _parse_utc(body.get("observed_at"))
    age = (now - observed_at).total_seconds()
    if age > MAX_EGRESS_OBSERVATION_AGE_SECONDS or age < -MAX_CLOCK_SKEW_SECONDS:
        raise _trust_mismatch()

    message = canonical_bytes({"contract": _EGRESS_DOMAIN, "attestation": dict(body)})
    if not verify(signer_public_key, message, bytes(signature)):
        raise _trust_mismatch()
    return "attested-egress"
