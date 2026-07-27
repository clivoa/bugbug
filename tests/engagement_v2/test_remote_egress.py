"""P4 typed egress attestation."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from hackbot.engagement_v2.canonical import canonical_bytes
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.remote_egress import verify_egress

from ._ed25519_sign import public_key, sign

_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_NOW = datetime(2026, 7, 27, 12, 0, 30, tzinfo=UTC)
_RUN_ID = "11111111-1111-4111-8111-111111111111"
_NONCE = "n" * 43
_EXEC = "sha256:" + "c" * 64


def _fingerprint(pub: bytes) -> str:
    return "sha256:" + hashlib.sha256(pub).hexdigest()


def _run_kwargs() -> dict:
    return {
        "run_id": _RUN_ID,
        "nonce": _NONCE,
        "execution_digest": _EXEC,
        "signer_public_key": public_key(_SEED),
        "pinned_signer_fingerprint": _fingerprint(public_key(_SEED)),
        "now": _NOW,
    }


def test_none_and_direct_interface_claims() -> None:
    assert verify_egress({"mode": "none"}, None, now=_NOW) == "none"
    assert (
        verify_egress({"mode": "direct-interface", "address": "10.10.0.5"}, None, now=_NOW)
        == "direct-interface"
    )


def test_attested_without_adapter_fails_closed() -> None:
    with pytest.raises(ContractError) as excinfo:
        verify_egress({"mode": "attested-egress"}, None, now=_NOW)
    assert excinfo.value.reason_code is ReasonCode.EXEC_TRUST_MISMATCH


def _attestation(observed_at: str, *, run_id: str = _RUN_ID) -> dict:
    body = {
        "run_id": run_id,
        "nonce": _NONCE,
        "execution_digest": _EXEC,
        "observed_at": observed_at,
        "address": "203.0.113.5",
    }
    message = canonical_bytes({"contract": "hackbot-egress-attestation-v1", "attestation": body})
    return {"attestation": body, "signature": sign(_SEED, message)}


def test_fresh_signed_run_bound_attestation_accepted() -> None:
    att = _attestation("2026-07-27T12:00:00Z")
    assert verify_egress({"mode": "attested-egress"}, att, **_run_kwargs()) == "attested-egress"


def test_attestation_for_another_run_rejected() -> None:
    att = _attestation("2026-07-27T12:00:00Z", run_id="22222222-2222-4222-8222-222222222222")
    with pytest.raises(ContractError) as excinfo:
        verify_egress({"mode": "attested-egress"}, att, **_run_kwargs())
    assert excinfo.value.reason_code is ReasonCode.EXEC_TRUST_MISMATCH


def test_stale_attestation_rejected() -> None:
    att = _attestation("2026-07-27T11:00:00Z")  # far older than the 60s max
    with pytest.raises(ContractError) as excinfo:
        verify_egress({"mode": "attested-egress"}, att, **_run_kwargs())
    assert excinfo.value.reason_code is ReasonCode.EXEC_TRUST_MISMATCH


def test_future_attestation_rejected() -> None:
    att = _attestation("2026-07-27T12:05:00Z")  # future beyond skew
    with pytest.raises(ContractError):
        verify_egress({"mode": "attested-egress"}, att, **_run_kwargs())


def test_missigned_attestation_rejected() -> None:
    att = _attestation("2026-07-27T12:00:00Z")
    att["attestation"]["address"] = "198.51.100.9"  # tamper after signing
    with pytest.raises(ContractError):
        verify_egress({"mode": "attested-egress"}, att, **_run_kwargs())
