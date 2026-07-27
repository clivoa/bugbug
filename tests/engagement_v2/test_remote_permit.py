"""P4 Ed25519 privilege permit verification."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from hackbot.engagement_v2.canonical import canonical_bytes
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.remote_permit import PermitContext, verify_permit

from ._ed25519_sign import public_key, sign

_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_RFC_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def test_sign_helper_matches_rfc8032() -> None:
    assert public_key(_SEED).hex() == _RFC_PUBLIC
    expected = (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
        "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert sign(_SEED, b"").hex() == expected


def _fingerprint(pub: bytes) -> str:
    return "sha256:" + hashlib.sha256(pub).hexdigest()


def _permit() -> dict:
    return {
        "engagement_id": "engv2.alpha",
        "authority_digest": "sha256:" + "a" * 64,
        "action_id": "operator.capture",
        "runner_identity": "kali.node",
        "executable_sha256": "sha256:" + "b" * 64,
        "privileges": ["network-raw"],
        "nonce": "n" * 43,
        "issued_at": "2026-07-27T12:00:00Z",
        "expires_at": "2026-07-27T12:05:00Z",
    }


def _context() -> PermitContext:
    return PermitContext(
        engagement_id="engv2.alpha",
        authority_digest="sha256:" + "a" * 64,
        action_id="operator.capture",
        runner_identity="kali.node",
        executable_sha256="sha256:" + "b" * 64,
        required_privileges=frozenset({"network-raw"}),
    )


def _signed(permit: dict) -> bytes:
    message = canonical_bytes({"contract": "hackbot-privilege-permit-v1", "permit": permit})
    return sign(_SEED, message)


_NOW = datetime(2026, 7, 27, 12, 1, tzinfo=UTC)


def test_valid_permit_verifies() -> None:
    permit = _permit()
    verify_permit(
        permit,
        _signed(permit),
        public_key(_SEED),
        pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
        context=_context(),
        now=_NOW,
    )


def test_wrong_signer_fingerprint_rejected() -> None:
    permit = _permit()
    with pytest.raises(ContractError) as excinfo:
        verify_permit(
            permit,
            _signed(permit),
            public_key(_SEED),
            pinned_signer_fingerprint="sha256:" + "0" * 64,
            context=_context(),
            now=_NOW,
        )
    assert excinfo.value.reason_code is ReasonCode.EXEC_PRIVILEGE_MISMATCH


def test_tampered_permit_rejected() -> None:
    permit = _permit()
    signature = _signed(permit)
    permit["action_id"] = "operator.other"  # tamper after signing
    with pytest.raises(ContractError) as excinfo:
        verify_permit(
            permit,
            signature,
            public_key(_SEED),
            pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
            context=_context(),
            now=_NOW,
        )
    assert excinfo.value.reason_code is ReasonCode.EXEC_PRIVILEGE_MISMATCH


def test_privilege_set_mismatch_rejected() -> None:
    permit = _permit()
    permit["privileges"] = ["superuser"]
    with pytest.raises(ContractError) as excinfo:
        verify_permit(
            permit,
            _signed(permit),
            public_key(_SEED),
            pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
            context=_context(),
            now=_NOW,
        )
    assert excinfo.value.reason_code is ReasonCode.EXEC_PRIVILEGE_MISMATCH


def test_expired_permit_rejected() -> None:
    permit = _permit()
    late = datetime(2026, 7, 27, 12, 6, tzinfo=UTC)
    with pytest.raises(ContractError) as excinfo:
        verify_permit(
            permit,
            _signed(permit),
            public_key(_SEED),
            pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
            context=_context(),
            now=late,
        )
    assert excinfo.value.reason_code is ReasonCode.EXEC_PROTOCOL_EXPIRED
