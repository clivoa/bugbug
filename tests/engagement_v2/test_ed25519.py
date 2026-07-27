"""RFC 8032 Ed25519 verification vectors and negative cases."""

from __future__ import annotations

from hackbot.engagement_v2 import _ed25519
from hackbot.engagement_v2._ed25519 import verify


def test_noncanonical_x_zero_encoding_rejected() -> None:
    # x**2 == 0 (y == 1) is canonical only with a clear sign bit (RFC 8032).
    assert _ed25519._recover_x(1, 1) is None
    assert _ed25519._recover_x(1, 0) == 0


# RFC 8032, Section 7.1.
_VECTORS = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
        "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


def test_rfc8032_vectors_verify() -> None:
    for public_hex, message_hex, signature_hex in _VECTORS:
        assert verify(
            bytes.fromhex(public_hex), bytes.fromhex(message_hex), bytes.fromhex(signature_hex)
        )


def test_tampered_message_rejected() -> None:
    public, message, signature = _VECTORS[1]
    assert not verify(bytes.fromhex(public), b"\x73", bytes.fromhex(signature))


def test_wrong_key_rejected() -> None:
    _, message, signature = _VECTORS[1]
    other = _VECTORS[0][0]
    assert not verify(bytes.fromhex(other), bytes.fromhex(message), bytes.fromhex(signature))


def test_malleable_scalar_rejected() -> None:
    public, message, signature = _VECTORS[0]
    raw = bytearray.fromhex(signature)
    # Add the group order L to S -> non-canonical scalar, must be rejected.
    s = int.from_bytes(raw[32:], "little") + (2**252 + 27742317777372353535851937790883648493)
    tampered = bytes(raw[:32]) + s.to_bytes(40, "little")[:32]
    assert not verify(bytes.fromhex(public), bytes.fromhex(message), tampered)


def test_wrong_length_rejected() -> None:
    public, message, signature = _VECTORS[0]
    assert not verify(bytes.fromhex(public)[:31], bytes.fromhex(message), bytes.fromhex(signature))
    assert not verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)[:63])
