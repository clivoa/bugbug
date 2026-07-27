"""Test-only Ed25519 signing (RFC 8032). Production never signs.

Reuses the pure-Python verify module's curve primitives so tests can produce
valid permits/attestations to exercise verification.
"""

from __future__ import annotations

import hashlib

from hackbot.engagement_v2 import _ed25519 as ed


def _compress(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zinv = ed._inv(z)
    x = (x * zinv) % ed._P
    y = (y * zinv) % ed._P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def secret_scalar(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = secret_scalar(seed)
    return _compress(ed._scalar_mult(ed._B, a))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = secret_scalar(seed)
    pub = _compress(ed._scalar_mult(ed._B, a))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % ed._L
    r_point = _compress(ed._scalar_mult(ed._B, r))
    k = int.from_bytes(hashlib.sha512(r_point + pub + message).digest(), "little") % ed._L
    s = (r + k * a) % ed._L
    return r_point + s.to_bytes(32, "little")
