"""Pure-standard-library Ed25519 signature verification (RFC 8032).

Verification only: Hackbot never signs. This keeps the core dependency-free and
means no signing key ever exists in the process. The implementation follows RFC
8032 and rejects non-canonical encodings and out-of-range scalars.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx % _P, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


# Edwards curve base point.
_BY = (4 * _inv(5)) % _P
_BX = _recover_x(_BY, 0)
assert _BX is not None
_B = (_BX % _P, _BY % _P, 1, (_BX * _BY) % _P)


def _point_add(
    p: tuple[int, int, int, int], q: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    dd = (z1 * 2 * z2) % _P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalar_mult(p: tuple[int, int, int, int], e: int) -> tuple[int, int, int, int]:
    q = (0, 1, 1, 0)  # neutral element
    while e > 0:
        if e & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        e >>= 1
    return q


def _point_equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    if (x1 * z2 - x2 * z1) % _P != 0:
        return False
    if (y1 * z2 - y2 * z1) % _P != 0:
        return False
    return True


def _decompress(data: bytes) -> tuple[int, int, int, int] | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff the Ed25519 signature verifies for message under key."""

    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    if a is None:
        return False
    r_bytes = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:  # reject non-canonical / malleable scalars
        return False
    r = _decompress(r_bytes)
    if r is None:
        return False
    digest = hashlib.sha512(r_bytes + public_key + message).digest()
    k = int.from_bytes(digest, "little") % _L
    left = _scalar_mult(_B, s)
    right = _point_add(r, _scalar_mult(a, k))
    return _point_equal(left, right)
