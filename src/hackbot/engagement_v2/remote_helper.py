"""Pinned helper identity and remote executable-digest verification.

The helper is identified only by pinned values from the confirmed runner
projection; a helper self-report never satisfies identity. For an exact-digest
action, the executable is opened as a regular file and its digest verified before
spawn, and `argv[0]` is bound to that verified path.
"""

from __future__ import annotations

import hashlib
import os
import stat

from hackbot.engagement_v2.errors import ContractError, ReasonCode

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIGEST_CHUNK = 1_048_576


def verify_protocol_version(reported_version: object, pinned_version: int) -> None:
    """Reject a helper protocol version other than the pinned expected version."""

    if type(reported_version) is not int or reported_version != pinned_version:
        raise ContractError(ReasonCode.EXEC_PROTOCOL_INVALID)


def verify_helper_identity(computed_sha256: str, pinned_sha256: str) -> None:
    """Verify a helper binary digest against the pinned value (not a self-report)."""

    if computed_sha256 != pinned_sha256:
        raise ContractError(ReasonCode.EXEC_TRUST_MISMATCH)


def file_digest(path: str) -> str:
    """Return the `sha256:` digest of a regular file, opened without following links."""

    try:
        descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
    except OSError as exc:
        raise ContractError(ReasonCode.EXEC_TRUST_MISMATCH) from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError(ReasonCode.EXEC_TRUST_MISMATCH)
        hasher = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, _DIGEST_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
        return "sha256:" + hasher.hexdigest()
    finally:
        os.close(descriptor)


def verify_executable_digest(path: str, expected_sha256: str) -> str:
    """Verify an executable's digest before spawn and return its verified path.

    The returned path is what a consumer binds to `argv[0]` (P0 review N2).
    """

    if file_digest(path) != expected_sha256:
        raise ContractError(ReasonCode.EXEC_TRUST_MISMATCH)
    return path
