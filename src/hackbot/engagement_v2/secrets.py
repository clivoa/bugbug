"""Post-ALLOW, engagement-namespaced secret resolution.

Secrets are resolved only within the active engagement's namespace identity, so a
reference that exists only under another engagement fails closed. Resolved
material is delivered to a child only through stdin or a protected, exclusively
created mode-0600 file; secret names and values never enter argv, the
environment, audit, evidence, or errors.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Protocol


class SecretResolutionError(Exception):
    """Fail-closed secret failure. Its message never contains a secret name."""


class SecretBackend(Protocol):
    def get(self, name: str) -> str | None: ...


def namespaced_key(engagement_identity: str, name: str) -> str:
    """Return the backend key for a secret within one engagement namespace."""

    return f"engagement-secret/{engagement_identity}/{name}"


def resolve_secret(backend: SecretBackend, engagement_identity: str, name: str) -> bytes:
    """Resolve one secret within the engagement namespace or fail closed."""

    value = backend.get(namespaced_key(engagement_identity, name))
    if value is None:
        # No secret name in the message: the failure is secret-free.
        raise SecretResolutionError("required secret is unavailable for this engagement")
    return value.encode("utf-8")


def resolve_all(
    backend: SecretBackend, engagement_identity: str, names: Mapping[str, None] | frozenset[str]
) -> dict[str, bytes]:
    """Resolve every referenced secret, failing closed if any is missing."""

    return {name: resolve_secret(backend, engagement_identity, name) for name in names}


def write_protected_file(directory: str, value: bytes) -> str:
    """Write secret bytes to a new mode-0600 exclusive file and return its path."""

    descriptor, path = _exclusive_file(directory, mode=0o600)
    try:
        os.write(descriptor, value)
    finally:
        os.close(descriptor)
    return path


_counter = 0


def _exclusive_file(directory: str, *, mode: int) -> tuple[int, str]:
    global _counter
    while True:
        _counter += 1
        # Opaque numeric name: never a parameter or secret name.
        path = os.path.join(directory, f"run-{os.getpid()}-{_counter:06d}")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        except FileExistsError:
            continue
        return descriptor, path
