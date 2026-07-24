"""Canonical, path-bound engagement identity shared by policy inputs."""

from __future__ import annotations

import hashlib
from pathlib import Path

_ENGAGEMENT_PATH_LIMIT = 2_048


class EngagementIdentityError(ValueError):
    """Raised when a path cannot identify an existing engagement directory."""


def canonical_engagement_identity(path: str | Path) -> tuple[str, str]:
    """Return an absolute canonical path and its stable collision-resistant identity."""
    try:
        directory = Path(path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EngagementIdentityError(f"engagement path could not be resolved: {path}") from exc
    if not directory.is_dir():
        raise EngagementIdentityError(f"engagement path is not a directory: {directory}")
    canonical_path = str(directory)
    if not canonical_path or len(canonical_path) > _ENGAGEMENT_PATH_LIMIT:
        raise EngagementIdentityError(
            f"engagement_path: expected a path up to {_ENGAGEMENT_PATH_LIMIT} characters"
        )
    return canonical_path, hashlib.sha256(canonical_path.encode("utf-8")).hexdigest()
