"""Replay reservation for remote runs.

The helper atomically reserves ``(authority_digest, run_id, nonce)`` before it
creates any resource and rejects a duplicate for the P0 reservation window.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from hackbot.engagement_v2.constants import REPLAY_RESERVATION_SECONDS
from hackbot.engagement_v2.errors import ContractError, ReasonCode


class ReplayCache:
    """An in-memory replay reservation cache with time-bounded retention."""

    __slots__ = ("_seen", "_retention")

    def __init__(self, retention_seconds: int = REPLAY_RESERVATION_SECONDS) -> None:
        self._seen: dict[tuple[str, str, str], datetime] = {}
        self._retention = timedelta(seconds=retention_seconds)

    def reserve(self, authority_digest: str, run_id: str, nonce: str, now: datetime) -> None:
        """Reserve a run tuple or fail closed with EXEC_PROTOCOL_REPLAY."""

        self._prune(now)
        key = (authority_digest, run_id, nonce)
        if key in self._seen:
            raise ContractError(ReasonCode.EXEC_PROTOCOL_REPLAY)
        self._seen[key] = now + self._retention

    def _prune(self, now: datetime) -> None:
        expired = [key for key, deadline in self._seen.items() if deadline <= now]
        for key in expired:
            del self._seen[key]
