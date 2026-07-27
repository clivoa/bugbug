"""P4 replay reservation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.remote_replay import ReplayCache

_NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)


def test_duplicate_tuple_rejected() -> None:
    cache = ReplayCache()
    cache.reserve("sha256:a", "run-1", "nonce-1", _NOW)
    with pytest.raises(ContractError) as excinfo:
        cache.reserve("sha256:a", "run-1", "nonce-1", _NOW)
    assert excinfo.value.reason_code is ReasonCode.EXEC_PROTOCOL_REPLAY


def test_distinct_tuples_allowed() -> None:
    cache = ReplayCache()
    cache.reserve("sha256:a", "run-1", "nonce-1", _NOW)
    cache.reserve("sha256:a", "run-2", "nonce-2", _NOW)


def test_reservation_expires_after_window() -> None:
    cache = ReplayCache(retention_seconds=600)
    cache.reserve("sha256:a", "run-1", "nonce-1", _NOW)
    later = _NOW + timedelta(seconds=601)
    cache.reserve("sha256:a", "run-1", "nonce-1", later)  # window elapsed, allowed again
