"""Tests for strict canonical engagement-v2 values and digests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hackbot.engagement_v2.canonical import (
    authority_digest,
    canonical_bytes,
    digest_value,
    execution_digest,
)
from hackbot.engagement_v2.constants import MAX_DOCUMENT_NESTING_DEPTH
from hackbot.engagement_v2.errors import ContractError, ReasonCode

FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "engagement_v2" / "canonical"


def test_canonical_bytes_sort_keys_and_preserve_ordered_lists() -> None:
    value = {"z": ["second", "first"], "a": {"enabled": True, "count": 2}}

    assert canonical_bytes(value) == (
        b'{"a":{"count":2,"enabled":true},"z":["second","first"]}'
    )


@pytest.mark.parametrize(
    "value",
    [
        1.0,
        b"raw",
        2**63,
        -(2**63) - 1,
        {"Bad-Key": "value"},
        {"value": "e\u0301"},
        {"value": "\u0000"},
        {"value": "\u007f"},
        {"value": "\ud800"},
    ],
)
def test_invalid_canonical_value_fails_closed(value: object) -> None:
    with pytest.raises(ContractError) as caught:
        canonical_bytes(value)

    assert caught.value.reason_code is ReasonCode.INVALID_CANONICAL_VALUE


def test_excessively_nested_canonical_value_fails_closed() -> None:
    value: object = None
    for _ in range(MAX_DOCUMENT_NESTING_DEPTH + 1):
        value = [value]

    with pytest.raises(ContractError) as caught:
        canonical_bytes(value)

    assert caught.value.reason_code is ReasonCode.INVALID_LIMIT


def test_digest_domains_are_distinct() -> None:
    projection = {"schema_version": 1, "profile": "private-pentest"}

    assert authority_digest(projection) != execution_digest(projection)


def test_digest_value_uses_lower_case_sha256_prefix() -> None:
    assert digest_value({"value": "fixture"}) == (
        "sha256:bc2674594440583782c17d5cf875c88037498d39f5661b6a5962dcf6089752c0"
    )


def test_authority_fixture_is_frozen_canonical_bytes_and_digest() -> None:
    projection = json.loads(
        (FIXTURE_DIRECTORY / "authority-input.json").read_text(encoding="utf-8")
    )
    expected_bytes = (FIXTURE_DIRECTORY / "authority-canonical.json").read_bytes()
    digest_path = FIXTURE_DIRECTORY / "authority-digest.txt"
    expected_digest = digest_path.read_text(encoding="ascii").rstrip("\n")

    assert canonical_bytes(projection) == expected_bytes
    assert authority_digest(projection) == expected_digest
