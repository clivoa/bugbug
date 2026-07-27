"""Tests for strict canonical engagement-v2 values and digests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import hackbot.engagement_v2.constants as constants
from hackbot.engagement_v2.canonical import (
    authority_digest,
    canonical_bytes,
    digest_value,
    execution_digest,
)
from hackbot.engagement_v2.constants import MAX_DOCUMENT_NESTING_DEPTH
from hackbot.engagement_v2.errors import ContractError, ReasonCode

FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "engagement_v2" / "canonical"


class IntegerSubclass(int):
    """An int subclass which canonical values must reject."""


class StringSubclass(str):
    """A str subclass which canonical values must reject."""


class ListSubclass(list[object]):
    """A list subclass which canonical values must reject."""


class TupleSubclass(tuple[object, ...]):
    """A tuple subclass which canonical values must reject."""


class DictSubclass(dict[str, object]):
    """A dict subclass which canonical values must reject."""


def test_canonical_bytes_sort_keys_and_preserve_ordered_lists() -> None:
    value = {"z": ["second", "first"], "a": {"enabled": True, "count": 2}}

    assert canonical_bytes(value) == (b'{"a":{"count":2,"enabled":true},"z":["second","first"]}')


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, b"null"),
        (True, b"true"),
        (False, b"false"),
        ("caf\u00e9", b'"caf\xc3\xa9"'),
        (("first", 2, False), b'["first",2,false]'),
        (-(2**63), b"-9223372036854775808"),
        (2**63 - 1, b"9223372036854775807"),
    ],
)
def test_canonical_bytes_accepts_exact_literal_values(value: object, expected: bytes) -> None:
    assert canonical_bytes(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        1.0,
        b"raw",
        IntegerSubclass(1),
        StringSubclass("value"),
        ListSubclass(["value"]),
        TupleSubclass(("value",)),
        DictSubclass({"value": "item"}),
        2**63,
        -(2**63) - 1,
        {"Bad-Key": "value"},
        {1: "value"},
        {b"value": "item"},
        {"value": "e\u0301"},
        {"value": "\u0000"},
        {"value": "\u007f"},
        {"value": "\u0080"},
        {"value": "\u009f"},
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


def test_canonical_bytes_accepts_maximum_nesting_depth() -> None:
    value: object = None
    for _ in range(MAX_DOCUMENT_NESTING_DEPTH):
        value = [value]

    assert canonical_bytes(value) == (
        b"[" * MAX_DOCUMENT_NESTING_DEPTH + b"null" + b"]" * MAX_DOCUMENT_NESTING_DEPTH
    )


def test_digest_domains_are_distinct() -> None:
    projection = {"schema_version": 1, "profile": "private-pentest"}

    assert authority_digest(projection) != execution_digest(projection)


def test_execution_digest_uses_the_frozen_execution_domain() -> None:
    projection = {"schema_version": 1, "profile": "private-pentest"}

    assert execution_digest(projection) == (
        "sha256:fd637f9f65ed2aacc2f3b5b409b8d9531606469264af4a1fdfdaee4922f3eaa7"
    )


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


def test_caller_normalizes_set_like_inputs_while_canonical_argv_stays_ordered() -> None:
    fixture = json.loads(
        (FIXTURE_DIRECTORY / "caller-normalized-collections.json").read_text(encoding="utf-8")
    )

    assert fixture["set_like_input"] == [
        "packet-capture",
        "network-raw",
        "packet-capture",
    ]
    projection = fixture["canonical_projection"]
    assert projection == {
        "argv": ["/opt/example.invalid/bin/tool", "--second", "--first"],
        "permitted_privileges": ["network-raw", "packet-capture"],
    }
    assert projection["permitted_privileges"] == sorted(set(fixture["set_like_input"]))
    assert canonical_bytes(projection) == (
        b'{"argv":["/opt/example.invalid/bin/tool","--second","--first"],'
        b'"permitted_privileges":["network-raw","packet-capture"]}'
    )


def test_runner_security_projection_golden_vector_binds_every_registered_field() -> None:
    projection_path = FIXTURE_DIRECTORY / "runner-security-projection.json"
    digest_path = FIXTURE_DIRECTORY / "runner-security-authority-digest.txt"
    projection = json.loads(projection_path.read_text(encoding="utf-8"))
    expected_digest = digest_path.read_text(encoding="ascii").removesuffix("\n")

    assert authority_digest(projection) == expected_digest
    assert expected_digest == (
        "sha256:ad39a9a43757e3e0c2305942e061120d92223fdb0229da981f67afde5bee0a2c"
    )

    for field in constants.RUNNER_SECURITY_PROJECTION_FIELDS:
        changed = copy.deepcopy(projection)
        path = field.split(".")
        parent = changed
        for segment in path[:-1]:
            parent = parent[segment]
        value = parent[path[-1]]
        if type(value) is bool:
            replacement: object = not value
        elif type(value) is int:
            replacement = value + 1
        elif type(value) is list:
            replacement = [*value, "superuser"]
        else:
            replacement = f"{value}-changed"
        parent[path[-1]] = replacement

        assert authority_digest(changed) != expected_digest, field
