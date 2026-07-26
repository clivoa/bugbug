from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import hackbot.engagement_v2.patterns as safe_patterns
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.patterns import (
    CharacterSet,
    PatternAtom,
    SafePattern,
    compile_safe_pattern,
    safe_fullmatch,
)

FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "engagement_v2" / "patterns" / "cases.json"


def test_frozen_synthetic_pattern_cases() -> None:
    cases = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    for case in cases:
        assert (
            safe_fullmatch(compile_safe_pattern(case["source"]), case["value"]) is case["expected"]
        ), case["name"]


@pytest.mark.parametrize(
    ("source", "value", "expected"),
    [
        (r"[A-Za-z0-9._\-]{1,64}", "dc01.corp", True),
        (r"[0-9]{1,5}", "65535", True),
        (r"[0-9]{1,5}", "65536x", False),
        (r"host\{1\}", "host{1}", True),
        (r"ab{0,2}c", "ac", True),
        (r"a{0}", "", True),
        (r"Az09 _.:/@", "Az09 _.:/@", True),
        (r"\-\[\]\{\}\\", "-[]{}\\", True),
        (r"[^a]{1,3}", "!Z9", True),
        (r"[C-Fm-p3-7]", "n", True),
    ],
)
def test_safe_fullmatch_cases(source: str, value: str, expected: bool) -> None:
    assert safe_fullmatch(compile_safe_pattern(source), value) is expected


@pytest.mark.parametrize(
    "source",
    [
        "",
        "(a+)+",
        "a|b",
        ".*",
        "^a$",
        r"(?!a)",
        r"\1",
        "a+",
        "a?",
        "a*",
        "!",
        "-",
        "{",
        "a{0,1025}",
        "a{1025}",
        "a{2,1}",
        "a{}",
        "a{,1}",
        "a{1,}",
        "a{1,2,3}",
        "a{1",
        "a{1}{1}",
        "\\",
        r"\a",
        "[]",
        "[^]",
        "[a",
        "[a\\",
        "[A-z]",
        "[z-a]",
        "[0-a]",
        "[a-]",
        "[-a]",
        "[{]",
    ],
)
def test_unsafe_or_malformed_constructs_are_rejected(source: str) -> None:
    with pytest.raises(ContractError) as caught:
        compile_safe_pattern(source)
    assert caught.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST


def test_pattern_source_byte_limit_is_exact() -> None:
    accepted = compile_safe_pattern("a" * 256)
    assert safe_fullmatch(accepted, "a" * 256)

    with pytest.raises(ContractError) as caught:
        compile_safe_pattern("a" * 257)
    assert caught.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST


def test_character_class_item_limit_is_exact() -> None:
    accepted = compile_safe_pattern("[" + ("a" * 64) + "]")
    assert safe_fullmatch(accepted, "a")

    with pytest.raises(ContractError) as caught:
        compile_safe_pattern("[" + ("a" * 65) + "]")
    assert caught.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST


def test_quantifier_limits_are_exact() -> None:
    exact_maximum = compile_safe_pattern("a{1024}")
    optional_maximum = compile_safe_pattern("a{0,1024}")

    assert safe_fullmatch(exact_maximum, "a" * 1024)
    assert safe_fullmatch(optional_maximum, "")


@pytest.mark.parametrize("source", ["café", "[é]", "a\n"])
def test_non_ascii_or_control_pattern_source_is_rejected(source: str) -> None:
    with pytest.raises(ContractError) as caught:
        compile_safe_pattern(source)
    assert caught.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST


@pytest.mark.parametrize("value", ["é", "\n", "\x00", "\x7f"])
def test_non_ascii_or_control_match_value_is_denied(value: str) -> None:
    assert not safe_fullmatch(compile_safe_pattern(r"[^a]{1,8}"), value)


def test_compiled_pattern_values_are_deeply_immutable() -> None:
    pattern = compile_safe_pattern("[a-c]{1,2}")

    assert isinstance(pattern, SafePattern)
    assert isinstance(pattern.atoms, tuple)
    assert isinstance(pattern.atoms[0], PatternAtom)
    assert isinstance(pattern.atoms[0].matcher, CharacterSet)
    assert isinstance(pattern.atoms[0].matcher.characters, frozenset)
    with pytest.raises(FrozenInstanceError):
        pattern.source = "changed"
    with pytest.raises(FrozenInstanceError):
        pattern.atoms[0].minimum = 0


def test_large_bounded_pattern_matches_iteratively() -> None:
    pattern = compile_safe_pattern("a" * 256)
    assert safe_fullmatch(pattern, "a" * 256)


def test_operation_budget_fails_closed_at_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_patterns, "_operation_limit", lambda _value, _atoms: 0)

    with pytest.raises(ContractError) as caught:
        safe_fullmatch(compile_safe_pattern("a"), "a")
    assert caught.value.reason_code is ReasonCode.INVALID_LIMIT
