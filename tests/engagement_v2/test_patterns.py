from __future__ import annotations

import json
import re
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import FrameType
from typing import ClassVar

import pytest

import hackbot.engagement_v2.patterns as safe_patterns
from hackbot.engagement_v2.constants import MAX_UTF8_STRING_BYTES
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.patterns import (
    CharacterSet,
    PatternAtom,
    SafePattern,
    compile_safe_pattern,
    safe_fullmatch,
)

FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "engagement_v2" / "patterns" / "cases.json"


def _maximum_pattern_module_call_depth(pattern: SafePattern, value: str) -> int:
    module_globals = vars(safe_patterns)
    active_depth = 0
    maximum_depth = 0

    def observe_calls(frame: FrameType, event: str, _argument: object) -> None:
        nonlocal active_depth, maximum_depth
        if frame.f_globals is not module_globals:
            return
        if event == "call":
            active_depth += 1
            maximum_depth = max(maximum_depth, active_depth)
        elif event == "return":
            active_depth -= 1

    previous_profiler = sys.getprofile()
    sys.setprofile(observe_calls)
    try:
        assert safe_fullmatch(pattern, value)
    finally:
        sys.setprofile(previous_profiler)
    assert active_depth == 0
    return maximum_depth


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


def test_compile_and_match_do_not_call_python_re(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject_re_entrypoint(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("safe patterns must not call Python re")

    for entrypoint in (
        "_compile",
        "Scanner",
        "compile",
        "findall",
        "finditer",
        "fullmatch",
        "match",
        "search",
        "split",
        "sub",
        "subn",
    ):
        monkeypatch.setattr(re, entrypoint, reject_re_entrypoint)

    pattern = compile_safe_pattern(r"[A-Za-z0-9._\-]{1,64}")
    assert safe_fullmatch(pattern, "scanner.example.invalid")


def test_matching_call_depth_does_not_grow_with_atom_count() -> None:
    control_depth = _maximum_pattern_module_call_depth(compile_safe_pattern("a"), "a")
    bounded_depth = _maximum_pattern_module_call_depth(compile_safe_pattern("a" * 256), "a" * 256)

    assert bounded_depth <= control_depth


def test_maximum_ascii_match_input_byte_limit_is_exact() -> None:
    pattern = compile_safe_pattern("a{1024}" * 8)

    assert safe_fullmatch(pattern, "a" * MAX_UTF8_STRING_BYTES)
    with pytest.raises(ContractError) as caught:
        safe_fullmatch(pattern, "a" * (MAX_UTF8_STRING_BYTES + 1))
    assert caught.value.reason_code is ReasonCode.INVALID_LIMIT


def test_worst_case_transition_count_is_linear_in_input_times_atoms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_accepts = CharacterSet.accepts

    class AcceptCounter:
        calls: ClassVar[int] = 0

    def counted_accepts(character_set: CharacterSet, character: str) -> bool:
        AcceptCounter.calls += 1
        return original_accepts(character_set, character)

    monkeypatch.setattr(CharacterSet, "accepts", counted_accepts)
    pattern = compile_safe_pattern("a{0,1024}" * 8)
    value = "a" * MAX_UTF8_STRING_BYTES

    assert safe_fullmatch(pattern, value)
    assert AcceptCounter.calls == len(value) * len(pattern.atoms)
