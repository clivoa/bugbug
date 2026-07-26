"""Bounded parser and full matcher for ``hackbot-safe-fullmatch-v1``."""

from __future__ import annotations

from dataclasses import dataclass

from .constants import (
    MAX_SAFE_PATTERN_BYTES,
    MAX_SAFE_PATTERN_CLASS_LITERALS,
    MAX_SAFE_PATTERN_QUANTIFIER,
    MIN_SAFE_PATTERN_CLASS_LITERALS,
    MIN_SAFE_PATTERN_QUANTIFIER,
)
from .errors import ContractError, ReasonCode

_UNESCAPED_LITERALS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 _.:/@"
)
_ESCAPED_LITERALS = frozenset("-[]{}\\")
_FIRST_PRINTABLE_ASCII = 0x20
_LAST_PRINTABLE_ASCII = 0x7E


@dataclass(frozen=True, slots=True)
class CharacterSet:
    """An immutable set of accepted characters, optionally negated."""

    characters: frozenset[str]
    negated: bool = False

    def accepts(self, character: str) -> bool:
        """Return whether *character* belongs to this set."""

        present = character in self.characters
        return not present if self.negated else present


@dataclass(frozen=True, slots=True)
class PatternAtom:
    """One immutable character matcher with a bounded repetition."""

    matcher: CharacterSet
    minimum: int
    maximum: int


@dataclass(frozen=True, slots=True)
class SafePattern:
    """An immutable compiled safe-fullmatch pattern."""

    source: str
    atoms: tuple[PatternAtom, ...]


def _invalid_pattern() -> ContractError:
    return ContractError(ReasonCode.INVALID_ACTION_MANIFEST)


def _parse_escaped_literal(source: str, index: int) -> tuple[str, int]:
    escaped_index = index + 1
    if escaped_index >= len(source) or source[escaped_index] not in _ESCAPED_LITERALS:
        raise _invalid_pattern()
    return source[escaped_index], escaped_index + 1


def _range_characters(start: str, end: str) -> frozenset[str]:
    within_uppercase = "A" <= start <= end <= "Z"
    within_lowercase = "a" <= start <= end <= "z"
    within_digits = "0" <= start <= end <= "9"
    if not (within_uppercase or within_lowercase or within_digits):
        raise _invalid_pattern()
    return frozenset(chr(codepoint) for codepoint in range(ord(start), ord(end) + 1))


def _is_class_literal(character: str) -> bool:
    return (
        _FIRST_PRINTABLE_ASCII <= ord(character) <= _LAST_PRINTABLE_ASCII
        and character not in "[-\\{}"
    )


def _parse_character_class(source: str, index: int) -> tuple[CharacterSet, int]:
    index += 1
    negated = index < len(source) and source[index] == "^"
    if negated:
        index += 1

    characters: set[str] = set()
    item_count = 0
    while index < len(source) and source[index] != "]":
        character = source[index]
        if character == "\\":
            literal, index = _parse_escaped_literal(source, index)
            characters.add(literal)
        else:
            if not _is_class_literal(character):
                raise _invalid_pattern()
            if index + 1 < len(source) and source[index + 1] == "-":
                end_index = index + 2
                if end_index >= len(source) or source[end_index] == "]":
                    raise _invalid_pattern()
                characters.update(_range_characters(character, source[end_index]))
                index = end_index + 1
            else:
                characters.add(character)
                index += 1

        item_count += 1
        if item_count > MAX_SAFE_PATTERN_CLASS_LITERALS:
            raise _invalid_pattern()

    if index >= len(source) or source[index] != "]":
        raise _invalid_pattern()
    if item_count < MIN_SAFE_PATTERN_CLASS_LITERALS:
        raise _invalid_pattern()
    return CharacterSet(frozenset(characters), negated), index + 1


def _parse_decimal(source: str, index: int) -> tuple[int, int]:
    if index >= len(source) or not ("0" <= source[index] <= "9"):
        raise _invalid_pattern()

    value = 0
    while index < len(source) and "0" <= source[index] <= "9":
        value = (value * 10) + (ord(source[index]) - ord("0"))
        if value > MAX_SAFE_PATTERN_QUANTIFIER:
            raise _invalid_pattern()
        index += 1
    return value, index


def _parse_quantifier(source: str, index: int) -> tuple[int, int, int]:
    minimum, index = _parse_decimal(source, index + 1)
    if index >= len(source):
        raise _invalid_pattern()

    if source[index] == "}":
        maximum = minimum
    elif source[index] == ",":
        maximum, index = _parse_decimal(source, index + 1)
        if index >= len(source) or source[index] != "}":
            raise _invalid_pattern()
    else:
        raise _invalid_pattern()

    if not (MIN_SAFE_PATTERN_QUANTIFIER <= minimum <= maximum <= MAX_SAFE_PATTERN_QUANTIFIER):
        raise _invalid_pattern()
    return minimum, maximum, index + 1


def compile_safe_pattern(source: str) -> SafePattern:
    """Compile the exact bounded ASCII safe-fullmatch grammar."""

    try:
        source_bytes = source.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        raise _invalid_pattern() from None
    if not source_bytes or len(source_bytes) > MAX_SAFE_PATTERN_BYTES:
        raise _invalid_pattern()

    atoms: list[PatternAtom] = []
    index = 0
    while index < len(source):
        character = source[index]
        if character in _UNESCAPED_LITERALS:
            matcher = CharacterSet(frozenset({character}))
            index += 1
        elif character == "\\":
            literal, index = _parse_escaped_literal(source, index)
            matcher = CharacterSet(frozenset({literal}))
        elif character == "[":
            matcher, index = _parse_character_class(source, index)
        else:
            raise _invalid_pattern()

        minimum = 1
        maximum = 1
        if index < len(source) and source[index] == "{":
            minimum, maximum, index = _parse_quantifier(source, index)
        atoms.append(PatternAtom(matcher, minimum, maximum))

    return SafePattern(source, tuple(atoms))


def _operation_limit(value_length: int, atom_count: int) -> int:
    return (value_length + 1) * (atom_count + 1) * (MAX_SAFE_PATTERN_QUANTIFIER + 1)


def safe_fullmatch(pattern: SafePattern, value: str) -> bool:
    """Return a bounded, implicitly anchored match result."""

    if any(
        not (_FIRST_PRINTABLE_ASCII <= ord(character) <= _LAST_PRINTABLE_ASCII)
        for character in value
    ):
        return False

    operations = 0
    operation_limit = _operation_limit(len(value), len(pattern.atoms))
    positions = {0}
    for atom in pattern.atoms:
        next_positions: set[int] = set()
        for start in positions:
            operations += 1
            if operations > operation_limit:
                raise ContractError(ReasonCode.INVALID_LIMIT)

            end = start
            if atom.minimum == 0:
                next_positions.add(start)
            for count in range(1, atom.maximum + 1):
                operations += 1
                if operations > operation_limit:
                    raise ContractError(ReasonCode.INVALID_LIMIT)
                if end >= len(value) or not atom.matcher.accepts(value[end]):
                    break
                end += 1
                if count >= atom.minimum:
                    next_positions.add(end)
        positions = next_positions
        if not positions:
            return False
    return len(value) in positions
