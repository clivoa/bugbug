"""Strict, standard-library-only decoding for security-critical local data."""

from __future__ import annotations

import json


class DuplicateJSONKeyError(ValueError):
    """Raised when a JSON object repeats a key at any nesting level."""


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJSONKeyError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def strict_json_loads(text: str) -> object:
    """Decode JSON without allowing duplicate-key last-wins behavior."""
    return json.loads(text, object_pairs_hook=_strict_json_object)
