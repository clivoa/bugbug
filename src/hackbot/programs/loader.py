"""
programs.loader — read program/scope files as LOCAL DATA and build a Scope.

  * YAML is parsed with yaml.safe_load only (no arbitrary object construction).
  * No network, no provider calls. Files only.
  * On ANY validation failure the loader raises — callers must treat that as
    default-deny (never fall back to an open scope).
  * The produced Scope is the frozen engine object; there is no runtime expansion.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hackbot.programs.decoding import DuplicateJSONKeyError, strict_json_loads
from hackbot.programs.schema import ScopeDoc, ValidationError, validate_program, validate_scope
from hackbot.scope import Scope


class ProgramError(Exception):
    """Raised for load/parse problems (missing yaml dep, unreadable file, bad doc)."""


def _strict_yaml_load(text: str, yaml: Any) -> object:
    """Safe-load YAML while rejecting duplicate mapping keys at every depth."""
    mapping_tag = yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG

    class StrictSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        loader.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "mapping key must be a string",
                    key_node.start_mark,
                )
            if key in result:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate YAML key {key!r}",
                    key_node.start_mark,
                )
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    StrictSafeLoader.add_constructor(mapping_tag, construct_mapping)
    return yaml.load(text, Loader=StrictSafeLoader)


def _load_mapping(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        raise ProgramError(f"file not found: {p}")
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ProgramError(f"unable to read {p}") from exc
    if p.suffix.lower() == ".json":
        try:
            data = strict_json_loads(text)
        except (json.JSONDecodeError, DuplicateJSONKeyError) as e:
            raise ProgramError(f"invalid JSON in {p}: {e}") from e
        if not isinstance(data, dict):
            raise ProgramError(f"{p}: top-level document must be a mapping")
        return data
    try:
        import yaml  # config extra
    except ModuleNotFoundError as e:
        raise ProgramError(
            "PyYAML is required to read YAML program/scope files; "
            "install with: pip install 'hackbot[config]'"
        ) from e
    try:
        data = _strict_yaml_load(text, yaml)  # SafeLoader subclass: no arbitrary objects
    except yaml.YAMLError as e:
        raise ProgramError(f"invalid YAML in {p}: {e}") from e
    if not isinstance(data, dict):
        raise ProgramError(f"{p}: top-level document must be a mapping")
    return data


def _scope_from_doc(sd: ScopeDoc, name: str) -> Scope:
    return Scope(
        in_scope=sd.in_rules,
        out_of_scope=sd.out_rules,
        name=name,
        rule_sources=sd.rule_sources,
    )


def load_scope_file(path: str | Path, *, name: str = "engagement") -> Scope:
    """Validate a standalone scope file and return the frozen Scope (or raise)."""
    doc = _load_mapping(path)
    sd = validate_scope(doc)  # raises ValidationError on any problem (default-deny)
    return _scope_from_doc(sd, name)


def load_program_file(path: str | Path, *, name: str = "engagement") -> tuple[dict, Scope]:
    """Validate a full program file; return (raw_doc, frozen Scope) or raise."""
    doc = _load_mapping(path)
    sd = validate_program(doc)
    return doc, _scope_from_doc(sd, name)


def validate_file(path: str | Path) -> list[str]:
    """Return [] if the file validates, else the list of error messages.

    Auto-detects program vs scope by presence of a top-level ``program``/
    ``testing_rules`` section; otherwise treats it as a scope document.
    """
    try:
        doc = _load_mapping(path)
    except ProgramError as e:
        return [str(e)]
    is_program = isinstance(doc, dict) and (
        "program" in doc
        or "testing_rules" in doc
        or "authorization" in doc
        or ("scope" in doc and "in_scope" not in doc)
    )
    try:
        if is_program:
            validate_program(doc)
        else:
            validate_scope(doc)
    except ValidationError as e:
        return e.errors
    return []
