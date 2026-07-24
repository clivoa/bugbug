"""Strict schema validation tests (default-deny on any failure)."""

from pathlib import Path

import pytest
import yaml

from hackbot.programs.schema import (
    SCHEMA_VERSION,
    ValidationError,
    validate_program,
    validate_scope,
)

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return yaml.safe_load((FIX / name).read_text())


def test_valid_program():
    sd = validate_program(load("valid_program.yaml"))
    assert "acme-corp.example" in sd.in_rules
    assert "*.api.acme-corp.example" in sd.in_rules
    assert "203.0.113.0/24" in sd.in_rules
    assert "2001:db8::/32" in sd.in_rules
    assert "github.com/acme-corp/webapp" in sd.in_rules
    assert "blog.acme-corp.example" in sd.out_rules
    assert sd.rule_sources["acme-corp.example"] == "in_scope.domains"


def test_valid_scope():
    sd = validate_scope(load("valid_scope.yaml"))
    assert "example.com" in sd.in_rules and "internal.example.com" in sd.out_rules


def test_unknown_security_field_rejected():
    with pytest.raises(ValidationError) as e:
        validate_scope(load("invalid_unknown_field.yaml"))
    assert any("unknown security-critical field" in m for m in e.value.errors)


def test_duplicate_rejected():
    with pytest.raises(ValidationError) as e:
        validate_scope(load("invalid_duplicate.yaml"))
    assert any("duplicate" in m for m in e.value.errors)


def test_malformed_rejected():
    with pytest.raises(ValidationError) as e:
        validate_scope(load("invalid_malformed.yaml"))
    msgs = " ".join(e.value.errors)
    assert "invalid CIDR" in msgs
    assert "bare hostname" in msgs  # domain with a path


def test_missing_version_rejected():
    with pytest.raises(ValidationError) as e:
        validate_scope(load("invalid_no_version.yaml"))
    assert any("missing required schema_version" in m for m in e.value.errors)


def test_unsupported_version_rejected():
    with pytest.raises(ValidationError) as e:
        validate_scope(load("invalid_bad_version.yaml"))
    assert any("unsupported schema_version" in m for m in e.value.errors)


def test_empty_scope_is_default_deny():
    with pytest.raises(ValidationError) as e:
        validate_scope({"schema_version": SCHEMA_VERSION, "in_scope": {}})
    assert any("default-deny" in m for m in e.value.errors)


def test_program_requires_scope():
    with pytest.raises(ValidationError) as e:
        validate_program({"schema_version": 1, "program": {"name": "x"}})
    assert any("missing required scope" in m for m in e.value.errors)


def test_unknown_top_level_program_section_rejected():
    with pytest.raises(ValidationError) as e:
        validate_program(
            {"schema_version": 1, "scope": {"in_scope": {"domains": ["a.com"]}}, "backdoor": True}
        )
    assert any("unknown top-level section" in m for m in e.value.errors)
