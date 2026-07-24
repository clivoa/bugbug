"""Strict schema validation tests (default-deny on any failure)."""

from pathlib import Path

import pytest
import yaml

from hackbot.programs.schema import (
    SCHEMA_VERSION,
    ValidationError,
    validate_program,
    validate_scope,
    validate_testing_policy,
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


def test_testing_policy_rejects_invalid_ranges():
    with pytest.raises(ValidationError):
        validate_testing_policy({"max_requests_per_second": 0, "concurrency": 101})


@pytest.mark.parametrize(
    "field",
    ["denial_of_service_allowed", "social_engineering_allowed"],
)
def test_project_level_l3_flags_cannot_be_true(field):
    with pytest.raises(ValidationError):
        validate_testing_policy({field: True})


def test_policy_rejects_duplicate_normalized_tool_names():
    with pytest.raises(ValidationError):
        validate_testing_policy({"prohibited_tools": ["NMAP", "nmap"]})


def test_policy_parses_restricted_hours_mapping():
    policy = validate_testing_policy(
        {"restricted_hours": {"timezone": "Europe/Madrid", "windows": ["09:00-10:00"]}}
    )
    assert policy.restricted_hours_timezone == "Europe/Madrid"
    assert policy.restricted_hours == ("09:00-10:00",)


@pytest.mark.parametrize(
    "restricted_hours",
    [
        {"timezone": "Mars/Olympus", "windows": ["09:00-10:00"]},
        {"timezone": "UTC", "windows": ["09:00-09:00"]},
        {"timezone": "UTC", "windows": ["9:00-10:00"]},
        {"timezone": "UTC", "windows": ["09:00-10:00"], "extra": True},
    ],
)
def test_policy_rejects_invalid_restricted_hours(restricted_hours):
    with pytest.raises(ValidationError):
        validate_testing_policy({"restricted_hours": restricted_hours})


def test_validate_program_applies_typed_testing_policy_validation():
    program = load("valid_program.yaml")
    program["testing_rules"]["concurrency"] = True
    with pytest.raises(ValidationError, match="concurrency"):
        validate_program(program)


def test_validate_program_rejects_explicit_null_testing_rules():
    program = load("valid_program.yaml")
    program["testing_rules"] = None
    with pytest.raises(ValidationError, match="testing_rules"):
        validate_program(program)


@pytest.mark.parametrize(
    "headers",
    [
        ["Authorization: Bearer value"],
        ["X Header"],
        ["X-Header\nInjected"],
        ["X-Header", "x-header"],
    ],
)
def test_testing_policy_rejects_non_field_name_required_headers(headers):
    with pytest.raises(ValidationError, match="required_headers"):
        validate_testing_policy({"required_headers": headers})


def test_testing_policy_normalizes_header_field_names():
    policy = validate_testing_policy({"required_headers": ["X-Research-ID", "!Custom"]})
    assert policy.required_headers == ("x-research-id", "!custom")
