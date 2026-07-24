from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from hackbot.risk.identity import canonical_engagement_identity
from hackbot.risk.models import (
    ActionDefinition,
    ActionRequest,
    ApprovalChallenge,
    RiskLevel,
)
from hackbot.risk.models import TestingPolicy as _TestingPolicy
from hackbot.risk.registry import ActionRegistry, RegistryError


def _request_values(tmp_path):
    engagement = tmp_path / "engagement"
    engagement.mkdir(exist_ok=True)
    engagement_path, engagement_id = canonical_engagement_identity(engagement)
    return {
        "engagement_id": engagement_id,
        "engagement_path": engagement_path,
        "action_id": "fixture.scan",
        "target": "https://example.com",
        "argv": ("fixture", "scan"),
        "hypothesis_id": "hyp-1",
        "rationale": "Validate one authorized hypothesis.",
        "rate": 1,
        "concurrency": 1,
        "data_touched": "Public response headers.",
        "expected_impact": "One low-rate request.",
        "stop_condition": "Stop on any rate limit.",
        "cleanup_plan": "No state is created.",
        "program_rule": "Automated testing rule.",
    }


def test_risk_levels_are_ordered():
    assert RiskLevel.L0 < RiskLevel.L1 < RiskLevel.L2 < RiskLevel.L3


def test_action_definition_is_frozen_and_characteristics_raise_floor():
    action = ActionDefinition("fixture.write", RiskLevel.L1, state_changing=True)
    assert action.effective_floor == RiskLevel.L2
    with pytest.raises(FrozenInstanceError):
        action.action_id = "changed"


def test_request_cannot_lower_registered_floor(tmp_path):
    action = ActionDefinition("fixture.scan", RiskLevel.L2)
    request = ActionRequest(**_request_values(tmp_path), requested_risk=RiskLevel.L0)
    assert request.effective_risk(action) == RiskLevel.L2


@pytest.mark.parametrize("field", ["hypothesis_id", "stop_condition", "cleanup_plan"])
def test_active_request_requires_reviewed_safety_fields(field, tmp_path):
    values = _request_values(tmp_path)
    values[field] = ""

    with pytest.raises(ValueError, match=field):
        ActionRequest(**values)


def test_request_requires_id_for_the_canonical_engagement_path(tmp_path):
    values = _request_values(tmp_path)
    values["engagement_id"] = "different"
    with pytest.raises(ValueError, match="engagement_id"):
        ActionRequest(**values)


def test_request_canonicalizes_symlinked_engagement_paths(tmp_path):
    values = _request_values(tmp_path)
    real_path = values["engagement_path"]
    alias = tmp_path / "engagement-alias"
    alias.symlink_to(real_path, target_is_directory=True)
    values["engagement_path"] = str(alias)
    request = ActionRequest(**values)
    assert request.engagement_path == real_path


def test_request_rejects_oversized_or_missing_engagement_paths(tmp_path):
    values = _request_values(tmp_path)
    values["engagement_path"] = "x" * 2_049
    with pytest.raises(ValueError, match="engagement_path"):
        ActionRequest(**values)
    values = _request_values(tmp_path)
    values["engagement_path"] = str(tmp_path / "missing")
    with pytest.raises(ValueError, match="engagement path"):
        ActionRequest(**values)


@pytest.mark.parametrize(
    "headers",
    [
        ("Authorization: Bearer secret",),
        ("X-Header\rInjected",),
        ("X-Header", "x-header"),
        ("x" * 129,),
    ],
)
def test_request_required_headers_are_bounded_field_names_only(tmp_path, headers):
    with pytest.raises(ValueError, match="required_headers"):
        ActionRequest(**_request_values(tmp_path), required_headers=headers)


def test_request_normalizes_required_header_names(tmp_path):
    request = ActionRequest(**_request_values(tmp_path), required_headers=("X-Research-ID",))
    assert request.required_headers == ("x-research-id",)


def test_registry_rejects_duplicate_and_unknown_actions():
    action = ActionDefinition("fixture.passive", RiskLevel.L0)
    with pytest.raises(RegistryError):
        ActionRegistry([action, action])
    registry = ActionRegistry([action])
    with pytest.raises(RegistryError):
        registry.require("missing")


def _testing_policy(**changes):
    values = {
        "max_requests_per_second": 2,
        "concurrency": 2,
        "automated_scanning_allowed": False,
        "authenticated_testing_allowed": False,
        "account_creation_allowed": False,
        "multiple_accounts_allowed": False,
        "social_engineering_allowed": False,
        "denial_of_service_allowed": False,
        "out_of_band_testing_allowed": False,
    }
    values.update(changes)
    return _TestingPolicy(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_requests_per_second", 0),
        ("max_requests_per_second", True),
        ("max_requests_per_second", 1_001),
        ("max_requests_per_second", None),
        ("concurrency", 0),
        ("concurrency", "1"),
        ("concurrency", 101),
        ("concurrency", None),
    ],
)
def test_testing_policy_rejects_invalid_rate_and_concurrency(field, value):
    with pytest.raises(ValueError, match=field):
        _testing_policy(**{field: value})


@pytest.mark.parametrize("field", ["social_engineering_allowed", "denial_of_service_allowed"])
def test_testing_policy_rejects_absolute_l3_flags(field):
    with pytest.raises(ValueError, match=field):
        _testing_policy(**{field: True})


_PERMISSION_FLAGS = (
    "automated_scanning_allowed",
    "authenticated_testing_allowed",
    "account_creation_allowed",
    "multiple_accounts_allowed",
    "social_engineering_allowed",
    "denial_of_service_allowed",
    "out_of_band_testing_allowed",
)


@pytest.mark.parametrize("field", _PERMISSION_FLAGS)
@pytest.mark.parametrize("value", ["false", 0, 1, None])
def test_testing_policy_rejects_non_boolean_permission_flags(field, value):
    with pytest.raises(ValueError, match=field):
        _testing_policy(**{field: value})


@pytest.mark.parametrize(
    "field",
    [
        "automated_scanning_allowed",
        "authenticated_testing_allowed",
        "account_creation_allowed",
        "multiple_accounts_allowed",
        "out_of_band_testing_allowed",
    ],
)
def test_testing_policy_preserves_non_l3_boolean_permission_flags(field):
    assert getattr(_testing_policy(**{field: True}), field) is True


def test_testing_policy_normalizes_immutable_collections_and_timezone():
    policy = _testing_policy(
        source_ip_requirements=[" OFFICE-IP "],
        required_headers=[" X-Research-Id "],
        restricted_hours=["09:00-10:00"],
        restricted_hours_timezone="Europe/Madrid",
        prohibited_tools=[" NMAP "],
        prohibited_vulnerability_types=[" XSS "],
        excluded_impacts=[" Availability "],
    )

    assert policy.source_ip_requirements == ("office-ip",)
    assert policy.required_headers == ("x-research-id",)
    assert policy.restricted_hours == ("09:00-10:00",)
    assert policy.restricted_hours_timezone == "Europe/Madrid"
    assert policy.prohibited_tools == ("nmap",)
    assert policy.prohibited_vulnerability_types == ("xss",)
    assert policy.excluded_impacts == ("availability",)


@pytest.mark.parametrize("field", ["required_headers", "prohibited_tools", "excluded_impacts"])
def test_testing_policy_rejects_duplicate_normalized_collection_values(field):
    with pytest.raises(ValueError, match=field):
        _testing_policy(**{field: ["NMAP", " nmap "]})


def test_testing_policy_rejects_unknown_restricted_hours_timezone():
    with pytest.raises(ValueError, match="restricted_hours_timezone"):
        _testing_policy(restricted_hours_timezone="Mars/Olympus")


@pytest.mark.parametrize("timezone", ["/etc/passwd", "../UTC"])
def test_testing_policy_rejects_invalid_zoneinfo_path_values(timezone):
    with pytest.raises(ValueError, match="restricted_hours_timezone"):
        _testing_policy(restricted_hours=["09:00-10:00"], restricted_hours_timezone=timezone)


@pytest.mark.parametrize(
    "headers",
    [["Authorization: Bearer value"], ["X Header"], ["X-Header\rInjected"]],
)
def test_testing_policy_required_headers_are_field_names_only(headers):
    with pytest.raises(ValueError, match="required_headers"):
        _testing_policy(required_headers=headers)


def test_approval_challenge_canonicalizes_and_validates_argv():
    now = datetime(2026, 7, 24, tzinfo=UTC)
    challenge = ApprovalChallenge(
        engagement_id="sample",
        program_id="program",
        target="https://example.com",
        action_id="fixture.scan",
        argv=["fixture", "scan"],
        effective_risk=RiskLevel.L2,
        rationale="Validate one authorized hypothesis.",
        hypothesis_id="hyp-1",
        expected_impact="One low-rate request.",
        rate=1,
        concurrency=1,
        data_touched="Public response headers.",
        stop_condition="Stop on any rate limit.",
        program_rule="Automated testing rule.",
        cleanup_plan="No state is created.",
        scope_digest="scope-digest",
        policy_digest="policy-digest",
        created_at=now,
        expires_at=now,
        nonce="nonce",
        challenge_digest="challenge-digest",
    )

    assert challenge.argv == ("fixture", "scan")
    with pytest.raises(ValueError, match="argv"):
        ApprovalChallenge(
            engagement_id="sample",
            program_id="program",
            target="https://example.com",
            action_id="fixture.scan",
            argv=["fixture"] * 129,
            effective_risk=RiskLevel.L2,
            rationale="Validate one authorized hypothesis.",
            hypothesis_id="hyp-1",
            expected_impact="One low-rate request.",
            rate=1,
            concurrency=1,
            data_touched="Public response headers.",
            stop_condition="Stop on any rate limit.",
            program_rule="Automated testing rule.",
            cleanup_plan="No state is created.",
            scope_digest="scope-digest",
            policy_digest="policy-digest",
            created_at=now,
            expires_at=now,
            nonce="nonce",
            challenge_digest="challenge-digest",
        )
