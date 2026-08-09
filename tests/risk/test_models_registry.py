from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from hackbot.risk.identity import EngagementIdentityError, canonical_engagement_identity
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


@pytest.mark.parametrize(
    "changes",
    [
        {"action_id": " Not Canonical "},
        {"minimum_risk": 1},
        {"network_access": 1},
        {"tool_id": " Nmap "},
        {"executable": "nmap"},
        {"vulnerability_types": ("XSS", "xss")},
        {"impacts": (" availability ",)},
    ],
)
def test_action_definitions_strictly_validate_code_owned_fields(changes):
    values = {"action_id": "fixture.scan", "minimum_risk": RiskLevel.L1}
    values.update(changes)
    with pytest.raises(ValueError):
        ActionDefinition(**values)


@pytest.mark.parametrize(
    "field",
    [
        "network_access",
        "low_impact_allowlisted",
        "state_changing",
        "high_volume",
        "touches_third_party",
        "automated",
        "authenticated",
        "creates_account",
        "uses_multiple_accounts",
        "out_of_band",
        "honors_required_headers",
        "shell_execution",
    ],
)
def test_action_definition_requires_exact_boolean_characteristics(field):
    with pytest.raises(ValueError, match=field):
        ActionDefinition("fixture.scan", RiskLevel.L1, **{field: 1})


def test_shell_execution_is_an_absolute_l3_definition_characteristic():
    action = ActionDefinition(
        "fixture.shell",
        RiskLevel.L0,
        uses_external_tool=True,
        executable="/bin/sh",
        argv_template=("/bin/sh",),
        shell_execution=True,
    )
    assert action.effective_floor is RiskLevel.L3


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("automated", RiskLevel.L1),
        ("authenticated", RiskLevel.L1),
        ("creates_account", RiskLevel.L2),
        ("uses_multiple_accounts", RiskLevel.L2),
        ("out_of_band", RiskLevel.L2),
    ],
)
def test_trusted_action_characteristics_raise_the_effective_floor(field, expected):
    action = ActionDefinition("fixture.floor", RiskLevel.L0, **{field: True})
    assert action.effective_floor is expected


@pytest.mark.parametrize(
    "changes",
    [
        {"uses_external_tool": 1},
        {"uses_external_tool": False, "tool_id": "nmap"},
        {"uses_external_tool": False, "executable": "/opt/nmap"},
        {"uses_external_tool": True},
        {"uses_external_tool": True, "tool_id": "nmap"},
        {"uses_external_tool": True, "executable": "/opt/nmap"},
        {"uses_external_tool": True, "tool_id": "nmap", "executable": "/opt//nmap"},
        {"uses_external_tool": True, "executable": "/opt/../nmap"},
    ],
)
def test_external_tool_metadata_is_explicit_and_paths_are_canonical(changes):
    with pytest.raises(ValueError):
        ActionDefinition("fixture.tool", RiskLevel.L0, **changes)


def test_external_tool_metadata_normalizes_windows_paths_lexically():
    action = ActionDefinition(
        "fixture.tool",
        RiskLevel.L0,
        uses_external_tool=True,
        executable="C:\\Tools\\Nmap.EXE",
        argv_template=("c:/tools/nmap.exe",),
    )
    assert action.executable == "c:/tools/nmap.exe"


@pytest.mark.parametrize(
    "argv_template",
    [
        [],
        ("/usr/bin/sqlmap", "{unknown}"),
        ("/usr/bin/sqlmap", "--url={target}"),
        ("/usr/bin/sqlmap", "{target}", "{target}"),
        ("/usr/bin/other",),
        ("/usr/bin/sqlmap", "x" * 4_097),
        ("/usr/bin/sqlmap", "\ud800"),
    ],
)
def test_external_argv_templates_are_immutable_and_unambiguous(argv_template):
    with pytest.raises(ValueError):
        ActionDefinition(
            "fixture.template",
            RiskLevel.L0,
            uses_external_tool=True,
            executable="/usr/bin/sqlmap",
            argv_template=argv_template,
        )


def test_external_argv_template_is_frozen_and_preserves_typed_placeholders():
    action = ActionDefinition(
        "fixture.template",
        RiskLevel.L0,
        uses_external_tool=True,
        executable="/usr/bin/sqlmap",
        argv_template=("/usr/bin/sqlmap", "--url", "{target}", "--rate", "{rate}"),
    )
    assert action.argv_template == (
        "/usr/bin/sqlmap",
        "--url",
        "{target}",
        "--rate",
        "{rate}",
    )
    with pytest.raises(FrozenInstanceError):
        action.argv_template = ()


def test_no_tool_definition_rejects_an_argv_template():
    with pytest.raises(ValueError, match="no-tool"):
        ActionDefinition("fixture.no-tool", RiskLevel.L0, argv_template=("/bin/sh",))


@pytest.mark.parametrize(
    "executable",
    [
        "/bin/sh",
        "/usr/bin/bash",
        "/bin/csh",
        "c:/windows/system32/cmd.exe",
        "c:/windows/system32/windowspowershell/v1.0/powershell.exe",
        "c:/program files/powershell/7/pwsh.exe",
    ],
)
def test_known_shell_executables_require_explicit_shell_execution(executable):
    with pytest.raises(ValueError, match="shell_execution"):
        ActionDefinition(
            "fixture.shell",
            RiskLevel.L0,
            uses_external_tool=True,
            executable=executable,
            argv_template=(executable,),
        )


def test_shell_execution_requires_a_trusted_external_executable():
    with pytest.raises(ValueError, match="external"):
        ActionDefinition("fixture.shell", RiskLevel.L0, shell_execution=True)


def test_shell_command_mode_requires_shell_execution():
    """-c/--command flags only raise when the executable IS a shell.
    A non-shell tool like sqlmap with -c (for config) should NOT raise."""
    # This should NOT raise — sqlmap uses -c for config, not shell command
    ActionDefinition(
        "fixture.command",
        RiskLevel.L0,
        uses_external_tool=True,
        executable="/usr/bin/sqlmap",
        argv_template=("/usr/bin/sqlmap", "-c", "{target}"),
    )
    # This SHOULD raise — bash with -c IS shell command mode
    with pytest.raises(ValueError, match="shell_execution"):
        ActionDefinition(
            "fixture.shell_cmd",
            RiskLevel.L0,
            uses_external_tool=True,
            executable="/bin/bash",
            argv_template=("/bin/bash", "-c", "{target}"),
        )


def test_registry_revalidates_mutated_action_definition():
    action = ActionDefinition("fixture.scan", RiskLevel.L1)
    object.__setattr__(action, "network_access", 1)
    with pytest.raises(RegistryError, match="invalid"):
        ActionRegistry([action])


def test_request_cannot_lower_registered_floor(tmp_path):
    action = ActionDefinition("fixture.scan", RiskLevel.L2)
    request = ActionRequest(**_request_values(tmp_path), requested_risk=RiskLevel.L0)
    assert request.effective_risk(action) == RiskLevel.L2


def test_request_cannot_declare_trusted_vulnerability_or_impact_classifications(tmp_path):
    with pytest.raises(TypeError):
        ActionRequest(**_request_values(tmp_path), vulnerability_type="xss")
    with pytest.raises(TypeError):
        ActionRequest(**_request_values(tmp_path), impact="availability")


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


def test_action_request_rejects_surrogate_text(tmp_path):
    values = _request_values(tmp_path)
    values["rationale"] = "\ud800"
    with pytest.raises(ValueError, match="rationale"):
        ActionRequest(**values)


def test_engagement_identity_rejects_surrogate_path_without_echoing_value():
    with pytest.raises(
        EngagementIdentityError, match="engagement_path: contains invalid Unicode"
    ) as exc_info:
        canonical_engagement_identity("/tmp/\ud800")
    assert "\\ud800" not in str(exc_info.value)


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


def test_testing_policy_rejects_surrogate_list_and_timezone_text():
    with pytest.raises(ValueError, match="prohibited_tools"):
        _testing_policy(prohibited_tools=["\ud800"])
    with pytest.raises(ValueError, match="restricted_hours_timezone"):
        _testing_policy(restricted_hours=["09:00-10:00"], restricted_hours_timezone="\ud800")


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


def test_approval_challenge_rejects_surrogate_text():
    now = datetime(2026, 7, 24, tzinfo=UTC)
    with pytest.raises(ValueError, match="rationale"):
        ApprovalChallenge(
            engagement_id="sample",
            program_id="program",
            target="https://example.com",
            action_id="fixture.scan",
            argv=("fixture", "scan"),
            effective_risk=RiskLevel.L2,
            rationale="\ud800",
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
