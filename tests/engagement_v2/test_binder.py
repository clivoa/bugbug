"""P2 typed binder."""

from __future__ import annotations

import pytest

from hackbot.engagement_v2.binder import FileReference, SecretReference, bind
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.manifest import validate_manifest

from ._actions_builders import action_doc, manifest_doc, request_doc


def _action(action_override=None):
    registry = validate_manifest(manifest_doc(action_override))
    return registry["operator.http-probe"]


_TARGET = {"url": ("https://app.corp.example/admin",)}


def test_bind_produces_argv() -> None:
    command = bind(_action(), request_doc(), _TARGET, platform="linux")
    assert command.argv == (
        "/usr/bin/curl",
        "--rate",
        "5",
        "--target",
        "https://app.corp.example/admin",
    )


def test_argv0_is_the_executable() -> None:
    command = bind(_action(), request_doc(), _TARGET, platform="linux")
    assert command.argv[0] == "/usr/bin/curl"
    assert command.executable == "/usr/bin/curl"


def test_request_supplied_argv_refused() -> None:
    request = request_doc(argv=["/bin/sh", "-c", "id"])
    with pytest.raises(ContractError) as excinfo:
        bind(_action(), request, _TARGET, platform="linux")
    assert excinfo.value.reason_code is ReasonCode.INVALID_REQUEST


def test_request_cannot_override_executable() -> None:
    request = request_doc(executable="/bin/sh")
    with pytest.raises(ContractError) as excinfo:
        bind(_action(), request, _TARGET, platform="linux")
    assert excinfo.value.reason_code is ReasonCode.INVALID_REQUEST


def test_out_of_bound_parameter_rejected() -> None:
    request = request_doc()
    request["parameters"]["rate"] = 5000  # above maximum 100
    with pytest.raises(ContractError) as excinfo:
        bind(_action(), request, _TARGET, platform="linux")
    assert excinfo.value.reason_code is ReasonCode.INVALID_REQUEST


def test_missing_executable_for_platform_rejected() -> None:
    with pytest.raises(ContractError) as excinfo:
        bind(_action(), request_doc(), _TARGET, platform="windows")
    assert excinfo.value.reason_code is ReasonCode.INVALID_REQUEST


def test_target_placeholder_requires_single_target() -> None:
    resolved = {"url": ("https://app.corp.example/admin", "https://app.corp.example/x")}
    with pytest.raises(ContractError) as excinfo:
        bind(_action(), request_doc(), resolved, platform="linux")
    assert excinfo.value.reason_code is ReasonCode.INVALID_REQUEST


def test_secret_placeholder_stays_a_reference() -> None:
    action = action_doc()
    action["secrets"] = {"api_key": {"transport": "file"}}
    action["argv"] = ["--target", "{target:url}", "--secret", "{secret_file:api_key}"]
    command = bind(_action(action), request_doc(), _TARGET, platform="linux")
    assert SecretReference("api_key") in command.argv
    assert command.secret_references == frozenset({"api_key"})
    # No secret material is ever embedded.
    assert all(not isinstance(token, str) or "api_key" not in token for token in command.argv)


def test_targets_file_placeholder_is_a_reference() -> None:
    action = action_doc()
    action["argv"] = ["--list", "{targets_file:url}"]
    command = bind(_action(action), request_doc(), _TARGET, platform="linux")
    assert FileReference("targets_file", "url") in command.argv


def test_unbounded_string_hits_default_scalar_cap() -> None:
    action = action_doc()
    action["parameters"]["note"] = {"type": "string", "required": True}
    action["argv"] = ["--note", "{value:note}", "--target", "{target:url}"]
    request = request_doc()
    request["parameters"]["note"] = "A" * 200_000
    with pytest.raises(ContractError) as excinfo:
        bind(_action(action), request, _TARGET, platform="linux")
    assert excinfo.value.reason_code is ReasonCode.INVALID_REQUEST


def test_safe_pattern_is_enforced() -> None:
    action = action_doc()
    action["parameters"]["label"] = {
        "type": "string",
        "required": True,
        "pattern": "[a-z]{1,8}",
        "pattern_format": "hackbot-safe-fullmatch-v1",
    }
    action["argv"] = ["--label", "{value:label}", "--target", "{target:url}"]
    good = request_doc()
    good["parameters"]["label"] = "abc"
    assert bind(_action(action), good, _TARGET, platform="linux").argv[2] == "abc"
    bad = request_doc()
    bad["parameters"]["label"] = "NOT-lower"
    with pytest.raises(ContractError) as excinfo:
        bind(_action(action), bad, _TARGET, platform="linux")
    assert excinfo.value.reason_code is ReasonCode.INVALID_REQUEST
