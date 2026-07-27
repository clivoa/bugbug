"""P2 action manifest validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.manifest import load_manifest, validate_manifest

from ._actions_builders import action_doc, manifest_doc


def _reason(excinfo: pytest.ExceptionInfo[ContractError]) -> ReasonCode:
    return excinfo.value.reason_code


def test_valid_manifest_loads() -> None:
    registry = validate_manifest(manifest_doc())
    assert "operator.http-probe" in registry
    action = registry["operator.http-probe"]
    assert action.executables["linux"] == "/usr/bin/curl"
    assert action.rate_control.kind == "argv-placeholder"


def test_non_operator_id_rejected() -> None:
    action = action_doc()
    action["id"] = "native.http-probe"
    with pytest.raises(ContractError) as excinfo:
        validate_manifest(manifest_doc(action))
    assert _reason(excinfo) is ReasonCode.INVALID_ACTION_MANIFEST


def test_non_absolute_executable_rejected() -> None:
    action = action_doc()
    action["executables"] = {"linux": "curl"}
    with pytest.raises(ContractError) as excinfo:
        validate_manifest(manifest_doc(action))
    assert _reason(excinfo) is ReasonCode.INVALID_ACTION_MANIFEST


def test_shell_executable_requires_l3() -> None:
    action = action_doc()
    action["executables"] = {"linux": "/bin/bash"}
    with pytest.raises(ContractError):
        validate_manifest(manifest_doc(action))
    action["risk"] = "L3"
    # An L3 action may name a shell executable.
    registry = validate_manifest(manifest_doc(action))
    assert registry["operator.http-probe"].risk == "L3"


def test_elevation_executable_always_rejected() -> None:
    action = action_doc()
    action["risk"] = "L3"
    action["executables"] = {"linux": "/usr/bin/sudo"}
    with pytest.raises(ContractError):
        validate_manifest(manifest_doc(action))


def test_unknown_capability_rejected() -> None:
    action = action_doc()
    action["capabilities"] = ["mind-control"]
    with pytest.raises(ContractError) as excinfo:
        validate_manifest(manifest_doc(action))
    assert _reason(excinfo) is ReasonCode.INVALID_ACTION_MANIFEST


def test_argv_placeholder_requires_rate_and_concurrency() -> None:
    action = action_doc()
    action["rate_control"] = {"kind": "argv-placeholder", "rate_parameter": "rate"}
    with pytest.raises(ContractError):
        validate_manifest(manifest_doc(action))


def test_argv_placeholder_references_unknown_param_rejected() -> None:
    action = action_doc()
    action["argv"] = ["--rate", "{value:missing}"]
    with pytest.raises(ContractError):
        validate_manifest(manifest_doc(action))


def test_partial_token_placeholder_rejected() -> None:
    action = action_doc()
    action["argv"] = ["--rate={value:rate}"]
    with pytest.raises(ContractError) as excinfo:
        validate_manifest(manifest_doc(action))
    assert _reason(excinfo) is ReasonCode.INVALID_PLACEHOLDER


def test_too_many_actions_rejected() -> None:
    document = manifest_doc()
    document["actions"] = [action_doc() for _ in range(257)]
    for index, action in enumerate(document["actions"]):
        action["id"] = f"operator.probe-{index}"
    with pytest.raises(ContractError):
        validate_manifest(document)


def test_interpreter_inline_eval_rejected_even_at_l3() -> None:
    action = action_doc()
    action["risk"] = "L3"
    action["executables"] = {"linux": "/bin/bash"}
    action["parameters"] = {"cmd": {"type": "string", "required": True}}
    action["rate_control"] = {"kind": "not-applicable"}
    action["capabilities"] = ["payload-execution"]
    action["argv"] = ["-c", "{value:cmd}"]
    with pytest.raises(ContractError) as excinfo:
        validate_manifest(manifest_doc(action))
    assert _reason(excinfo) is ReasonCode.INVALID_ACTION_MANIFEST


def test_target_typed_value_parameter_rejected() -> None:
    action = action_doc()
    action["parameters"] = {
        "rate": {"type": "integer", "required": True},
        "concurrency": {"type": "integer", "required": True},
        "host": {"type": "url", "required": True},
    }
    action["targets"] = []
    action["argv"] = ["{value:host}"]
    with pytest.raises(ContractError) as excinfo:
        validate_manifest(manifest_doc(action))
    assert _reason(excinfo) is ReasonCode.INVALID_ACTION_MANIFEST


def test_elevation_argv_token_rejected() -> None:
    action = action_doc()
    action["executables"] = {"linux": "/usr/bin/timeout"}
    action["argv"] = ["sudo", "{target:url}"]
    with pytest.raises(ContractError) as excinfo:
        validate_manifest(manifest_doc(action))
    assert _reason(excinfo) is ReasonCode.INVALID_ACTION_MANIFEST


def test_unknown_action_field_rejected() -> None:
    action = action_doc()
    action["backdoor"] = True
    with pytest.raises(ContractError) as excinfo:
        validate_manifest(manifest_doc(action))
    assert _reason(excinfo) is ReasonCode.INVALID_ACTION_MANIFEST


def test_load_manifest_from_disk(tmp_path: Path) -> None:
    path = tmp_path / "actions.json"
    path.write_text(json.dumps(manifest_doc()), encoding="utf-8")
    registry = load_manifest(str(path))
    assert "operator.http-probe" in registry
