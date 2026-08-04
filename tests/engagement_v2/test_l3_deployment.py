"""Closed root-owned L3 broker and forced-command SSH deployment contract."""

from __future__ import annotations

import copy
import importlib
import importlib.util

import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode

_BROKER_PATH = "/usr/local/libexec/hackbot-l3-runner"


def _document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "broker_path": _BROKER_PATH,
        "broker_sha256": "sha256:" + "a" * 64,
        "ssh_user": "hackbot-l3",
        "forced_command": _BROKER_PATH,
        "interactive_shell": False,
        "tty": False,
        "port_forwarding": False,
        "agent_forwarding": False,
        "x11_forwarding": False,
        "permitted_signer_sha256": "sha256:" + "b" * 64,
    }


def _module():
    module_name = "hackbot.engagement_v2.l3_deployment"
    assert importlib.util.find_spec(module_name) is not None, "deployment validator is absent"
    return importlib.import_module(module_name)


def test_valid_fixed_deployment_returns_immutable_contract() -> None:
    """Catch deployment authority that is not reduced to fixed reviewed values."""

    result = _module().validate_l3_deployment(_document())
    assert result.broker_path == _BROKER_PATH
    assert result.broker_sha256 == "sha256:" + "a" * 64
    assert result.ssh_user == "hackbot-l3"
    assert result.forced_command == _BROKER_PATH
    assert result.permitted_signer_sha256 == "sha256:" + "b" * 64
    with pytest.raises((AttributeError, TypeError)):
        result.ssh_user = "root"


@pytest.mark.parametrize("shape", ["missing", "unknown", "tag", "self-report"])
def test_field_set_is_exact(shape: str) -> None:
    """Catch optional authority or identity claims outside the closed contract."""

    document = _document()
    if shape == "missing":
        document.pop("broker_sha256")
    elif shape == "unknown":
        document["unknown"] = True
    elif shape == "tag":
        document["image_tag"] = "latest"
    else:
        document["runtime_self_report"] = "trusted"
    with pytest.raises(ContractError) as excinfo:
        _module().validate_l3_deployment(document)
    assert excinfo.value.reason_code is ReasonCode.INVALID_RUNNER


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("broker_path", "hackbot-l3-runner"),
        ("broker_path", "/opt/hackbot-l3-runner"),
        ("forced_command", "/bin/sh"),
        ("forced_command", _BROKER_PATH + " --debug"),
        ("ssh_user", "root"),
        ("broker_sha256", "a" * 64),
        ("broker_sha256", "sha256:" + "A" * 64),
        ("permitted_signer_sha256", "sha256:" + "b" * 63),
    ],
)
def test_identity_path_and_digest_drift_denies(field: str, value: object) -> None:
    """Catch mutable path, user, version, or digest deployment identity."""

    document = _document()
    document[field] = value
    with pytest.raises(ContractError) as excinfo:
        _module().validate_l3_deployment(document)
    assert excinfo.value.reason_code is ReasonCode.INVALID_RUNNER


@pytest.mark.parametrize(
    "field",
    ["interactive_shell", "tty", "port_forwarding", "agent_forwarding", "x11_forwarding"],
)
@pytest.mark.parametrize("value", [True, 0, None, "false"])
def test_every_interactive_or_forwarding_feature_is_exact_false(field: str, value: object) -> None:
    """Catch truthy values and non-boolean lookalikes enabling SSH features."""

    document = copy.deepcopy(_document())
    document[field] = value
    with pytest.raises(ContractError) as excinfo:
        _module().validate_l3_deployment(document)
    assert excinfo.value.reason_code is ReasonCode.INVALID_RUNNER
