"""Exact, complete P5b catalog contracts and authority bindings."""

from __future__ import annotations

import copy
import importlib
import importlib.util
import json
from pathlib import Path

import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode

_GOLDEN = Path("tests/fixtures/engagement_v2_l3/catalog-v1.json")
_EXPECTED_IDS = (
    "operator.internal.directory.policies",
    "operator.internal.directory.spns",
    "operator.internal.directory.adcs",
    "operator.internal.directory.graph",
    "operator.internal.credential.asrep",
    "operator.internal.credential.kerberoast",
    "operator.internal.credential.laps",
    "operator.internal.credential.gmsa",
    "operator.internal.validation.password-spray",
    "operator.internal.responder.analyze",
    "operator.internal.responder.capture",
    "operator.internal.exploit.verify",
    "operator.internal.payload.verify",
    "operator.internal.lateral.verify",
    "operator.internal.persistence.verify",
)


def test_complete_catalog_matches_independent_golden() -> None:
    """Catch any missing, partial, reordered, or drifted complete definition."""

    module_name = "hackbot.engagement_v2.l3_contracts"
    assert importlib.util.find_spec(module_name) is not None, "complete contracts module is absent"
    contracts_module = importlib.import_module(module_name)

    expected = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    actual = contracts_module.complete_catalog_document()
    assert actual == expected

    contracts = contracts_module.validate_complete_catalog(expected, project_root=Path.cwd())
    assert tuple(contracts) == _EXPECTED_IDS


@pytest.mark.parametrize(
    ("section", "replacement"),
    [
        ("adapter_id", "operator-controlled"),
        ("image_key", "latest"),
        ("input_schema", {"additional_properties": True}),
        ("network_policy", {"mode": "unrestricted"}),
        ("rate_policy", {"kind": "none"}),
        ("evidence_schema", {"mode": "redacted-output"}),
        ("cleanup_contract", {"target": "optional"}),
    ],
)
def test_complete_definition_mutation_denies(section: str, replacement: object) -> None:
    """Catch a validator that stops enforcing any complete-definition section."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    document = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    document["actions"][0][section] = replacement

    with pytest.raises(ContractError) as excinfo:
        contracts_module.validate_complete_catalog(document, project_root=Path.cwd())
    assert excinfo.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST


def test_manifest_capability_drift_denies() -> None:
    """Catch acceptance of an excluded or non-golden capability set."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    document = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    document["actions"][0]["manifest"]["capabilities"].append("denial-of-service")

    with pytest.raises(ContractError) as excinfo:
        contracts_module.validate_complete_catalog(document, project_root=Path.cwd())
    assert excinfo.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST


@pytest.mark.parametrize("mutation", ["shell", "raw-input", "arbitrary-argv"])
def test_generic_execution_surface_denies(mutation: str) -> None:
    """Catch any reintroduction of shell or operator-controlled execution inputs."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    document = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    manifest = document["actions"][0]["manifest"]
    if mutation == "shell":
        manifest["executables"] = {"linux": "/bin/bash"}
        manifest["argv"] = ["true"]
    elif mutation == "raw-input":
        manifest["parameters"]["module"] = {
            "type": "string",
            "required": True,
            "max_length": 512,
        }
    else:
        manifest["argv"].append("--operator-module")

    with pytest.raises(ContractError) as excinfo:
        contracts_module.validate_complete_catalog(document, project_root=Path.cwd())
    assert excinfo.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST


@pytest.mark.parametrize("mutation", ["missing", "extra", "reordered"])
def test_exact_ordered_action_set_denies_drift(mutation: str) -> None:
    """Catch missing, extra, or reordered reviewed action definitions."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    document = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    if mutation == "missing":
        document["actions"].pop()
    elif mutation == "extra":
        extra = copy.deepcopy(document["actions"][-1])
        extra["manifest"]["id"] = "operator.internal.persistence.unreviewed"
        document["actions"].append(extra)
    else:
        document["actions"][0], document["actions"][1] = (
            document["actions"][1],
            document["actions"][0],
        )

    with pytest.raises(ContractError) as excinfo:
        contracts_module.validate_complete_catalog(document, project_root=Path.cwd())
    assert excinfo.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST


def test_nonexistent_local_provenance_denies() -> None:
    """Catch provenance that is exact-looking but has no reviewed local source."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    document = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    document["actions"][0]["provenance"]["local_path"] = "skills/missing.md"

    with pytest.raises(ContractError) as excinfo:
        contracts_module.validate_complete_catalog(document, project_root=Path.cwd())
    assert excinfo.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST
