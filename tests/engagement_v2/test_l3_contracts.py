"""Exact, complete P5b catalog contracts and authority bindings."""

from __future__ import annotations

import copy
import importlib
import importlib.util
import json
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.loader import EngagementSnapshot
from hackbot.engagement_v2.manifest import CAPABILITY_TO_FIELD
from hackbot.engagement_v2.policy import DecisionKind

from ._engagement_builders import program_doc, scope_doc

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


def _snapshot(
    *,
    enabled: set[str] | frozenset[str] = frozenset(),
    omitted: set[str] | frozenset[str] = frozenset(),
    profile: str = "local-lab",
    confirmed: object = True,
) -> EngagementSnapshot:
    program = program_doc()
    program["profile"] = profile
    testing_rules = program["testing_rules"]
    for capability, field in CAPABILITY_TO_FIELD.items():
        if capability not in omitted:
            testing_rules[field] = capability in enabled
    authority_digest = "sha256:" + "a" * 64
    authorization = {
        "confirmed": confirmed,
        "confirmed_authority_digest": authority_digest,
    }
    return EngagementSnapshot(
        program=MappingProxyType(program),
        scope=MappingProxyType(scope_doc()),
        authorization=MappingProxyType(authorization),
        runner=None,
        profile=profile,
        authority_digest=authority_digest,
        identity="engagement-v2:synthetic-authority",
    )


def _request(action_id: str = "operator.internal.payload.verify") -> dict[str, object]:
    return {
        "schema_version": 2,
        "action_id": action_id,
        "parameters": {"host": "https://app.corp.example/admin"},
        "hypothesis_id": "synthetic-lab-hypothesis",
        "rationale": "validate the isolated example lab control",
        "expected_impact": "minimal synthetic proof only",
        "stop_condition": "stop after one bounded attempt",
        "cleanup_plan": "run the code-owned cleanup action",
    }


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


def test_same_snapshot_activates_evaluates_and_binds() -> None:
    """Catch activation or binding that is not anchored to one snapshot."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    assert callable(getattr(contracts_module, "activate_catalog", None))
    assert callable(getattr(contracts_module, "decide_l3", None))
    snapshot = _snapshot(enabled={"payload-execution", "state-changing"})

    activation = contracts_module.activate_catalog(
        snapshot,
        internal_recon_confirmed=True,
        project_root=Path.cwd(),
    )
    decision = contracts_module.decide_l3(
        _request(),
        snapshot,
        activation,
        platform="linux",
    )

    assert activation.binding.snapshot_identity == snapshot.identity
    assert activation.binding.profile == snapshot.profile
    assert activation.binding.authority_digest == snapshot.authority_digest
    assert decision.kind is DecisionKind.ALLOW
    assert decision.bound is not None


@pytest.mark.parametrize("field", ["identity", "profile", "authority_digest"])
def test_snapshot_change_after_activation_denies_stale(field: str) -> None:
    """Catch policy evaluation against a snapshot different from activation."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    snapshot = _snapshot(enabled={"payload-execution", "state-changing"})
    activation = contracts_module.activate_catalog(
        snapshot,
        internal_recon_confirmed=True,
        project_root=Path.cwd(),
    )
    replacement = {
        "identity": "engagement-v2:changed",
        "profile": "private-pentest",
        "authority_digest": "sha256:" + "f" * 64,
    }[field]

    with pytest.raises(ContractError) as excinfo:
        contracts_module.decide_l3(
            _request(),
            replace(snapshot, **{field: replacement}),
            activation,
            platform="linux",
        )
    assert excinfo.value.reason_code is ReasonCode.DENY_AUTHORIZATION_STALE


@pytest.mark.parametrize(
    ("profile", "confirmed", "internal_confirmed"),
    [
        ("bug-bounty", True, True),
        ("local-lab", False, True),
        ("private-pentest", True, False),
    ],
)
def test_activation_requires_internal_profile_and_both_confirmations(
    profile: str, confirmed: object, internal_confirmed: bool
) -> None:
    """Catch source presence or a profile name enabling the catalog by itself."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    snapshot = _snapshot(profile=profile, confirmed=confirmed)

    with pytest.raises(ContractError) as excinfo:
        contracts_module.activate_catalog(
            snapshot,
            internal_recon_confirmed=internal_confirmed,
            project_root=Path.cwd(),
        )
    assert excinfo.value.reason_code is ReasonCode.DENY_AUTHORIZATION_UNCONFIRMED


def test_activation_rejects_snapshot_lookalike() -> None:
    """Catch structurally similar mutable objects crossing the authority boundary."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    snapshot = _snapshot()
    lookalike = SimpleNamespace(**snapshot.__dict__)

    with pytest.raises(ContractError) as excinfo:
        contracts_module.activate_catalog(
            lookalike,
            internal_recon_confirmed=True,
            project_root=Path.cwd(),
        )
    assert excinfo.value.reason_code is ReasonCode.INVALID_REQUEST


@pytest.mark.parametrize("missing_kind", ["absent", "false", "non-boolean"])
def test_profile_never_grants_a_missing_capability(missing_kind: str) -> None:
    """Catch profile-based capability grants or truthy non-boolean flags."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    required = {"payload-execution", "state-changing"}
    missing = "state-changing"
    snapshot = _snapshot(
        enabled=required - {missing},
        omitted={missing} if missing_kind == "absent" else frozenset(),
    )
    if missing_kind == "non-boolean":
        snapshot.program["testing_rules"][CAPABILITY_TO_FIELD[missing]] = "true"
    activation = contracts_module.activate_catalog(
        snapshot,
        internal_recon_confirmed=True,
        project_root=Path.cwd(),
    )

    decision = contracts_module.decide_l3(_request(), snapshot, activation, platform="linux")
    assert decision.kind is DecisionKind.DENY
    assert decision.reason == ReasonCode.DENY_CAPABILITY_NOT_ALLOWED.value
    assert decision.bound is None


@pytest.mark.parametrize("override", ["executable", "argv", "argv0"])
def test_request_cannot_override_execution_surface(override: str) -> None:
    """Catch request-controlled executable or argv entering the bound command."""

    contracts_module = importlib.import_module("hackbot.engagement_v2.l3_contracts")
    snapshot = _snapshot(enabled={"payload-execution", "state-changing"})
    activation = contracts_module.activate_catalog(
        snapshot,
        internal_recon_confirmed=True,
        project_root=Path.cwd(),
    )
    request = _request()
    request[override] = ["operator-controlled"] if override == "argv" else "/bin/sh"

    with pytest.raises(ContractError) as excinfo:
        contracts_module.decide_l3(request, snapshot, activation, platform="linux")
    assert excinfo.value.reason_code is ReasonCode.INVALID_REQUEST


def test_profile_string_loader_cannot_activate_l3_catalog() -> None:
    """Catch restoration of the prototype profile-only authority entry point."""

    catalog_module = importlib.import_module("hackbot.engagement_v2.l3_catalog")
    assert not hasattr(catalog_module, "load_catalog")
    assert callable(getattr(catalog_module, "_load_catalog_fixture", None))
