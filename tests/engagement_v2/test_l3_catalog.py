"""P5b credential/L3 catalog: closed classification, policy, evidence, and guard."""

from __future__ import annotations

import ast
import copy
import importlib
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.evidence import check_evidence_mode
from hackbot.engagement_v2.manifest import CAPABILITY_TO_FIELD, validate_manifest
from hackbot.engagement_v2.policy import DecisionKind, decide

from ._engagement_builders import program_doc, scope_doc

_EXPECTED_IDS = {
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
}
_EXCLUDED_CAPABILITIES = {
    "denial-of-service",
    "destructive-testing",
    "data-exfiltration",
}
_SENSITIVE_CAPABILITIES = {
    "credential-access",
    "credential-capture",
    "sensitive-data-access",
}


def _catalog() -> ModuleType:
    return importlib.import_module("hackbot.engagement_v2.l3_catalog")


def _registry():
    return _catalog().load_catalog(active_profile="local-lab", internal_recon_confirmed=True)


def _raw_actions() -> dict[str, dict[str, object]]:
    document = _catalog()._catalog_manifest()
    return {action["id"]: action for action in document["actions"]}


def _snapshot(*, enabled: set[str], omitted: set[str] = frozenset()) -> SimpleNamespace:
    program = program_doc()
    rules = program["testing_rules"]
    for capability, field in CAPABILITY_TO_FIELD.items():
        if capability not in omitted:
            rules[field] = capability in enabled
    return SimpleNamespace(
        authorization={"confirmed": True},
        program=program,
        scope=scope_doc(),
        profile="local-lab",
    )


def _request(action_id: str) -> dict[str, object]:
    return {
        "schema_version": 2,
        "action_id": action_id,
        "parameters": {"host": "dc01.corp.example"},
        "hypothesis_id": "synthetic-lab-hypothesis",
        "rationale": "validate the isolated example lab control",
        "expected_impact": "minimal synthetic proof only",
        "stop_condition": "stop after one bounded attempt",
        "cleanup_plan": "run the code-owned cleanup action",
    }


# ------------------------------------------------------- manifest validity ---
def test_catalog_validates_and_has_the_reviewed_action_ids() -> None:
    document = _catalog()._catalog_manifest()
    registry = validate_manifest(document)
    assert set(registry) == _EXPECTED_IDS
    assert set(_registry()) == _EXPECTED_IDS


def test_catalog_rejects_shell_inline_eval_and_pipeline_actions() -> None:
    document = _catalog()._catalog_manifest()
    for raw in document["actions"]:
        executable = next(iter(raw["executables"].values()))
        assert Path(executable).is_absolute()
        assert Path(executable).name.lower() not in {
            "bash",
            "cmd",
            "cmd.exe",
            "dash",
            "fish",
            "ksh",
            "powershell",
            "pwsh",
            "sh",
            "zsh",
        }
        assert not ({"|", "||", "&&", ";"} & set(raw["argv"]))

    shell_document = copy.deepcopy(document)
    shell_document["actions"][0]["executables"] = {"linux": "/bin/bash"}
    shell_document["actions"][0]["argv"] = ["-c", "true"]
    with pytest.raises(ContractError):
        _catalog().validate_catalog_manifest(shell_document)

    pipeline_document = copy.deepcopy(document)
    pipeline_document["actions"][0]["argv"].append("|")
    with pytest.raises(ContractError):
        _catalog().validate_catalog_manifest(pipeline_document)


def test_every_action_is_l3_and_excluded_capabilities_are_disjoint() -> None:
    registry = _registry()
    all_capabilities: set[str] = set()
    for action in registry.values():
        assert action.risk == "L3"
        assert action.capabilities
        all_capabilities.update(action.capabilities)
    assert all_capabilities.isdisjoint(_EXCLUDED_CAPABILITIES)


# ------------------------------------------------------ capability policy ---
@pytest.mark.parametrize("missing_kind", ["absent", "false", "non-boolean"])
def test_each_declared_capability_must_be_exactly_true(missing_kind: str) -> None:
    action_id = "operator.internal.payload.verify"
    action = _registry()[action_id]
    assert action.capabilities == frozenset({"payload-execution", "state-changing"})
    missing = "state-changing"
    snapshot = _snapshot(
        enabled=set(action.capabilities) - {missing},
        omitted={missing} if missing_kind == "absent" else set(),
    )
    if missing_kind == "non-boolean":
        snapshot.program["testing_rules"][CAPABILITY_TO_FIELD[missing]] = "true"

    decision = decide(_request(action_id), snapshot, _registry(), platform="linux")
    assert decision.kind is DecisionKind.DENY
    assert decision.reason == ReasonCode.DENY_CAPABILITY_NOT_ALLOWED.value
    assert decision.bound is None


def test_all_declared_capabilities_true_allows_the_gate_without_approval() -> None:
    action_id = "operator.internal.payload.verify"
    capabilities = set(_registry()[action_id].capabilities)
    decision = decide(
        _request(action_id),
        _snapshot(enabled=capabilities),
        _registry(),
        platform="linux",
    )
    assert decision.kind is DecisionKind.ALLOW
    assert decision.reason == "ALLOW"
    assert decision.bound is not None


# --------------------------------------------------------- evidence policy ---
def test_credential_actions_never_declare_redacted_output() -> None:
    registry = _registry()
    sensitive_actions = [
        action for action in registry.values() if action.capabilities & _SENSITIVE_CAPABILITIES
    ]
    assert sensitive_actions
    for action in sensitive_actions:
        assert action.evidence_mode in {"metadata-only", "structured"}
        assert action.evidence_mode != "redacted-output"


def test_credential_action_requesting_redacted_output_is_denied() -> None:
    document = _catalog()._catalog_manifest()
    document["actions"][4]["evidence_policy"] = {"mode": "redacted-output"}
    action = validate_manifest(document)["operator.internal.credential.asrep"]
    with pytest.raises(ContractError) as excinfo:
        check_evidence_mode(
            action.evidence_mode,
            action.capabilities,
            output_persistence_allowed=True,
        )
    assert excinfo.value.reason_code is ReasonCode.EVIDENCE_POLICY_DENIED


def test_closed_structured_evidence_rejects_raw_secret_bytes_and_unknown_fields() -> None:
    schema_id = "principal-summary-v1"
    accepted = _catalog().validate_structured_evidence(
        schema_id,
        {"principal_count": 2, "principal_names": ["alice@example.test", "bob@example.test"]},
    )
    assert accepted["principal_count"] == 2

    with pytest.raises(ContractError) as bytes_exc:
        _catalog().validate_structured_evidence(
            schema_id,
            {"principal_count": 1, "principal_names": [b"raw-secret-bytes"]},
        )
    assert bytes_exc.value.reason_code is ReasonCode.EVIDENCE_POLICY_DENIED

    with pytest.raises(ContractError):
        _catalog().validate_structured_evidence(
            schema_id,
            {"principal_count": 1, "principal_names": ["alice@example.test"], "hash": "x"},
        )


# ----------------------------------------------- capture and provenance ---
def test_capture_and_analyze_are_distinct_and_capture_is_never_passive() -> None:
    registry = _registry()
    raw = _raw_actions()
    records = _catalog().provenance()
    analyze_id = "operator.internal.responder.analyze"
    capture_id = "operator.internal.responder.capture"
    analyze = registry[analyze_id]
    capture = registry[capture_id]

    assert analyze.capabilities != capture.capabilities
    assert "credential-capture" not in analyze.capabilities
    assert capture.risk == "L3"
    assert "credential-capture" in capture.capabilities
    assert "state-changing" in capture.capabilities
    assert raw[capture_id]["characteristics"]["state_changing"] is True
    assert raw[capture_id]["characteristics"]["touches_third_party"] is True
    assert records[capture_id].classification == "credential-capture"
    assert not ({"passive", "discovery"} & set(records[capture_id].labels))


def test_every_action_has_reviewed_non_excluded_provenance() -> None:
    registry = _registry()
    records = _catalog().provenance()
    assert set(records) == set(registry)
    for action_id, action in registry.items():
        record = records[action_id]
        assert record.action_id == action_id
        assert record.risk == "L3"
        assert record.capabilities == action.capabilities
        assert record.source_skill.startswith("internal-recon/")
        assert record.category
        assert record.classification
        assert "reeshasx" in record.attribution
        normalized = " ".join(
            (record.source_skill, record.category, record.classification, *record.labels)
        ).lower()
        assert not any(
            term in normalized
            for term in ("denial-of-service", "destructive", "exfiltration", "evasion")
        )


# --------------------------------------------------- disabled by default ---
@pytest.mark.parametrize(
    ("profile", "confirmed"),
    [(None, False), ("bug-bounty", True), ("private-pentest", False), ("local-lab", False)],
)
def test_catalog_is_disabled_without_internal_profile_and_confirmation(
    profile: str | None, confirmed: bool
) -> None:
    with pytest.raises(ContractError) as excinfo:
        _catalog().load_catalog(
            active_profile=profile,
            internal_recon_confirmed=confirmed,
        )
    assert excinfo.value.reason_code is ReasonCode.DENY_CAPABILITY_NOT_ALLOWED


def test_catalog_module_has_no_live_execution_path() -> None:
    source_path = Path("src/hackbot/engagement_v2/l3_catalog.py")
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_modules = {"asyncio", "socket", "subprocess"}
    forbidden_calls = {"Popen", "call", "popen", "run", "spawn", "system"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] not in forbidden_modules for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden_modules
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in forbidden_calls
