"""P5a non-credential internal-recon catalog: classification, provenance, guard."""

from __future__ import annotations

import copy

import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.manifest import validate_manifest
from hackbot.engagement_v2.policy import _CAPABILITY_RISK_FLOOR
from hackbot.engagement_v2.recon_catalog import (
    FORBIDDEN_CAPABILITIES,
    _catalog_manifest,
    load_catalog,
    provenance,
)

_EXPECTED_IDS = {
    "operator.internal.netstate.interfaces",
    "operator.internal.netstate.routes",
    "operator.internal.netstate.neighbors",
    "operator.internal.netstate.listeners",
    "operator.internal.discovery.arp-sweep",
    "operator.internal.discovery.icmp-sweep",
    "operator.internal.enum.service-ports",
    "operator.internal.ldap.naming-contexts",
    "operator.internal.ldap.anonymous-users",
}


def _registry():
    return load_catalog(active_profile="local-lab", internal_recon_confirmed=True)


# ------------------------------------------------------- manifest validity ---
def test_catalog_validates_as_a_manifest() -> None:
    registry = _registry()
    assert set(registry) == _EXPECTED_IDS


def test_every_action_is_non_credential() -> None:
    registry = _registry()
    for action in registry.values():
        assert action.risk in {"L1", "L2"}
        assert not (action.capabilities & FORBIDDEN_CAPABILITIES)


def test_scanning_actions_declare_automated_scanning() -> None:
    registry = _registry()
    for action_id, action in registry.items():
        if action.risk == "L2":
            assert "automated-scanning" in action.capabilities, action_id


def test_a_credential_action_is_caught_by_disjointness() -> None:
    # Simulate adding a credential action; the guard set must flag it.
    document = _catalog_manifest()
    document["actions"][0]["capabilities"] = ["credential-access"]
    registry = validate_manifest(document)
    offending = {
        aid for aid, action in registry.items() if action.capabilities & FORBIDDEN_CAPABILITIES
    }
    assert offending  # the classification guard would fail on this


def test_forbidden_set_covers_policy_l3_floor() -> None:
    # The non-credential guard must exclude every capability whose policy risk
    # floor is L3, so a mis-declared L2 action carrying an L3 capability is caught.
    l3_capabilities = {cap for cap, floor in _CAPABILITY_RISK_FLOOR.items() if floor == "L3"}
    assert l3_capabilities <= FORBIDDEN_CAPABILITIES


# ------------------------------------------------------------- provenance ---
def test_every_action_has_provenance() -> None:
    registry = _registry()
    records = provenance()
    assert set(records) == set(registry)
    for action_id, action in registry.items():
        record = records[action_id]
        assert record.risk == action.risk
        assert record.capabilities == action.capabilities
        assert "cyberneon" in record.attribution.lower()
        assert not (record.capabilities & FORBIDDEN_CAPABILITIES)


# --------------------------------------------------- disabled by default ---
def test_catalog_denied_for_unauthorized_profile() -> None:
    """An unrecognized profile name still denies internal recon."""
    with pytest.raises(ContractError) as excinfo:
        load_catalog(active_profile="nonexistent-profile", internal_recon_confirmed=True)
    assert excinfo.value.reason_code is ReasonCode.DENY_CAPABILITY_NOT_ALLOWED


def test_catalog_enabled_for_bug_bounty_with_confirmation() -> None:
    """bug-bounty profile NOW allows internal recon — operator responsibility."""
    registry = load_catalog(active_profile="bug-bounty", internal_recon_confirmed=True)
    assert len(registry) > 0
    assert "operator.internal.discovery.arp-sweep" in registry


def test_catalog_disabled_without_confirmation() -> None:
    with pytest.raises(ContractError):
        load_catalog(active_profile="local-lab", internal_recon_confirmed=False)


def test_catalog_loads_under_authorized_internal_profile() -> None:
    registry = load_catalog(active_profile="local-lab", internal_recon_confirmed=True)
    assert set(registry) == _EXPECTED_IDS


def test_manifest_document_is_not_mutated_by_load(monkeypatch: pytest.MonkeyPatch) -> None:
    before = copy.deepcopy(_catalog_manifest())
    load_catalog(active_profile="private-pentest", internal_recon_confirmed=True)
    assert _catalog_manifest() == before


# ------------------------------------------------- no live scanning ---
def test_catalog_module_does_not_execute() -> None:
    import ast
    from pathlib import Path

    source = Path("src/hackbot/engagement_v2/recon_catalog.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_modules = {"subprocess", "socket", "asyncio"}
    forbidden_calls = {"system", "popen", "run", "call", "Popen", "spawn"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in forbidden_modules
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden_modules
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in forbidden_calls


def test_lab_fixture_is_synthetic() -> None:
    import json
    from pathlib import Path

    data = json.loads(Path("tests/fixtures/engagement_v2_recon/lab-targets.json").read_text())
    text = json.dumps(data).lower()
    for marker in ("password", "secret", "token", "private key", "begin rsa"):
        assert marker not in text
    assert all(s.startswith(("10.", "192.0.2.", "192.168.", "172.")) for s in data["subnets"])
