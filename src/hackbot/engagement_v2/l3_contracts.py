"""Complete, inert contracts for the reviewed P5b L3 catalog.

This module defines authority data only. It cannot execute an adapter, resolve a
secret, create a resource, or make an action executable.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TypeAlias

from hackbot.engagement_v2.canonical import canonical_bytes, digest_value
from hackbot.engagement_v2.constants import ACTIONS_SCHEMA_VERSION, Profile
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.l3_catalog import _SPECS, _catalog_manifest
from hackbot.engagement_v2.loader import EngagementSnapshot
from hackbot.engagement_v2.manifest import ActionDefinition, validate_manifest
from hackbot.engagement_v2.policy import PolicyDecision, decide
from hackbot.engagement_v2.projection import (
    engagement_identity,
    projection_digest,
    security_projection,
)

_CONTRACT_SCHEMA_VERSION = 1
_DEFINITION_DIGEST_DOMAIN = "hackbot-l3-action-definition-v1"
_PROVENANCE_PATH = "skills/internal-recon/credential-l3-catalog.md"
_ATTRIBUTION = (
    "CyberNeon Recon Bundle (public source; no formal license), reviewed single-action subset"
)
_COMPLETE_FIELDS = frozenset(
    {
        "manifest",
        "adapter_id",
        "image_key",
        "input_schema",
        "network_policy",
        "rate_policy",
        "evidence_schema",
        "cleanup_contract",
        "provenance",
    }
)

_ACTION_META: Mapping[str, tuple[str, str, str]] = MappingProxyType(
    {
        "operator.internal.directory.policies": (
            "l3.directory.policies.v1",
            "openldap",
            "directory-policy-summary-v1",
        ),
        "operator.internal.directory.spns": (
            "l3.directory.spns.v1",
            "openldap",
            "spn-summary-v1",
        ),
        "operator.internal.directory.adcs": (
            "l3.directory.adcs.v1",
            "certipy",
            "adcs-summary-v1",
        ),
        "operator.internal.directory.graph": (
            "l3.directory.graph.v1",
            "bloodhound",
            "directory-graph-summary-v1",
        ),
        "operator.internal.credential.asrep": (
            "l3.credential.asrep.v1",
            "impacket",
            "asrep-summary-v1",
        ),
        "operator.internal.credential.kerberoast": (
            "l3.credential.kerberoast.v1",
            "impacket",
            "kerberoast-summary-v1",
        ),
        "operator.internal.credential.laps": (
            "l3.credential.laps.v1",
            "netexec",
            "laps-summary-v1",
        ),
        "operator.internal.credential.gmsa": (
            "l3.credential.gmsa.v1",
            "netexec",
            "gmsa-summary-v1",
        ),
        "operator.internal.validation.password-spray": (
            "l3.validation.password-spray.v1",
            "netexec",
            "password-validation-summary-v1",
        ),
        "operator.internal.responder.analyze": (
            "l3.responder.analyze.v1",
            "responder",
            "responder-analysis-summary-v1",
        ),
        "operator.internal.responder.capture": (
            "l3.responder.capture.v1",
            "responder",
            "responder-capture-summary-v1",
        ),
        "operator.internal.exploit.verify": (
            "l3.exploit.verify.v1",
            "lab_exploit",
            "exploit-proof-summary-v1",
        ),
        "operator.internal.payload.verify": (
            "l3.payload.verify.v1",
            "payload_proof",
            "payload-proof-summary-v1",
        ),
        "operator.internal.lateral.verify": (
            "l3.lateral.verify.v1",
            "lateral_ssh",
            "lateral-proof-summary-v1",
        ),
        "operator.internal.persistence.verify": (
            "l3.persistence.verify.v1",
            "persistence_proof",
            "persistence-proof-summary-v1",
        ),
    }
)

# role, request field, schemes, protocols, minimum, maximum, host kind
_NetworkBinding: TypeAlias = tuple[str, str, tuple[str, ...], tuple[str, ...], int, int, str]
_NETWORK_BINDINGS: Mapping[str, tuple[_NetworkBinding, ...]] = MappingProxyType(
    {
        "operator.internal.directory.policies": (
            ("directory", "endpoint", ("ldap", "ldaps"), ("tcp",), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.directory.spns": (
            ("directory", "endpoint", ("ldap", "ldaps"), ("tcp",), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.directory.adcs": (
            ("directory", "host", ("ldap", "ldaps"), ("tcp",), 1, 1, "hostname-or-ip"),
            (
                "kerberos",
                "kerberos_endpoint",
                ("kerberos",),
                ("udp", "tcp"),
                1,
                1,
                "hostname-or-ip",
            ),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.directory.graph": (
            ("directory", "host", ("ldap", "ldaps"), ("tcp",), 1, 1, "hostname-or-ip"),
            (
                "kerberos",
                "kerberos_endpoint",
                ("kerberos",),
                ("udp", "tcp"),
                1,
                1,
                "hostname-or-ip",
            ),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.credential.asrep": (
            ("kerberos", "host", ("kerberos",), ("udp", "tcp"), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.credential.kerberoast": (
            ("directory", "host", ("ldap", "ldaps"), ("tcp",), 1, 1, "hostname-or-ip"),
            (
                "kerberos",
                "kerberos_endpoint",
                ("kerberos",),
                ("udp", "tcp"),
                1,
                1,
                "hostname-or-ip",
            ),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.credential.laps": (
            ("directory", "host", ("ldap", "ldaps"), ("tcp",), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.credential.gmsa": (
            ("directory", "host", ("ldap", "ldaps"), ("tcp",), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.validation.password-spray": (
            ("smb", "host", ("smb",), ("tcp",), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.responder.analyze": (
            ("authorized-subnet", "subnet", ("cidr",), ("udp", "tcp"), 1, 1, "cidr"),
        ),
        "operator.internal.responder.capture": (
            ("authorized-subnet", "subnet", ("cidr",), ("udp", "tcp"), 1, 1, "cidr"),
        ),
        "operator.internal.exploit.verify": (
            ("proof-target", "host", ("http", "https"), ("tcp",), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.payload.verify": (
            ("proof-target", "host", ("https",), ("tcp",), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.lateral.verify": (
            ("ssh-target", "host", ("ssh",), ("tcp",), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
        "operator.internal.persistence.verify": (
            ("ssh-target", "host", ("ssh",), ("tcp",), 1, 1, "hostname-or-ip"),
            ("dns-resolver", "dns_resolver", ("dns",), ("udp", "tcp"), 0, 1, "ip-literal"),
        ),
    }
)


@dataclass(frozen=True)
class L3ActionContract:
    """One exact reviewed definition and its canonical identity."""

    action: ActionDefinition
    adapter_id: str
    image_key: str
    input_schema: Mapping[str, object]
    network_policy: Mapping[str, object]
    rate_policy: Mapping[str, object]
    evidence_schema: Mapping[str, object]
    cleanup_contract: Mapping[str, object]
    provenance: Mapping[str, object]
    definition_digest: str


@dataclass(frozen=True)
class SnapshotBinding:
    """The exact immutable authority identity used for catalog activation."""

    snapshot_identity: str
    profile: str
    authority_digest: str


@dataclass(frozen=True)
class ActivatedL3Catalog:
    """Complete contracts activated for exactly one confirmed snapshot."""

    binding: SnapshotBinding
    actions: Mapping[str, L3ActionContract]


def _input_schema(action_id: str, manifest: Mapping[str, object]) -> dict[str, object]:
    fields: dict[str, object] = {}
    for (
        _role,
        binding_field,
        _schemes,
        _protocols,
        minimum,
        maximum,
        host_kind,
    ) in _NETWORK_BINDINGS[action_id]:
        fields[binding_field] = {
            "kind": "cidr" if host_kind == "cidr" else "network-endpoint",
            "required": minimum == 1,
            "max_items": maximum,
        }

    parameters = manifest["parameters"]
    assert isinstance(parameters, Mapping)
    for name, raw in parameters.items():
        assert isinstance(name, str) and isinstance(raw, Mapping)
        parameter_field: dict[str, object] = {
            "kind": raw["type"],
            "required": raw["required"],
        }
        if "max_length" in raw:
            parameter_field["max_length"] = raw["max_length"]
        if "enum_values" in raw:
            enum_values = raw["enum_values"]
            assert isinstance(enum_values, Sequence) and not isinstance(enum_values, str | bytes)
            parameter_field["enum_values"] = list(enum_values)
        fields[name] = parameter_field

    secrets = manifest["secrets"]
    assert isinstance(secrets, Mapping)
    for name in secrets:
        fields[str(name)] = {"kind": "secret-reference", "required": True}

    if action_id.endswith("password-spray"):
        fields.update(
            {
                "accounts": {
                    "kind": "string-list",
                    "required": True,
                    "min_items": 1,
                    "max_items": 25,
                    "max_item_bytes": 256,
                },
                "lockout_threshold": {
                    "kind": "integer",
                    "required": True,
                    "minimum": 2,
                    "maximum": 2_147_483_647,
                },
                "lockout_observed_at": {"kind": "timestamp", "required": True},
            }
        )
    elif action_id.endswith((".asrep", ".kerberoast")):
        fields["principals"] = {
            "kind": "string-list",
            "required": True,
            "min_items": 1,
            "max_items": 25,
            "max_item_bytes": 256,
        }
    elif action_id.endswith(".laps"):
        fields["computers"] = {
            "kind": "string-list",
            "required": True,
            "min_items": 1,
            "max_items": 25,
            "max_item_bytes": 256,
        }
    elif action_id.endswith(".gmsa"):
        fields["accounts"] = {
            "kind": "string-list",
            "required": True,
            "min_items": 1,
            "max_items": 25,
            "max_item_bytes": 256,
        }
    elif ".responder." in action_id:
        fields["interface"] = {
            "kind": "interface-name",
            "required": True,
            "max_length": 64,
        }
    return {"additional_properties": False, "fields": fields}


def _network_policy(action_id: str) -> dict[str, object]:
    bindings = []
    for role, field, schemes, protocols, minimum, maximum, host_kind in _NETWORK_BINDINGS[
        action_id
    ]:
        bindings.append(
            {
                "role": role,
                "field": field,
                "schemes": list(schemes),
                "protocols": list(protocols),
                "minimum": minimum,
                "maximum": maximum,
                "host_kind": host_kind,
            }
        )
    return {
        "mode": "default-deny",
        "endpoint_authority": "request-explicit",
        "port_authority": "request-explicit",
        "resolver_policy": "explicit-for-hostnames",
        "answer_set": "exact",
        "redirects": False,
        "proxies": False,
        "discovery": False,
        "bindings": bindings,
    }


def _rate_policy(action_id: str) -> dict[str, object]:
    if action_id.endswith("password-spray"):
        return {
            "kind": "durable-account-budget",
            "max_concurrency": 1,
            "minimum_interval_seconds": 30,
            "maximum_targets": 1,
            "maximum_accounts": 25,
            "maximum_candidates": 1,
        }
    if ".responder." in action_id:
        return {
            "kind": "bounded-observation",
            "max_concurrency": 1,
            "minimum_interval_seconds": 0,
            "maximum_targets": 1,
            "maximum_duration_seconds": 120,
        }
    return {
        "kind": "single-run",
        "max_concurrency": 1,
        "minimum_interval_seconds": 0,
        "maximum_targets": 1,
    }


def complete_catalog_document() -> dict[str, object]:
    """Return a fresh JSON-compatible copy of the exact code-owned catalog."""

    manifest_document = _catalog_manifest()
    raw_actions = manifest_document["actions"]
    assert isinstance(raw_actions, Sequence)
    specs = {spec.action_id: spec for spec in _SPECS}
    complete_actions: list[dict[str, object]] = []
    for raw in raw_actions:
        assert isinstance(raw, Mapping)
        action_id = raw["id"]
        assert isinstance(action_id, str)
        adapter_id, image_key, evidence_schema_id = _ACTION_META[action_id]
        spec = specs[action_id]
        characteristics = raw["characteristics"]
        assert isinstance(characteristics, Mapping)
        mutable = bool(characteristics["state_changing"])
        complete_actions.append(
            {
                "manifest": copy.deepcopy(dict(raw)),
                "adapter_id": adapter_id,
                "image_key": image_key,
                "input_schema": _input_schema(action_id, raw),
                "network_policy": _network_policy(action_id),
                "rate_policy": _rate_policy(action_id),
                "evidence_schema": {
                    "mode": "metadata-only",
                    "schema_id": evidence_schema_id,
                    "additional_properties": False,
                },
                "cleanup_contract": {
                    "resource": "required",
                    "target": "required" if mutable else "not-applicable",
                    "block_on_target_failure": mutable,
                },
                "provenance": {
                    "local_path": _PROVENANCE_PATH,
                    "category": spec.category,
                    "classification": spec.classification,
                    "labels": list(spec.labels),
                    "attribution": _ATTRIBUTION,
                },
            }
        )
    return {"schema_version": _CONTRACT_SCHEMA_VERSION, "actions": complete_actions}


def definition_digest(raw: Mapping[str, object]) -> str:
    """Return the domain-separated digest of one complete definition."""

    return digest_value({"contract": _DEFINITION_DIGEST_DOMAIN, "value": dict(raw)})


def _fail() -> ContractError:
    return ContractError(ReasonCode.INVALID_ACTION_MANIFEST)


def _canonical_equal(left: object, right: object) -> bool:
    try:
        return canonical_bytes(left) == canonical_bytes(right)
    except ContractError:
        return False


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return tuple(_freeze(item) for item in value)
    return value


def _valid_provenance(raw: Mapping[str, object], project_root: Path) -> bool:
    provenance = raw.get("provenance")
    if not isinstance(provenance, Mapping):
        return False
    local_path = provenance.get("local_path")
    if not isinstance(local_path, str) or Path(local_path).is_absolute():
        return False
    try:
        root = project_root.resolve(strict=True)
        candidate = (root / local_path).resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError):
        return False
    return candidate.is_file()


def validate_complete_catalog(
    document: Mapping[str, object], *, project_root: Path
) -> Mapping[str, L3ActionContract]:
    """Validate the exact catalog and return immutable ordered contracts."""

    if not _canonical_equal(document, complete_catalog_document()):
        raise _fail()
    actions = document.get("actions")
    if not isinstance(actions, Sequence) or isinstance(actions, str | bytes):
        raise _fail()
    manifest_document = {
        "schema_version": ACTIONS_SCHEMA_VERSION,
        "actions": [raw["manifest"] for raw in actions if isinstance(raw, Mapping)],
    }
    try:
        registry = validate_manifest(manifest_document)
    except ContractError as exc:
        raise _fail() from exc
    if len(registry) != len(actions):
        raise _fail()

    contracts: dict[str, L3ActionContract] = {}
    for raw in actions:
        if not isinstance(raw, Mapping) or set(raw) != _COMPLETE_FIELDS:
            raise _fail()
        manifest = raw.get("manifest")
        if not isinstance(manifest, Mapping):
            raise _fail()
        action_id = manifest.get("id")
        if not isinstance(action_id, str) or not _valid_provenance(raw, project_root):
            raise _fail()
        contracts[action_id] = L3ActionContract(
            action=registry[action_id],
            adapter_id=str(raw["adapter_id"]),
            image_key=str(raw["image_key"]),
            input_schema=_freeze(raw["input_schema"]),  # type: ignore[arg-type]
            network_policy=_freeze(raw["network_policy"]),  # type: ignore[arg-type]
            rate_policy=_freeze(raw["rate_policy"]),  # type: ignore[arg-type]
            evidence_schema=_freeze(raw["evidence_schema"]),  # type: ignore[arg-type]
            cleanup_contract=_freeze(raw["cleanup_contract"]),  # type: ignore[arg-type]
            provenance=_freeze(raw["provenance"]),  # type: ignore[arg-type]
            definition_digest=definition_digest(raw),
        )
    return MappingProxyType(contracts)


def _snapshot_binding(snapshot: object) -> SnapshotBinding:
    if type(snapshot) is not EngagementSnapshot:
        raise ContractError(ReasonCode.INVALID_REQUEST)
    assert isinstance(snapshot, EngagementSnapshot)
    try:
        computed_digest = projection_digest(
            security_projection(
                program=snapshot.program,
                scope=snapshot.scope,
                runner=snapshot.runner,
            )
        )
        computed_identity = engagement_identity(computed_digest)
    except (ContractError, TypeError, ValueError) as exc:
        raise ContractError(ReasonCode.DENY_AUTHORIZATION_STALE) from exc
    if (
        type(snapshot.profile) is not str
        or type(snapshot.authority_digest) is not str
        or type(snapshot.identity) is not str
        or snapshot.program.get("profile") != snapshot.profile
        or snapshot.authorization.get("confirmed_authority_digest") != computed_digest
        or snapshot.authority_digest != computed_digest
        or snapshot.identity != computed_identity
    ):
        raise ContractError(ReasonCode.DENY_AUTHORIZATION_STALE)
    return SnapshotBinding(
        snapshot_identity=snapshot.identity,
        profile=snapshot.profile,
        authority_digest=snapshot.authority_digest,
    )


def activate_catalog(
    snapshot: object,
    *,
    internal_recon_confirmed: bool,
    project_root: Path,
) -> ActivatedL3Catalog:
    """Activate complete definitions for one explicitly confirmed snapshot."""

    binding = _snapshot_binding(snapshot)
    assert isinstance(snapshot, EngagementSnapshot)
    authorized_profiles = {Profile.PRIVATE_PENTEST.value, Profile.LOCAL_LAB.value, Profile.BUG_BOUNTY.value}
    if (
        internal_recon_confirmed is not True
        or snapshot.authorization.get("confirmed") is not True
        or binding.profile not in authorized_profiles
    ):
        raise ContractError(ReasonCode.DENY_AUTHORIZATION_UNCONFIRMED)
    if (
        snapshot.program.get("profile") != binding.profile
        or snapshot.authorization.get("confirmed_authority_digest") != binding.authority_digest
    ):
        raise ContractError(ReasonCode.DENY_AUTHORIZATION_STALE)
    actions = validate_complete_catalog(complete_catalog_document(), project_root=project_root)
    return ActivatedL3Catalog(binding=binding, actions=actions)


def decide_l3(
    request: Mapping[str, object],
    snapshot: object,
    activation: object,
    *,
    platform: str,
) -> PolicyDecision:
    """Evaluate and bind an L3 request only under its activating snapshot."""

    binding = _snapshot_binding(snapshot)
    if type(activation) is not ActivatedL3Catalog:
        raise ContractError(ReasonCode.INVALID_REQUEST)
    assert isinstance(activation, ActivatedL3Catalog)
    if binding != activation.binding:
        raise ContractError(ReasonCode.DENY_AUTHORIZATION_STALE)
    registry = MappingProxyType(
        {action_id: contract.action for action_id, contract in activation.actions.items()}
    )
    return decide(request, snapshot, registry, platform=platform)


__all__ = [
    "ActivatedL3Catalog",
    "L3ActionContract",
    "SnapshotBinding",
    "activate_catalog",
    "complete_catalog_document",
    "decide_l3",
    "definition_digest",
    "validate_complete_catalog",
]
