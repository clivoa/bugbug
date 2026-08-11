"""Reviewed credential and L3 internal-pentest action catalog (P5b).

The module contains inert, code-owned manifest data.  It deliberately has no
tool execution path: callers must first load it under an explicitly confirmed
internal profile, then pass an action through the existing P2/P3/P4 gate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from hackbot.engagement_v2.constants import (
    ACTIONS_SCHEMA_VERSION,
    INTERPRETER_BASENAMES,
    SHELL_BASENAMES,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.manifest import ActionDefinition, validate_manifest

_ATTRIBUTION = (
    "reviewed single-action subset from reference methodologies"
)
EXCLUDED_CAPABILITIES = frozenset({"denial-of-service", "destructive-testing", "data-exfiltration"})
_SENSITIVE_CAPABILITIES = frozenset(
    {"credential-access", "credential-capture", "sensitive-data-access"}
)
_SHELL_CONTROL_FRAGMENTS = ("|", "&&", ";", "$(", "`", "\r", "\n")


@dataclass(frozen=True)
class L3Provenance:
    action_id: str
    category: str
    source_skill: str
    classification: str
    risk: str
    capabilities: frozenset[str]
    labels: tuple[str, ...]
    attribution: str


@dataclass(frozen=True)
class _ActionSpec:
    action_id: str
    title: str
    category: str
    source_skill: str
    classification: str
    executable: str
    argv: tuple[str, ...]
    targets: tuple[str, ...]
    parameters: Mapping[str, object]
    secrets: Mapping[str, object]
    capabilities: tuple[str, ...]
    labels: tuple[str, ...] = ()
    state_changing: bool = False
    touches_third_party: bool = False
    high_volume: bool = False


_STRING_PARAMETER: Mapping[str, object] = MappingProxyType(
    {"type": "string", "required": True, "max_length": 512}
)
_ENUM_COLLECTION: Mapping[str, object] = MappingProxyType(
    {
        "type": "enum",
        "required": True,
        "enum_values": ["DCOnly"],
    }
)
_DIRECTORY_SECRET: Mapping[str, object] = MappingProxyType(
    {
        "directory_credential": {
            "reference": "engagement.directory-credential",
            "transport": "file",
        }
    }
)
_CANDIDATE_SECRET: Mapping[str, object] = MappingProxyType(
    {
        "credential_candidates": {
            "reference": "engagement.synthetic-candidate-set",
            "transport": "file",
        }
    }
)


_SPECS: tuple[_ActionSpec, ...] = (
    _ActionSpec(
        "operator.internal.directory.policies",
        "Authenticated directory policy enumeration",
        "authenticated-directory-enumeration",
        "internal-recon/authenticated-directory",
        "authenticated-directory",
        "/usr/bin/ldapsearch",
        (
            "-LLL",
            "-Y",
            "GSSAPI",
            "-H",
            "{target:endpoint}",
            "-b",
            "{value:base_dn}",
            "(objectClass=domainDNS)",
            "minPwdLength",
            "lockoutThreshold",
        ),
        ("endpoint",),
        {"base_dn": _STRING_PARAMETER},
        {},
        ("authenticated-testing", "sensitive-data-access"),
    ),
    _ActionSpec(
        "operator.internal.directory.spns",
        "Authenticated directory SPN enumeration",
        "authenticated-directory-enumeration",
        "internal-recon/authenticated-directory",
        "authenticated-directory",
        "/usr/bin/ldapsearch",
        (
            "-LLL",
            "-Y",
            "GSSAPI",
            "-H",
            "{target:endpoint}",
            "-b",
            "{value:base_dn}",
            "(servicePrincipalName=*)",
            "sAMAccountName",
            "servicePrincipalName",
        ),
        ("endpoint",),
        {"base_dn": _STRING_PARAMETER},
        {},
        ("authenticated-testing", "sensitive-data-access"),
    ),
    _ActionSpec(
        "operator.internal.directory.adcs",
        "Authenticated ADCS configuration enumeration",
        "authenticated-directory-enumeration",
        "internal-recon/adcs-enumeration",
        "authenticated-directory",
        "/usr/local/bin/certipy",
        ("find", "-target", "{target:host}", "-json", "-enabled"),
        ("host",),
        {},
        {},
        ("authenticated-testing", "sensitive-data-access"),
    ),
    _ActionSpec(
        "operator.internal.directory.graph",
        "Bounded Active Directory graph collection",
        "authenticated-directory-enumeration",
        "internal-recon/ad-graph",
        "authenticated-directory",
        "/usr/local/bin/bloodhound-python",
        ("-c", "{value:collection}", "-d", "{value:domain}", "-dc", "{target:host}"),
        ("host",),
        {"collection": _ENUM_COLLECTION, "domain": _STRING_PARAMETER},
        {},
        ("authenticated-testing", "sensitive-data-access"),
    ),
    _ActionSpec(
        "operator.internal.credential.asrep",
        "AS-REP material request for offline validation",
        "credential-material-access",
        "internal-recon/credential-material",
        "credential-access",
        "/usr/local/bin/GetNPUsers.py",
        ("-no-pass", "-request", "{target:host}"),
        ("host",),
        {},
        {},
        ("credential-access", "sensitive-data-access"),
    ),
    _ActionSpec(
        "operator.internal.credential.kerberoast",
        "Kerberos service-ticket request for offline validation",
        "credential-material-access",
        "internal-recon/credential-material",
        "credential-access",
        "/usr/local/bin/GetUserSPNs.py",
        ("-request", "{target:host}"),
        ("host",),
        {},
        {},
        ("credential-access", "sensitive-data-access"),
    ),
    _ActionSpec(
        "operator.internal.credential.laps",
        "Authorized LAPS attribute read",
        "credential-material-access",
        "internal-recon/directory-secrets",
        "credential-access",
        "/usr/local/bin/nxc",
        ("ldap", "{target:host}", "--laps", "{secret_file:directory_credential}"),
        ("host",),
        {},
        _DIRECTORY_SECRET,
        ("credential-access", "sensitive-data-access"),
    ),
    _ActionSpec(
        "operator.internal.credential.gmsa",
        "Authorized gMSA metadata read",
        "credential-material-access",
        "internal-recon/directory-secrets",
        "credential-access",
        "/usr/local/bin/nxc",
        ("ldap", "{target:host}", "--gmsa", "{secret_file:directory_credential}"),
        ("host",),
        {},
        _DIRECTORY_SECRET,
        ("credential-access", "sensitive-data-access"),
    ),
    _ActionSpec(
        "operator.internal.validation.password-spray",
        "Bounded password validation against one scoped host",
        "validation-and-capture",
        "internal-recon/credential-validation",
        "credential-validation",
        "/usr/local/bin/nxc",
        ("smb", "{target:host}", "-p", "{secret_file:credential_candidates}"),
        ("host",),
        {},
        _CANDIDATE_SECRET,
        ("credential-capture", "automated-scanning", "multiple-accounts", "state-changing"),
        state_changing=True,
        high_volume=True,
    ),
    _ActionSpec(
        "operator.internal.responder.analyze",
        "Responder analyze-only observation",
        "validation-and-capture",
        "internal-recon/responder-modes",
        "analyze-only",
        "/opt/hackbot/adapters/responder",
        ("--mode", "analyze", "--authorized-subnet", "{target:subnet}"),
        ("subnet",),
        {},
        {},
        ("sensitive-data-access",),
        ("analyze-only",),
        touches_third_party=True,
    ),
    _ActionSpec(
        "operator.internal.responder.capture",
        "Responder poison/capture in an isolated authorized subnet",
        "validation-and-capture",
        "internal-recon/responder-modes",
        "credential-capture",
        "/opt/hackbot/adapters/responder",
        ("--mode", "poison-capture", "--authorized-subnet", "{target:subnet}"),
        ("subnet",),
        {},
        {},
        ("credential-capture", "state-changing"),
        ("capture", "poisoning", "third-party"),
        state_changing=True,
        touches_third_party=True,
    ),
    _ActionSpec(
        "operator.internal.exploit.verify",
        "Single-target controlled exploit verification",
        "exploit-verification",
        "internal-recon/exploit-verification",
        "exploit-verification",
        "/opt/hackbot/adapters/exploit-verify",
        ("--single-proof", "--target", "{target:host}"),
        ("host",),
        {},
        {},
        ("exploit-execution",),
    ),
    _ActionSpec(
        "operator.internal.payload.verify",
        "Single-target controlled payload verification",
        "payload-post-exploitation",
        "internal-recon/post-exploitation",
        "payload-execution",
        "/opt/hackbot/adapters/payload-verify",
        ("--minimal-proof", "--target", "{target:host}"),
        ("host",),
        {},
        {},
        ("payload-execution", "state-changing"),
        state_changing=True,
    ),
    _ActionSpec(
        "operator.internal.lateral.verify",
        "Verify access to one additional scoped asset",
        "lateral-movement",
        "internal-recon/lateral-movement",
        "lateral-movement",
        "/usr/bin/ssh",
        ("-o", "BatchMode=yes", "{target:host}", "/usr/bin/true"),
        ("host",),
        {},
        {},
        ("lateral-movement", "credential-access"),
    ),
    _ActionSpec(
        "operator.internal.persistence.verify",
        "Install and remove one controlled persistence marker",
        "persistence",
        "internal-recon/persistence",
        "persistence",
        "/opt/hackbot/adapters/persistence-verify",
        ("--install-test-marker", "--target", "{target:host}"),
        ("host",),
        {},
        {},
        ("persistence", "state-changing"),
        state_changing=True,
    ),
)

L3_ACTION_IDS = frozenset(spec.action_id for spec in _SPECS)

_EXPECTED_ACTION_IDS = frozenset(spec.action_id for spec in _SPECS)
_RATE_CONTROL = {"kind": "native-adapter", "adapter_id": "internal-l3-bounded"}


def _characteristics(spec: _ActionSpec) -> dict[str, bool]:
    return {
        "network_access": True,
        "high_volume": spec.high_volume,
        "touches_third_party": spec.touches_third_party,
        "follows_redirects": False,
        "recursive_discovery": False,
        "state_changing": spec.state_changing,
        "creates_account": False,
        "uses_multiple_accounts": spec.action_id.endswith("password-spray"),
        "out_of_band": False,
        "honors_required_headers": True,
    }


def _plain_definitions(definitions: Mapping[str, object]) -> dict[str, object]:
    plain: dict[str, object] = {}
    for name, raw in definitions.items():
        if not isinstance(raw, Mapping):
            plain[name] = raw
            continue
        body = dict(raw)
        if isinstance(body.get("enum_values"), Sequence):
            body["enum_values"] = list(body["enum_values"])
        plain[name] = body
    return plain


def _action(spec: _ActionSpec) -> dict[str, object]:
    return {
        "id": spec.action_id,
        "title": spec.title,
        "risk": "L3",
        "platforms": ["linux"],
        "architectures": ["x86_64", "arm64"],
        "executables": {"linux": spec.executable},
        "required_privileges": [],
        "parameters": _plain_definitions(spec.parameters),
        "secrets": _plain_definitions(spec.secrets),
        "targets": list(spec.targets),
        "characteristics": _characteristics(spec),
        "rate_control": dict(_RATE_CONTROL),
        "capabilities": list(spec.capabilities),
        "vulnerability_types": [],
        "impacts": [],
        "evidence_policy": {"mode": "metadata-only"},
        "argv": list(spec.argv),
    }


def _catalog_manifest() -> dict[str, object]:
    """Return a fresh code-owned manifest document for the reviewed catalog."""

    return {"schema_version": ACTIONS_SCHEMA_VERSION, "actions": [_action(spec) for spec in _SPECS]}


def _catalog_error() -> ContractError:
    return ContractError(ReasonCode.INVALID_ACTION_MANIFEST)


def validate_catalog_manifest(
    document: Mapping[str, object],
) -> Mapping[str, ActionDefinition]:
    """Apply P2 validation plus the stricter P5b closed-catalog invariants."""

    registry = validate_manifest(document)
    if set(registry) != _EXPECTED_ACTION_IDS:
        raise _catalog_error()
    raw_actions = document.get("actions")
    if not isinstance(raw_actions, Sequence) or isinstance(raw_actions, str | bytes):
        raise _catalog_error()
    for raw in raw_actions:
        if not isinstance(raw, Mapping):
            raise _catalog_error()
        action_id = raw.get("id")
        if not isinstance(action_id, str):
            raise _catalog_error()
        action = registry[action_id]
        if action.risk != "L3" or not action.capabilities:
            raise _catalog_error()
        if action.capabilities & EXCLUDED_CAPABILITIES:
            raise _catalog_error()
        if action.executable_basenames & (SHELL_BASENAMES | INTERPRETER_BASENAMES):
            raise _catalog_error()
        if any(
            any(fragment in token for fragment in _SHELL_CONTROL_FRAGMENTS)
            for token in action.argv_template
        ):
            raise _catalog_error()
        if (
            action.capabilities & _SENSITIVE_CAPABILITIES
            and action.evidence_mode == "redacted-output"
        ):
            raise ContractError(ReasonCode.EVIDENCE_POLICY_DENIED)
    return registry


_PROVENANCE: Mapping[str, L3Provenance] = MappingProxyType(
    {
        spec.action_id: L3Provenance(
            action_id=spec.action_id,
            category=spec.category,
            source_skill=spec.source_skill,
            classification=spec.classification,
            risk="L3",
            capabilities=frozenset(spec.capabilities),
            labels=spec.labels,
            attribution=_ATTRIBUTION,
        )
        for spec in _SPECS
    }
)


def provenance() -> Mapping[str, L3Provenance]:
    """Return immutable reviewed provenance for every code-owned action."""

    return _PROVENANCE


_STRUCTURED_EVIDENCE_SCHEMAS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        "principal-summary-v1": MappingProxyType(
            {"principal_count": "integer", "principal_names": "strings"}
        ),
        "ticket-summary-v1": MappingProxyType(
            {
                "principal_name": "string",
                "service_name": "string",
                "encryption_type": "string",
            }
        ),
        "capture-summary-v1": MappingProxyType(
            {
                "capture_count": "integer",
                "principal_names": "strings",
                "protocol": "string",
                "source_hosts": "strings",
            }
        ),
    }
)


def _valid_text(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 512


def validate_structured_evidence(
    schema_id: str, payload: Mapping[str, object]
) -> Mapping[str, object]:
    """Validate a closed native evidence payload without accepting raw bytes."""

    schema = _STRUCTURED_EVIDENCE_SCHEMAS.get(schema_id)
    if schema is None or set(payload) != set(schema):
        raise ContractError(ReasonCode.EVIDENCE_POLICY_DENIED)
    normalized: dict[str, object] = {}
    for field, kind in schema.items():
        value = payload[field]
        if kind == "integer":
            if type(value) is not int or not 0 <= value <= 1_000_000:
                raise ContractError(ReasonCode.EVIDENCE_POLICY_DENIED)
            normalized[field] = value
        elif kind == "string":
            if not _valid_text(value):
                raise ContractError(ReasonCode.EVIDENCE_POLICY_DENIED)
            normalized[field] = value
        else:
            if (
                not isinstance(value, Sequence)
                or isinstance(value, str | bytes)
                or len(value) > 10_000
                or any(not _valid_text(item) for item in value)
            ):
                raise ContractError(ReasonCode.EVIDENCE_POLICY_DENIED)
            normalized[field] = tuple(value)
    return MappingProxyType(normalized)


def _load_catalog_fixture() -> Mapping[str, ActionDefinition]:
    """Return raw prototype definitions for legacy unit fixtures only."""

    return validate_catalog_manifest(_catalog_manifest())


__all__ = [
    "EXCLUDED_CAPABILITIES",
    "L3_ACTION_IDS",
    "L3Provenance",
    "provenance",
    "validate_catalog_manifest",
    "validate_structured_evidence",
]
