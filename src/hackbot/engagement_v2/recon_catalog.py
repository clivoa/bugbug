"""Reviewed, non-credential internal-recon action catalog (P5a).

A code-owned v2 action manifest covering the non-credential internal-recon
categories at their classified levels: local network state (L1); host discovery,
service enumeration, and anonymous LDAP (L2, automated-scanning). It validates
against the P2 manifest contract, carries provenance, and is disabled by default:
`load_catalog` yields actions only under an authorized internal profile with
explicit confirmation. Credential and L3 categories are P5b.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from hackbot.engagement_v2.constants import ACTIONS_SCHEMA_VERSION, Profile
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.manifest import ActionDefinition, validate_manifest

_ATTRIBUTION = "CyberNeon Recon Bundle (public source; no formal license), reviewed generic subset"

# Capabilities that must never appear in the non-credential catalog: every
# capability whose policy risk floor is L3, plus sensitive-data access.
FORBIDDEN_CAPABILITIES = frozenset(
    {
        "credential-access",
        "credential-capture",
        "sensitive-data-access",
        "exploit-execution",
        "payload-execution",
        "privileged-execution",
        "lateral-movement",
        "persistence",
        "data-exfiltration",
        "social-engineering",
        "destructive-testing",
        "denial-of-service",
    }
)

# Profiles under which internal recon may load (still requires explicit operator
# confirmation elsewhere; presence in a manifest never self-enables).
_INTERNAL_PROFILES = frozenset({Profile.PRIVATE_PENTEST.value, Profile.LOCAL_LAB.value, Profile.BUG_BOUNTY.value})


@dataclass(frozen=True)
class ReconProvenance:
    action_id: str
    category: str
    source_skill: str
    risk: str
    capabilities: frozenset[str]
    attribution: str


def _action(
    *,
    action_id: str,
    title: str,
    risk: str,
    executable: str,
    argv: list[str],
    targets: list[str],
    parameters: dict[str, object],
    capabilities: list[str],
    rate_control: dict[str, object],
) -> dict[str, object]:
    return {
        "id": action_id,
        "title": title,
        "risk": risk,
        "platforms": ["linux"],
        "architectures": ["x86_64", "arm64"],
        "executables": {"linux": executable},
        "required_privileges": [],
        "parameters": parameters,
        "secrets": {},
        "targets": targets,
        "characteristics": {},
        "rate_control": rate_control,
        "capabilities": capabilities,
        "vulnerability_types": [],
        "impacts": [],
        "evidence_policy": {"mode": "metadata-only"},
        "argv": argv,
    }


_NOT_APPLICABLE: dict[str, object] = {"kind": "not-applicable"}
_SCAN_RATE: dict[str, object] = {
    "kind": "argv-placeholder",
    "rate_parameter": "max_rate",
    "concurrency_parameter": "min_parallelism",
}
_SCAN_PARAMS: dict[str, object] = {
    "max_rate": {"type": "integer", "required": True, "minimum": 1, "maximum": 1000},
    "min_parallelism": {"type": "integer", "required": True, "minimum": 1, "maximum": 100},
}
# ldapsearch has no argv rate flag, so its rate is bound by a code-owned native
# adapter (never `not-applicable`, which policy would treat as unenforceable for
# a network-rated capability).
_LDAP_ADAPTER: dict[str, object] = {"kind": "native-adapter", "adapter_id": "internal-ldap-query"}


def _catalog_actions() -> list[dict[str, object]]:
    return [
        # --- local network state (L1) ---
        _action(
            action_id="operator.internal.netstate.interfaces",
            title="Local interface inventory",
            risk="L1",
            executable="/usr/bin/ip",
            argv=["addr", "show"],
            targets=[],
            parameters={},
            capabilities=[],
            rate_control=_NOT_APPLICABLE,
        ),
        _action(
            action_id="operator.internal.netstate.routes",
            title="Local route table",
            risk="L1",
            executable="/usr/bin/ip",
            argv=["route", "show"],
            targets=[],
            parameters={},
            capabilities=[],
            rate_control=_NOT_APPLICABLE,
        ),
        _action(
            action_id="operator.internal.netstate.neighbors",
            title="Local neighbor cache",
            risk="L1",
            executable="/usr/bin/ip",
            argv=["neigh", "show"],
            targets=[],
            parameters={},
            capabilities=[],
            rate_control=_NOT_APPLICABLE,
        ),
        _action(
            action_id="operator.internal.netstate.listeners",
            title="Local listening sockets",
            risk="L1",
            executable="/usr/bin/ss",
            argv=["-tulpn"],
            targets=[],
            parameters={},
            capabilities=[],
            rate_control=_NOT_APPLICABLE,
        ),
        # --- host discovery (L2, automated-scanning) ---
        _action(
            action_id="operator.internal.discovery.arp-sweep",
            title="ARP host discovery",
            risk="L2",
            executable="/usr/bin/nmap",
            argv=[
                "-sn",
                "-PR",
                "--max-rate",
                "{value:max_rate}",
                "--min-parallelism",
                "{value:min_parallelism}",
                "{target:subnet}",
            ],
            targets=["subnet"],
            parameters=dict(_SCAN_PARAMS),
            capabilities=["automated-scanning"],
            rate_control=dict(_SCAN_RATE),
        ),
        _action(
            action_id="operator.internal.discovery.icmp-sweep",
            title="ICMP host discovery",
            risk="L2",
            executable="/usr/bin/nmap",
            argv=[
                "-sn",
                "-PE",
                "--max-rate",
                "{value:max_rate}",
                "--min-parallelism",
                "{value:min_parallelism}",
                "{target:subnet}",
            ],
            targets=["subnet"],
            parameters=dict(_SCAN_PARAMS),
            capabilities=["automated-scanning"],
            rate_control=dict(_SCAN_RATE),
        ),
        # --- service enumeration (L2, automated-scanning) ---
        _action(
            action_id="operator.internal.enum.service-ports",
            title="Service/version enumeration",
            risk="L2",
            executable="/usr/bin/nmap",
            argv=[
                "-Pn",
                "-sV",
                "--top-ports",
                "{value:top_ports}",
                "--max-rate",
                "{value:max_rate}",
                "--min-parallelism",
                "{value:min_parallelism}",
                "{target:host}",
            ],
            targets=["host"],
            parameters={
                "top_ports": {"type": "integer", "required": True, "minimum": 1, "maximum": 65535},
                **_SCAN_PARAMS,
            },
            capabilities=["automated-scanning"],
            rate_control=dict(_SCAN_RATE),
        ),
        # --- anonymous LDAP (L2, automated-scanning) ---
        _action(
            action_id="operator.internal.ldap.naming-contexts",
            title="Anonymous LDAP naming contexts (RootDSE)",
            risk="L2",
            executable="/usr/bin/ldapsearch",
            # RootDSE base-scoped read; a base DN is supplied explicitly (the P0
            # argv grammar forbids an empty token, so no `-b ""`).
            argv=[
                "-x",
                "-LLL",
                "-H",
                "{target:endpoint}",
                "-s",
                "base",
                "-b",
                "{value:base_dn}",
                "namingContexts",
                "+",
            ],
            targets=["endpoint"],
            parameters={"base_dn": {"type": "string", "required": True, "max_length": 512}},
            capabilities=["automated-scanning"],
            rate_control=_LDAP_ADAPTER,
        ),
        _action(
            action_id="operator.internal.ldap.anonymous-users",
            title="Anonymous LDAP user/group listing",
            risk="L2",
            executable="/usr/bin/ldapsearch",
            argv=[
                "-x",
                "-LLL",
                "-H",
                "{target:endpoint}",
                "-b",
                "{value:base_dn}",
                "(objectClass=organizationalPerson)",
                "cn",
            ],
            targets=["endpoint"],
            parameters={"base_dn": {"type": "string", "required": True, "max_length": 512}},
            capabilities=["automated-scanning"],
            rate_control=_LDAP_ADAPTER,
        ),
    ]


def _catalog_manifest() -> dict[str, object]:
    """Return the code-owned non-credential internal-recon manifest document."""

    return {"schema_version": ACTIONS_SCHEMA_VERSION, "actions": _catalog_actions()}


_PROVENANCE: Mapping[str, ReconProvenance] = MappingProxyType(
    {
        "operator.internal.netstate.interfaces": ReconProvenance(
            "operator.internal.netstate.interfaces",
            "local-network-state",
            "internal-recon/local-network-state",
            "L1",
            frozenset(),
            _ATTRIBUTION,
        ),
        "operator.internal.netstate.routes": ReconProvenance(
            "operator.internal.netstate.routes",
            "local-network-state",
            "internal-recon/local-network-state",
            "L1",
            frozenset(),
            _ATTRIBUTION,
        ),
        "operator.internal.netstate.neighbors": ReconProvenance(
            "operator.internal.netstate.neighbors",
            "local-network-state",
            "internal-recon/local-network-state",
            "L1",
            frozenset(),
            _ATTRIBUTION,
        ),
        "operator.internal.netstate.listeners": ReconProvenance(
            "operator.internal.netstate.listeners",
            "local-network-state",
            "internal-recon/local-network-state",
            "L1",
            frozenset(),
            _ATTRIBUTION,
        ),
        "operator.internal.discovery.arp-sweep": ReconProvenance(
            "operator.internal.discovery.arp-sweep",
            "host-discovery",
            "internal-recon/host-discovery",
            "L2",
            frozenset({"automated-scanning"}),
            _ATTRIBUTION,
        ),
        "operator.internal.discovery.icmp-sweep": ReconProvenance(
            "operator.internal.discovery.icmp-sweep",
            "host-discovery",
            "internal-recon/host-discovery",
            "L2",
            frozenset({"automated-scanning"}),
            _ATTRIBUTION,
        ),
        "operator.internal.enum.service-ports": ReconProvenance(
            "operator.internal.enum.service-ports",
            "service-enumeration",
            "internal-recon/service-enumeration",
            "L2",
            frozenset({"automated-scanning"}),
            _ATTRIBUTION,
        ),
        "operator.internal.ldap.naming-contexts": ReconProvenance(
            "operator.internal.ldap.naming-contexts",
            "anonymous-ldap",
            "internal-recon/anonymous-ldap",
            "L2",
            frozenset({"automated-scanning"}),
            _ATTRIBUTION,
        ),
        "operator.internal.ldap.anonymous-users": ReconProvenance(
            "operator.internal.ldap.anonymous-users",
            "anonymous-ldap",
            "internal-recon/anonymous-ldap",
            "L2",
            frozenset({"automated-scanning"}),
            _ATTRIBUTION,
        ),
    }
)


def provenance() -> Mapping[str, ReconProvenance]:
    """Return the code-owned provenance mapping for every catalog action."""

    return _PROVENANCE


def load_catalog(
    *, active_profile: str | None, internal_recon_confirmed: bool
) -> Mapping[str, ActionDefinition]:
    """Return the validated catalog registry, or fail closed when disabled.

    Internal recon is disabled by default: it loads only under an authorized
    internal profile with explicit operator confirmation. Presence of the catalog
    in code never self-enables it.
    """

    if active_profile not in _INTERNAL_PROFILES or not internal_recon_confirmed:
        raise ContractError(ReasonCode.DENY_CAPABILITY_NOT_ALLOWED)
    return validate_manifest(_catalog_manifest())
