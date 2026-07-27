"""Typed, default-deny engagement v2 scope decisions.

Scope v2 decides each target against a confirmed snapshot's scope using
default-deny and deny-wins semantics. Authorization is typed: a rule of one kind
never authorizes a target of an incompatible kind, CIDR membership is decided by
literal-IP containment (never by DNS), and every decision carries a stable
machine-readable reason. The engine performs no network or DNS resolution.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

_HTTP_SCHEMES = frozenset({"http", "https"})
_HOSTNAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")


class ScopeDenyReason(str, Enum):
    """Closed set of stable scope decision reasons."""

    AUTHORIZED = "authorized"
    OUT_OF_SCOPE_NO_MATCH = "out-of-scope-no-match"
    EXCLUDED_BY_RULE = "excluded-by-rule"
    CROSS_PROTOCOL_NOT_AUTHORIZED = "cross-protocol-not-authorized"
    UNPARSABLE_TARGET = "unparsable-target"
    DNS_RESOLUTION_NOT_AUTHORITATIVE = "dns-resolution-not-authoritative"


@dataclass(frozen=True)
class ScopeV2Decision:
    authorized: bool
    target: str
    reason: ScopeDenyReason


@dataclass(frozen=True)
class _Target:
    kind: str  # "ip" | "name" | "url" | "endpoint"
    host: str = ""
    port: int | None = None
    scheme: str = ""
    path: str = ""
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None


def _parse_target(target: str) -> _Target | None:
    if not target or any(character.isspace() for character in target):
        return None
    if "://" in target:
        parts = urlsplit(target)
        host = parts.hostname or ""
        if not host:
            return None
        scheme = parts.scheme.lower()
        try:
            port = parts.port
        except ValueError:
            return None
        if scheme in _HTTP_SCHEMES:
            return _Target(kind="url", host=host, scheme=scheme, path=parts.path or "/")
        if port is None:
            # Network endpoints require an explicit port.
            return None
        return _Target(kind="endpoint", host=host, scheme=scheme, port=port)
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None
    if address is not None:
        return _Target(kind="ip", ip=address)
    if any(character not in _HOSTNAME_CHARS for character in target):
        return None
    return _Target(kind="name", host=target.lower())


def _section(scope: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = scope.get(key)
    return value if isinstance(value, Mapping) else {}


def _entries(section: Mapping[str, object], kind: str) -> list[str]:
    value = section.get(kind)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _domain_matches(host: str, section: Mapping[str, object]) -> bool:
    host = host.lower()
    for rule in _entries(section, "domains"):
        if host == rule.lower():
            return True
    for rule in _entries(section, "wildcard_domains"):
        suffix = rule.lower().removeprefix("*.")
        if host != suffix and host.endswith("." + suffix):
            return True
    return False


def _host_matches(host: str, section: Mapping[str, object]) -> bool:
    host = host.lower()
    return any(host == rule.lower() for rule in _entries(section, "hosts"))


def _url_matches(host: str, path: str, section: Mapping[str, object]) -> bool:
    host = host.lower()
    for rule in _entries(section, "urls"):
        parts = urlsplit(rule)
        if (parts.hostname or "").lower() != host:
            continue
        rule_path = parts.path or "/"
        if path == rule_path or path.startswith(rule_path.rstrip("/") + "/"):
            return True
    return False


def _endpoint_matches(target: _Target, section: Mapping[str, object]) -> bool:
    host = target.host.lower()
    for rule in _entries(section, "network_endpoints"):
        parts = urlsplit(rule)
        try:
            rule_port = parts.port
        except ValueError:
            continue
        if (
            parts.scheme.lower() == target.scheme
            and (parts.hostname or "").lower() == host
            and rule_port == target.port
        ):
            return True
    return False


def _ip_in_section_cidrs(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, section: Mapping[str, object]
) -> bool:
    for rule in _entries(section, "cidrs"):
        try:
            network = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            continue
        if network.version != address.version:
            continue
        if address in network:
            return True
    return False


class ScopeV2:
    """A frozen, typed scope decision engine over a confirmed snapshot."""

    __slots__ = ("_in_scope", "_out_of_scope")

    def __init__(self, scope_document: Mapping[str, object]) -> None:
        self._in_scope = _section(scope_document, "in_scope")
        self._out_of_scope = _section(scope_document, "out_of_scope")

    def check(self, target: str) -> ScopeV2Decision:
        parsed = _parse_target(target)
        if parsed is None:
            return self._deny(target, ScopeDenyReason.UNPARSABLE_TARGET)
        if self._excluded(parsed):
            return self._deny(target, ScopeDenyReason.EXCLUDED_BY_RULE)
        return self._included(target, parsed)

    def _excluded(self, target: _Target) -> bool:
        section = self._out_of_scope
        if target.kind == "ip":
            assert target.ip is not None
            return _ip_in_section_cidrs(target.ip, section)
        if target.kind == "name":
            return _domain_matches(target.host, section) or _host_matches(target.host, section)
        if target.kind == "url":
            return _domain_matches(target.host, section) or _url_matches(
                target.host, target.path, section
            )
        # endpoint
        return _endpoint_matches(target, section) or _host_matches(target.host, section)

    def _included(self, raw: str, target: _Target) -> ScopeV2Decision:
        section = self._in_scope
        if target.kind == "ip":
            assert target.ip is not None
            if _ip_in_section_cidrs(target.ip, section):
                return self._allow(raw)
            return self._deny(raw, ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH)
        if target.kind == "name":
            if _domain_matches(target.host, section) or _host_matches(target.host, section):
                return self._allow(raw)
            if _entries(section, "cidrs"):
                return self._deny(raw, ScopeDenyReason.DNS_RESOLUTION_NOT_AUTHORITATIVE)
            return self._deny(raw, ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH)
        if target.kind == "url":
            if _url_matches(target.host, target.path, section) or _domain_matches(
                target.host, section
            ):
                return self._allow(raw)
            if _host_matches(target.host, section) or _endpoint_matches(target, section):
                return self._deny(raw, ScopeDenyReason.CROSS_PROTOCOL_NOT_AUTHORIZED)
            return self._deny(raw, ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH)
        # endpoint
        if _endpoint_matches(target, section) or _host_matches(target.host, section):
            return self._allow(raw)
        if _domain_matches(target.host, section) or _url_matches(target.host, target.path, section):
            return self._deny(raw, ScopeDenyReason.CROSS_PROTOCOL_NOT_AUTHORIZED)
        return self._deny(raw, ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH)

    @staticmethod
    def _allow(target: str) -> ScopeV2Decision:
        return ScopeV2Decision(True, target, ScopeDenyReason.AUTHORIZED)

    @staticmethod
    def _deny(target: str, reason: ScopeDenyReason) -> ScopeV2Decision:
        return ScopeV2Decision(False, target, reason)
