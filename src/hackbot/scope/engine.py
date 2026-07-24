"""
scope.engine — deterministic, code-enforced scope checking.

Scope is enforced in CODE, never by trusting a model or any target-controlled
content. Core guarantees:

  * default-deny: anything not matching an in-scope rule is OUT of scope.
  * deny-wins: an excluded match beats any in-scope match.
  * immutable at runtime: a Scope is built from the program profile only. There is
    NO method that adds scope from tool output, model text, redirects, ASN/cert/
    Shodan/PTR/SPF/DNS-history, or any other discovery. Discovery ≠ authorization.
  * redirects are re-checked: a redirect target must independently be in scope.
  * shared CDN/cloud ranges are rejected unless the exact asset is explicitly listed.

The host-pattern matcher (apex+subdomain / *. / exact / CIDR / re:) is adapted from
elementalsouls/Claude-BugHunter engine/scope.py (MIT, (c) 2026 Sachin Sharma);
see docs/licenses-and-attribution.md. Extended here for URLs/ports, redirect
re-checking, CDN/shared-range rejection, and non-web scope kinds.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable
from urllib.parse import urlparse


class ScopeKind(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    MOBILE = "mobile"        # package id, e.g. com.example.app
    REPO = "repo"            # github repo, e.g. github.com/org/name
    CONTRACT = "contract"    # chain:0xaddress
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    target: str                       # normalized target
    kind: ScopeKind
    reason: str                       # human explanation
    matched_rule: str = ""            # the exact rule that authorized (if allowed)
    rule_source: str = ""             # program field the rule came from
    risk_flags: tuple[str, ...] = ()  # e.g. ("shared-cdn", "ip-literal")

    def explain(self) -> str:
        verdict = "IN SCOPE" if self.allowed else "OUT OF SCOPE"
        parts = [f"{verdict}: {self.target} ({self.kind.value})", f"reason: {self.reason}"]
        if self.matched_rule:
            parts.append(f"matched rule: {self.matched_rule} (from {self.rule_source})")
        if self.risk_flags:
            parts.append(f"flags: {', '.join(self.risk_flags)}")
        return "\n".join(parts)


# A starter set of shared CDN / cloud CIDR prefixes. These are NOT owned by a
# program's target; an IP inside them is rejected unless the exact asset is
# explicitly in scope. Extend via config/shared-ranges.yaml (loaded by callers).
_DEFAULT_SHARED_RANGES: tuple[str, ...] = (
    # Cloudflare (subset)
    "104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15", "173.245.48.0/20",
    "103.21.244.0/22", "131.0.72.0/22",
    # Fastly (subset)
    "151.101.0.0/16", "199.232.0.0/16",
    # AWS CloudFront / common (subset)
    "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15",
    # Google / GCP LB (subset)
    "34.96.0.0/12", "35.190.0.0/17",
    # Azure Front Door (subset)
    "13.107.0.0/16",
)


def _host_of(target: str) -> str:
    t = (target or "").strip()
    if "://" not in t:
        t = "//" + t
    return (urlparse(t).hostname or "").lower().rstrip(".")


def _port_of(target: str) -> int | None:
    t = (target or "").strip()
    if "://" not in t:
        t = "//" + t
    try:
        return urlparse(t).port
    except ValueError:
        return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def classify_target(target: str) -> ScopeKind:
    t = (target or "").strip()
    if re.fullmatch(r"[a-z]+:0x[0-9a-fA-F]{40}", t) or re.fullmatch(r"0x[0-9a-fA-F]{40}", t):
        return ScopeKind.CONTRACT
    if re.match(r"https?://github\.com/[^/]+/[^/]+", t, re.I) or re.fullmatch(
            r"github\.com/[^/]+/[^/]+(?:/.*)?", t, re.I):
        return ScopeKind.REPO
    # Android/iOS package id: reverse-DNS => FIRST label is a TLD, 3+ labels,
    # no scheme/slash/space. This disambiguates com.example.app from example.app.
    if "://" not in t and "/" not in t and " " not in t:
        labels = t.split(".")
        if len(labels) >= 3 and labels[0].lower() in _COMMON_TLDS:
            return ScopeKind.MOBILE
    host = _host_of(t)
    if host and _is_ip(host):
        return ScopeKind.IP
    if "://" in t or "/" in t:
        return ScopeKind.URL
    if host:
        return ScopeKind.DOMAIN
    return ScopeKind.UNKNOWN


# very small TLD sanity so we can spot reverse-DNS package ids vs domains
_COMMON_TLDS = {"com", "net", "org", "io", "dev", "app", "co", "gov", "edu",
                "info", "xyz", "cloud", "ai", "me", "us", "uk", "br"}


def _match_host(pattern: str, host: str) -> bool:
    p = (pattern or "").strip().lower()
    if not p or not host:
        return False
    if p.startswith("re:"):
        try:
            return re.search(p[3:], host) is not None
        except re.error:
            return False
    if "/" in p and p.replace(".", "").replace("/", "").isdigit():  # IPv4 CIDR
        try:
            return _is_ip(host) and ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    if p.startswith("*."):
        base = p[2:]
        return host.endswith("." + base)     # subdomains only, NOT the bare apex
    return host == p or host.endswith("." + p)  # apex or any subdomain, or exact host


class Scope:
    """Immutable scope built from a program profile. No runtime expansion."""

    def __init__(
        self,
        in_scope: Iterable[str],
        out_of_scope: Iterable[str] | None = None,
        *,
        name: str = "engagement",
        shared_ranges: Iterable[str] | None = None,
        rule_sources: dict[str, str] | None = None,
    ) -> None:
        self._in = tuple(p.strip() for p in in_scope if p and p.strip())
        self._out = tuple(p.strip() for p in (out_of_scope or ()) if p and p.strip())
        self.name = name
        self._rule_sources = dict(rule_sources or {})
        ranges = tuple(shared_ranges) if shared_ranges is not None else _DEFAULT_SHARED_RANGES
        self._shared = tuple(ipaddress.ip_network(r, strict=False) for r in ranges)

    # -- introspection (read-only) ----------------------------------------
    @property
    def in_scope(self) -> tuple[str, ...]:
        return self._in

    @property
    def out_of_scope(self) -> tuple[str, ...]:
        return self._out

    def _source_of(self, rule: str) -> str:
        return self._rule_sources.get(rule, "scope.domains/urls")

    def _in_shared_range(self, host: str) -> bool:
        if not _is_ip(host):
            return False
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in self._shared)

    def _explicitly_listed(self, target: str, host: str) -> str | None:
        """Return the exact in-scope rule that names this host/target, else None."""
        for r in self._in:
            rl = r.strip().lower()
            if rl in (host, target.strip().lower()):
                return r
        return None

    # -- the gate ---------------------------------------------------------
    def check(self, target: str) -> ScopeDecision:
        kind = classify_target(target)

        if kind in (ScopeKind.REPO, ScopeKind.CONTRACT, ScopeKind.MOBILE):
            return self._check_literal(target, kind)

        host = _host_of(target)
        if not host:
            return ScopeDecision(False, target, kind, "no host could be parsed")

        flags: list[str] = []
        if _is_ip(host):
            flags.append("ip-literal")

        # deny wins
        for r in self._out:
            if _match_host(r, host):
                return ScopeDecision(False, target, kind,
                                     "excluded by out-of-scope rule",
                                     matched_rule=r, rule_source="scope.excluded_assets",
                                     risk_flags=tuple(flags))

        # shared CDN/cloud range: only allowed if the exact asset is explicitly listed
        if self._in_shared_range(host):
            exact = self._explicitly_listed(target, host)
            if not exact:
                return ScopeDecision(False, target, kind,
                                     "IP is in a shared CDN/cloud range and is not "
                                     "explicitly listed in scope",
                                     risk_flags=tuple(flags + ["shared-cdn"]))
            return ScopeDecision(True, target, kind,
                                 "explicitly listed shared-range asset",
                                 matched_rule=exact, rule_source=self._source_of(exact),
                                 risk_flags=tuple(flags + ["shared-cdn"]))

        # default-deny: require an in-scope match
        for r in self._in:
            if _match_host(r, host):
                return ScopeDecision(True, target, kind, "matched in-scope rule",
                                     matched_rule=r, rule_source=self._source_of(r),
                                     risk_flags=tuple(flags))

        return ScopeDecision(False, target, kind,
                             "no in-scope rule matched (default-deny)",
                             risk_flags=tuple(flags))

    @staticmethod
    def _norm(target: str, kind: ScopeKind) -> str:
        t = target.strip().lower()
        if kind == ScopeKind.REPO:
            t = re.sub(r"^https?://", "", t).rstrip("/")
        return t

    def _check_literal(self, target: str, kind: ScopeKind) -> ScopeDecision:
        t = self._norm(target, kind)
        for r in self._out:
            if self._norm(r, kind) == t:
                return ScopeDecision(False, target, kind, "excluded literal asset",
                                     matched_rule=r, rule_source="scope.excluded_assets")
        for r in self._in:
            rl = self._norm(r, kind)
            if rl == t or (kind == ScopeKind.REPO and t.startswith(rl + "/")):
                return ScopeDecision(True, target, kind, f"matched in-scope {kind.value}",
                                     matched_rule=r, rule_source=f"scope.{kind.value}s")
        return ScopeDecision(False, target, kind,
                             f"{kind.value} not explicitly in scope (default-deny)")

    def check_redirect(self, from_target: str, to_target: str) -> ScopeDecision:
        """A redirect target must INDEPENDENTLY be in scope; out-of-scope stops it."""
        d = self.check(to_target)
        if d.allowed:
            return ScopeDecision(True, to_target, d.kind,
                                 f"redirect from {from_target} stays in scope",
                                 matched_rule=d.matched_rule, rule_source=d.rule_source,
                                 risk_flags=d.risk_flags)
        return ScopeDecision(False, to_target, d.kind,
                             f"redirect from {from_target} leaves scope: {d.reason}",
                             risk_flags=d.risk_flags + ("redirect-out",))
