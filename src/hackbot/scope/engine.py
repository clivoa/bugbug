"""
scope.engine — deterministic, code-enforced scope checking.

Scope is enforced in CODE, never by trusting a model or any target-controlled
content. Core guarantees:

  * default-deny: anything not matching an in-scope rule is OUT of scope.
  * deny-wins: an excluded match beats any in-scope match.
  * no public expansion API + frozen instances: a Scope is built from the program
    profile only. It exposes NO method that adds scope from tool output, model
    text, redirects, ASN/cert/Shodan/PTR/SPF/DNS-history, or any other discovery,
    and its attributes are frozen after construction (``__setattr__`` raises).
    Discovery ≠ authorization.
  * redirects are re-checked: a redirect target must independently be in scope.
  * shared CDN/cloud ranges are rejected unless the exact asset is explicitly listed.

Supported rule forms (host part):
  example.com            apex AND any subdomain
  *.example.com          subdomains only (NOT the bare apex)
  api.example.com        exact host
  203.0.113.0/24         IPv4 CIDR
  2001:db8::/32          IPv6 CIDR
  re:^staging[0-9]+\\.x$  explicit regex (prefix ``re:``)
Any of the above may carry a path, e.g. ``example.com/api`` or
``*.example.com/admin`` — matched as a segment-aware path prefix (``/api`` matches
``/api`` and ``/api/…`` but not ``/api2``). CIDR and ``re:`` rules do not take a path.

The host-pattern matcher is adapted from elementalsouls/Claude-BugHunter
engine/scope.py (MIT, (c) 2026 Sachin Sharma); see docs/licenses-and-attribution.md.
Extended here for URLs/ports/paths, IPv6 CIDRs, redirect re-checking, CDN/shared-
range rejection, non-web scope kinds, and instance freezing.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional
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
    target: str
    kind: ScopeKind
    reason: str
    matched_rule: str = ""
    rule_source: str = ""
    risk_flags: tuple[str, ...] = ()

    def explain(self) -> str:
        verdict = "IN SCOPE" if self.allowed else "OUT OF SCOPE"
        parts = [f"{verdict}: {self.target} ({self.kind.value})", f"reason: {self.reason}"]
        if self.matched_rule:
            parts.append(f"matched rule: {self.matched_rule} (from {self.rule_source})")
        if self.risk_flags:
            parts.append(f"flags: {', '.join(self.risk_flags)}")
        return "\n".join(parts)


# Starter set of shared CDN / cloud CIDR prefixes (not owned by a target). An IP
# inside these is rejected unless the exact asset is explicitly in scope. Extend
# via config/shared-ranges.yaml (loaded by callers).
_DEFAULT_SHARED_RANGES: tuple[str, ...] = (
    "104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15", "173.245.48.0/20",
    "103.21.244.0/22", "131.0.72.0/22",           # Cloudflare (subset)
    "151.101.0.0/16", "199.232.0.0/16",           # Fastly (subset)
    "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15",  # AWS CloudFront (subset)
    "34.96.0.0/12", "35.190.0.0/17",              # Google (subset)
    "13.107.0.0/16",                              # Azure Front Door (subset)
    "2606:4700::/32",                             # Cloudflare IPv6 (subset)
)

_COMMON_TLDS = {"com", "net", "org", "io", "dev", "app", "co", "gov", "edu",
                "info", "xyz", "cloud", "ai", "me", "us", "uk", "br"}


# --------------------------------------------------------------- helpers ----
def _looks_like_ipv6(t: str) -> bool:
    return t.count(":") >= 2 and "/" not in t and "[" not in t


def _host_of(target: str) -> str:
    t = (target or "").strip()
    if "://" not in t:
        # bracket a bare IPv6 literal so urlparse doesn't read colons as a port
        core = t.split("/", 1)[0]
        if _looks_like_ipv6(core):
            rest = t[len(core):]
            t = f"//[{core}]{rest}"
        else:
            t = "//" + t
    try:
        return (urlparse(t).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _path_of(target: str) -> str:
    t = (target or "").strip()
    if "://" not in t:
        core = t.split("/", 1)[0]
        t = (f"//[{core}]" + t[len(core):]) if _looks_like_ipv6(core) else "//" + t
    try:
        return urlparse(t).path or ""
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _as_network(pattern: str) -> Optional[ipaddress._BaseNetwork]:
    if "/" not in pattern:
        return None
    try:
        return ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return None


def classify_target(target: str) -> ScopeKind:
    t = (target or "").strip()
    if re.fullmatch(r"[a-z]+:0x[0-9a-fA-F]{40}", t) or re.fullmatch(r"0x[0-9a-fA-F]{40}", t):
        return ScopeKind.CONTRACT
    if re.match(r"https?://github\.com/[^/]+/[^/]+", t, re.I) or re.fullmatch(
            r"github\.com/[^/]+/[^/]+(?:/.*)?", t, re.I):
        return ScopeKind.REPO
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


def _match_host(pattern: str, host: str) -> bool:
    p = (pattern or "").strip().lower()
    if not p or not host:
        return False
    if p.startswith("re:"):
        try:
            return re.search(p[3:], host) is not None
        except re.error:
            return False
    net = _as_network(p)
    if net is not None:
        if not _is_ip(host):
            return False
        ip = ipaddress.ip_address(host)
        if ip.version != net.version:
            return False
        return ip in net
    if p.startswith("*."):
        return host.endswith("." + p[2:])          # subdomains only
    return host == p or host.endswith("." + p)      # apex or any subdomain / exact


def _path_matches(prefix: Optional[str], path: str) -> bool:
    if not prefix:
        return True                                  # host-only rule: any path ok
    p = path or "/"
    if not p.startswith("/"):
        p = "/" + p
    pref = prefix.rstrip("/")
    return pref == "" or p == pref or p.startswith(pref + "/")


@dataclass(frozen=True)
class _Rule:
    raw: str
    host_pattern: str
    path_prefix: Optional[str]

    @classmethod
    def parse(cls, raw: str) -> "_Rule":
        r = raw.strip()
        low = r.lower()
        if low.startswith("re:") or _as_network(r) is not None:
            return cls(raw, r, None)                 # regex / CIDR: no path
        body = re.sub(r"^https?://", "", r, flags=re.I)
        if "/" in body:
            host, _, path = body.partition("/")
            return cls(raw, host, "/" + path if path else None)
        return cls(raw, body, None)


# --------------------------------------------------------------- Scope ------
class Scope:
    """Immutable scope built from a program profile. Frozen after construction."""

    __slots__ = ("_frozen", "name", "_in", "_out", "_rule_sources", "_shared")

    def __init__(
        self,
        in_scope: Iterable[str],
        out_of_scope: Iterable[str] | None = None,
        *,
        name: str = "engagement",
        shared_ranges: Iterable[str] | None = None,
        rule_sources: dict[str, str] | None = None,
    ) -> None:
        object.__setattr__(self, "_frozen", False)
        self.name = name
        self._in = tuple(_Rule.parse(p) for p in in_scope if p and p.strip())
        self._out = tuple(_Rule.parse(p) for p in (out_of_scope or ()) if p and p.strip())
        self._rule_sources = dict(rule_sources or {})
        ranges = tuple(shared_ranges) if shared_ranges is not None else _DEFAULT_SHARED_RANGES
        self._shared = tuple(ipaddress.ip_network(r, strict=False) for r in ranges)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, key: str, value: object) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError("Scope is frozen; scope cannot be modified at runtime")
        object.__setattr__(self, key, value)

    def __delattr__(self, key: str) -> None:
        raise AttributeError("Scope is frozen; scope cannot be modified at runtime")

    # -- read-only introspection ------------------------------------------
    @property
    def in_scope(self) -> tuple[str, ...]:
        return tuple(r.raw for r in self._in)

    @property
    def out_of_scope(self) -> tuple[str, ...]:
        return tuple(r.raw for r in self._out)

    def _source_of(self, rule: str) -> str:
        return self._rule_sources.get(rule, "scope.domains/urls")

    def _in_shared_range(self, host: str) -> bool:
        if not _is_ip(host):
            return False
        ip = ipaddress.ip_address(host)
        return any(ip.version == net.version and ip in net for net in self._shared)

    def _explicitly_listed(self, target: str, host: str) -> Optional[str]:
        tl = target.strip().lower()
        for r in self._in:
            if r.host_pattern == host or r.raw.strip().lower() == tl:
                return r.raw
        return None

    # -- the gate ---------------------------------------------------------
    def check(self, target: str) -> ScopeDecision:
        kind = classify_target(target)
        if kind in (ScopeKind.REPO, ScopeKind.CONTRACT, ScopeKind.MOBILE):
            return self._check_literal(target, kind)

        host = _host_of(target)
        if not host:
            return ScopeDecision(False, target, kind, "no host could be parsed")
        path = _path_of(target)
        flags: list[str] = ["ip-literal"] if _is_ip(host) else []

        # deny wins
        for r in self._out:
            if _match_host(r.host_pattern, host) and _path_matches(r.path_prefix, path):
                return ScopeDecision(False, target, kind, "excluded by out-of-scope rule",
                                     matched_rule=r.raw, rule_source="scope.excluded_assets",
                                     risk_flags=tuple(flags))

        # shared CDN/cloud range: allowed only if the exact asset is explicitly listed
        if self._in_shared_range(host):
            exact = self._explicitly_listed(target, host)
            if not exact:
                return ScopeDecision(False, target, kind,
                                     "IP is in a shared CDN/cloud range and is not "
                                     "explicitly listed in scope",
                                     risk_flags=tuple(flags + ["shared-cdn"]))
            return ScopeDecision(True, target, kind, "explicitly listed shared-range asset",
                                 matched_rule=exact, rule_source=self._source_of(exact),
                                 risk_flags=tuple(flags + ["shared-cdn"]))

        # default-deny: require an in-scope match (host AND path)
        for r in self._in:
            if _match_host(r.host_pattern, host) and _path_matches(r.path_prefix, path):
                return ScopeDecision(True, target, kind, "matched in-scope rule",
                                     matched_rule=r.raw, rule_source=self._source_of(r.raw),
                                     risk_flags=tuple(flags))

        # host matched but path did not => report the path miss specifically
        for r in self._in:
            if _match_host(r.host_pattern, host) and r.path_prefix:
                return ScopeDecision(False, target, kind,
                                     f"host in scope but path outside rule {r.raw!r} "
                                     f"(default-deny)", risk_flags=tuple(flags + ["path-out"]))

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
            if self._norm(r.raw, kind) == t:
                return ScopeDecision(False, target, kind, "excluded literal asset",
                                     matched_rule=r.raw, rule_source="scope.excluded_assets")
        for r in self._in:
            rl = self._norm(r.raw, kind)
            if rl == t or (kind == ScopeKind.REPO and t.startswith(rl + "/")):
                return ScopeDecision(True, target, kind, f"matched in-scope {kind.value}",
                                     matched_rule=r.raw, rule_source=f"scope.{kind.value}s")
        return ScopeDecision(False, target, kind,
                             f"{kind.value} not explicitly in scope (default-deny)")

    def check_redirect(self, from_target: str, to_target: str) -> ScopeDecision:
        d = self.check(to_target)
        if d.allowed:
            return ScopeDecision(True, to_target, d.kind,
                                 f"redirect from {from_target} stays in scope",
                                 matched_rule=d.matched_rule, rule_source=d.rule_source,
                                 risk_flags=d.risk_flags)
        return ScopeDecision(False, to_target, d.kind,
                             f"redirect from {from_target} leaves scope: {d.reason}",
                             risk_flags=d.risk_flags + ("redirect-out",))
