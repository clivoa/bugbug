"""
programs.schema — strict, versioned validation for program.yaml and scope.yaml.

Principles:
  * Versioned: every document must declare a supported ``schema_version``.
  * Strict: unknown keys in security-critical sections (scope / authorization /
    testing_rules) are REJECTED, not ignored.
  * Malformed and duplicate scope entries are REJECTED.
  * DEFAULT-DENY: any validation failure yields no usable scope. Callers must treat
    a failed validation as "deny everything", never as "allow with warnings".

This module parses already-loaded Python dicts (YAML is read with yaml.safe_load in
programs.loader). It performs no I/O and no network access.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from hackbot.risk.models import TestingPolicy

SCHEMA_VERSION = 1
SUPPORTED_VERSIONS = {1}

# security-critical sections whose unknown keys are rejected
_SCOPE_KINDS = (
    "domains",
    "hosts",
    "wildcard_domains",
    "urls",
    "cidrs",
    "mobile_apps",
    "repositories",
    "contracts",
)
_PROGRAM_SECTIONS = (
    "schema_version",
    "program",
    "authorization",
    "scope",
    "testing_rules",
    "reporting",
)
_AUTH_KEYS = ("confirmed", "confirmation_timestamp", "confirmed_by")
_TESTING_KEYS = (
    "max_requests_per_second",
    "concurrency",
    "automated_scanning_allowed",
    "authenticated_testing_allowed",
    "account_creation_allowed",
    "multiple_accounts_allowed",
    "social_engineering_allowed",
    "denial_of_service_allowed",
    "out_of_band_testing_allowed",
    "source_ip_requirements",
    "required_headers",
    "restricted_hours",
    "prohibited_tools",
    "prohibited_vulnerability_types",
    "excluded_impacts",
)

_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MOBILE_RE = re.compile(r"^[a-zA-Z][\w]*(\.[a-zA-Z][\w]*){2,}$")
_REPO_RE = re.compile(r"^github\.com/[^/\s]+/[^/\s]+$", re.I)
_CONTRACT_RE = re.compile(r"^([a-z0-9]+:)?0x[0-9a-fA-F]{40}$")
_RESTRICTED_HOURS_WINDOW_RE = re.compile(
    r"^(?P<start_hour>[01]\d|2[0-3]):(?P<start_minute>[0-5]\d)-"
    r"(?P<end_hour>[01]\d|2[0-3]):(?P<end_minute>[0-5]\d)$"
)


class ValidationError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass
class ScopeDoc:
    """Validated scope, normalized to flat rule lists for the engine."""

    in_rules: list[str] = field(default_factory=list)
    out_rules: list[str] = field(default_factory=list)
    rule_sources: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------- validators --
def _err(errors: list[str], msg: str) -> None:
    errors.append(msg)


def _valid_hostname(value: str) -> bool:
    return len(value) <= 253 and all(_HOST_LABEL_RE.fullmatch(label) for label in value.split("."))


def _validate_entry(kind: str, value: object, errors: list[str], where: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        _err(errors, f"{where}: entry must be a non-empty string, got {value!r}")
        return None
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        _err(errors, f"{where}: contains invalid Unicode")
        return None
    v = value.strip()
    low = v.lower()
    if kind == "domains":
        if "://" in v or "/" in v or "*" in v:
            _err(errors, f"{where}: domain must be a bare hostname, got {v!r}")
            return None
        if not _DOMAIN_RE.match(low):
            _err(errors, f"{where}: invalid domain {v!r}")
            return None
        return low
    if kind == "hosts":
        # An exact host: matches only this hostname, never its subdomains. Bare
        # hostname in; an anchored regex rule out, which the engine matches exactly.
        if "://" in v or "/" in v or "*" in v:
            _err(errors, f"{where}: host must be a bare hostname, got {v!r}")
            return None
        if not _valid_hostname(low):
            _err(errors, f"{where}: invalid host {v!r}")
            return None
        return "re:^" + re.escape(low) + "$"
    if kind == "wildcard_domains":
        if not low.startswith("*.") or not _DOMAIN_RE.match(low[2:]):
            _err(errors, f"{where}: wildcard must be '*.<domain>', got {v!r}")
            return None
        return low
    if kind == "urls":
        if not re.match(r"^https?://[^/\s]+", low):
            _err(errors, f"{where}: url must start with http(s)://host, got {v!r}")
            return None
        return v  # preserve path/case
    if kind == "cidrs":
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            _err(errors, f"{where}: invalid CIDR {v!r}")
            return None
        return low
    if kind == "mobile_apps":
        if not _MOBILE_RE.match(v):
            _err(errors, f"{where}: invalid mobile package id {v!r}")
            return None
        return v
    if kind == "repositories":
        r = re.sub(r"^https?://", "", low).rstrip("/")
        if not _REPO_RE.match(r):
            _err(errors, f"{where}: repository must be github.com/org/repo, got {v!r}")
            return None
        return r
    if kind == "contracts":
        if not _CONTRACT_RE.match(v):
            _err(errors, f"{where}: invalid contract address {v!r}")
            return None
        return low
    _err(errors, f"{where}: unknown scope kind {kind!r}")
    return None


def _validate_scope_section(
    section: object, errors: list[str], label: str
) -> tuple[list[str], dict[str, str]]:
    rules: list[str] = []
    sources: dict[str, str] = {}
    if section is None:
        return rules, sources
    if not isinstance(section, dict):
        _err(errors, f"{label}: must be a mapping of scope kinds")
        return rules, sources
    for key in section:
        if key not in _SCOPE_KINDS:
            _err(
                errors,
                f"{label}: unknown security-critical field {key!r} "
                f"(allowed: {', '.join(_SCOPE_KINDS)})",
            )
    for kind in _SCOPE_KINDS:
        items = section.get(kind)
        if items is None:
            continue
        if not isinstance(items, list):
            _err(errors, f"{label}.{kind}: must be a list")
            continue
        seen: set[str] = set()
        for i, raw in enumerate(items):
            norm = _validate_entry(kind, raw, errors, f"{label}.{kind}[{i}]")
            if norm is None:
                continue
            if norm in seen:
                _err(errors, f"{label}.{kind}: duplicate entry {norm!r}")
                continue
            seen.add(norm)
            rules.append(norm)
            sources[norm] = f"{label}.{kind}"
    return rules, sources


def validate_scope(doc: object, *, require_version: bool = True) -> ScopeDoc:
    """Validate a scope mapping (standalone scope.yaml or a program's scope:)."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        raise ValidationError(["scope document must be a mapping"])
    if require_version:
        _check_version(doc.get("schema_version"), errors, "scope")
        allowed = {"schema_version", "in_scope", "out_of_scope"}
        for k in doc:
            if k not in allowed:
                _err(errors, f"scope: unknown top-level field {k!r}")
    in_rules, in_src = _validate_scope_section(doc.get("in_scope"), errors, "in_scope")
    out_rules, out_src = _validate_scope_section(doc.get("out_of_scope"), errors, "out_of_scope")
    if not errors and not in_rules:
        _err(errors, "scope: in_scope has no valid entries (default-deny: refusing empty scope)")
    if errors:
        raise ValidationError(errors)  # default-deny: no partial scope returned
    sources = {**in_src, **out_src}
    return ScopeDoc(in_rules=in_rules, out_rules=out_rules, rule_sources=sources)


def _check_version(v: object, errors: list[str], label: str) -> None:
    if v is None:
        _err(errors, f"{label}: missing required schema_version")
    elif isinstance(v, bool) or not isinstance(v, int) or v not in SUPPORTED_VERSIONS:
        _err(
            errors,
            f"{label}: unsupported schema_version {v!r} (supported: {sorted(SUPPORTED_VERSIONS)})",
        )


def _bounded_int(value: object, *, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValidationError([f"{name}: expected integer {low}..{high}"])
    return value


def _strict_bool(value: object, *, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError([f"{name}: expected boolean"])
    return value


def _normalized_unique_strings(value: object, *, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValidationError([f"{name}: must be a list"])
    if any(not isinstance(item, str) for item in value):
        raise ValidationError([f"{name}: values must be strings"])
    normalized = tuple(item.strip().lower() for item in value)
    if any(not item for item in normalized) or len(set(normalized)) != len(normalized):
        raise ValidationError([f"{name}: values must be non-empty and unique"])
    return normalized


def _restricted_hours(value: object) -> tuple[tuple[str, ...], str | None]:
    if value is None:
        return (), None
    if not isinstance(value, dict):
        raise ValidationError(["restricted_hours: must be a mapping"])
    allowed = {"timezone", "windows"}
    unknown = [key for key in value if key not in allowed]
    missing = [key for key in allowed if key not in value]
    if unknown or missing:
        raise ValidationError(["restricted_hours: requires only timezone and windows"])
    timezone = value["timezone"]
    if not isinstance(timezone, str) or not timezone.strip():
        raise ValidationError(["restricted_hours.timezone: must be a non-empty IANA name"])
    if any(0xD800 <= ord(character) <= 0xDFFF for character in timezone):
        raise ValidationError(["restricted_hours.timezone: invalid IANA name"])
    timezone = timezone.strip()
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValidationError(["restricted_hours.timezone: invalid IANA name"]) from exc
    windows = _normalized_unique_strings(value["windows"], name="restricted_hours.windows")
    if not windows:
        raise ValidationError(["restricted_hours.windows: must not be empty"])
    for window in windows:
        match = _RESTRICTED_HOURS_WINDOW_RE.fullmatch(window)
        if match is None:
            raise ValidationError(["restricted_hours.windows: must use HH:MM-HH:MM"])
        start = int(match["start_hour"]) * 60 + int(match["start_minute"])
        end = int(match["end_hour"]) * 60 + int(match["end_minute"])
        if start >= end:
            raise ValidationError(
                ["restricted_hours.windows: window must have an unambiguous duration"]
            )
    return windows, timezone


def validate_testing_policy(value: object) -> TestingPolicy:
    """Strictly validate testing rules and return a conservative frozen policy."""
    if not isinstance(value, dict):
        raise ValidationError(["testing_rules: must be a mapping"])
    unknown = [key for key in value if key not in _TESTING_KEYS]
    if unknown:
        raise ValidationError([f"testing_rules: unknown field {key!r}" for key in unknown])

    restricted_hours, restricted_hours_timezone = _restricted_hours(value.get("restricted_hours"))
    try:
        return TestingPolicy(
            max_requests_per_second=_bounded_int(
                value.get("max_requests_per_second", 1),
                name="max_requests_per_second",
                low=1,
                high=1_000,
            ),
            concurrency=_bounded_int(
                value.get("concurrency", 1), name="concurrency", low=1, high=100
            ),
            automated_scanning_allowed=_strict_bool(
                value.get("automated_scanning_allowed", False),
                name="automated_scanning_allowed",
            ),
            authenticated_testing_allowed=_strict_bool(
                value.get("authenticated_testing_allowed", False),
                name="authenticated_testing_allowed",
            ),
            account_creation_allowed=_strict_bool(
                value.get("account_creation_allowed", False), name="account_creation_allowed"
            ),
            multiple_accounts_allowed=_strict_bool(
                value.get("multiple_accounts_allowed", False),
                name="multiple_accounts_allowed",
            ),
            social_engineering_allowed=_strict_bool(
                value.get("social_engineering_allowed", False),
                name="social_engineering_allowed",
            ),
            denial_of_service_allowed=_strict_bool(
                value.get("denial_of_service_allowed", False),
                name="denial_of_service_allowed",
            ),
            out_of_band_testing_allowed=_strict_bool(
                value.get("out_of_band_testing_allowed", False),
                name="out_of_band_testing_allowed",
            ),
            source_ip_requirements=_normalized_unique_strings(
                value.get("source_ip_requirements"), name="source_ip_requirements"
            ),
            required_headers=_normalized_unique_strings(
                value.get("required_headers"), name="required_headers"
            ),
            restricted_hours=restricted_hours,
            restricted_hours_timezone=restricted_hours_timezone,
            prohibited_tools=_normalized_unique_strings(
                value.get("prohibited_tools"), name="prohibited_tools"
            ),
            prohibited_vulnerability_types=_normalized_unique_strings(
                value.get("prohibited_vulnerability_types"),
                name="prohibited_vulnerability_types",
            ),
            excluded_impacts=_normalized_unique_strings(
                value.get("excluded_impacts"), name="excluded_impacts"
            ),
        )
    except ValueError as exc:
        raise ValidationError([f"testing_rules: {exc}"]) from exc


def validate_program(doc: object) -> ScopeDoc:
    """Validate a full program.yaml. Returns the normalized ScopeDoc (default-deny)."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        raise ValidationError(["program document must be a mapping"])
    _check_version(doc.get("schema_version"), errors, "program")
    for k in doc:
        if k not in _PROGRAM_SECTIONS:
            _err(
                errors,
                f"program: unknown top-level section {k!r} "
                f"(allowed: {', '.join(_PROGRAM_SECTIONS)})",
            )
    # authorization: strict keys
    auth = doc.get("authorization")
    if auth is not None:
        if not isinstance(auth, dict):
            _err(errors, "authorization: must be a mapping")
        else:
            for k in auth:
                if k not in _AUTH_KEYS:
                    _err(errors, f"authorization: unknown field {k!r}")
    # testing_rules: strict keys
    if "testing_rules" in doc:
        tr = doc["testing_rules"]
        if not isinstance(tr, dict):
            _err(errors, "testing_rules: must be a mapping")
        else:
            for k in tr:
                if k not in _TESTING_KEYS:
                    _err(errors, f"testing_rules: unknown field {k!r}")
            try:
                validate_testing_policy(tr)
            except ValidationError as exc:
                errors.extend(exc.errors)
    # scope (nested, no its own version required)
    scope_section = doc.get("scope")
    if scope_section is None:
        _err(errors, "program: missing required scope section")
    in_rules: list[str] = []
    out_rules: list[str] = []
    sources: dict[str, str] = {}
    if isinstance(scope_section, dict):
        ir, isrc = _validate_scope_section(scope_section.get("in_scope"), errors, "in_scope")
        orr, osrc = _validate_scope_section(
            scope_section.get("out_of_scope"), errors, "out_of_scope"
        )
        for k in scope_section:
            if k not in ("in_scope", "out_of_scope"):
                _err(errors, f"scope: unknown security-critical field {k!r}")
        in_rules, out_rules, sources = ir, orr, {**isrc, **osrc}
        if not errors and not in_rules:
            _err(errors, "scope: in_scope has no valid entries (default-deny)")
    elif scope_section is not None:
        _err(errors, "scope: must be a mapping")
    if errors:
        raise ValidationError(errors)
    return ScopeDoc(in_rules=in_rules, out_rules=out_rules, rule_sources=sources)
