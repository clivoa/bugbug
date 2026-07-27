"""Security-relevant authority projection and domain-separated identity.

P1 builds the canonical security view that the confirmed-authority digest
covers and derives a stable, secret-free engagement namespace identity. The
projection is an explicit allowlist: only security-relevant values enter it, and
set-like collections are normalized (sorted) so semantically equal authority is
byte-identical after P0 ``canonical_bytes``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from hackbot.engagement_v2.canonical import authority_digest, digest_value
from hackbot.engagement_v2.constants import (
    POLICY_BOOLEAN_FIELDS,
    RUNNER_SECURITY_PROJECTION_FIELDS,
)

# Domain tag for the engagement namespace identity. It is separate from the
# authority and execution projection domains so an identity can never be
# confused with an authority digest.
ENGAGEMENT_NAMESPACE_FORMAT = "hackbot-engagement-namespace-v1"

# testing_rules numeric limits and array fields that are security-relevant.
_POLICY_NUMERIC_FIELDS = (
    "max_requests_per_second",
    "concurrency",
    "timeout_seconds",
    "output_cap_bytes",
    "max_targets_per_action",
)
_POLICY_LIST_FIELDS = (
    "excluded_impacts",
    "prohibited_tools",
    "prohibited_vulnerability_types",
    "required_headers",
    "source_ip_requirements",
)

# Ordered scope kinds. Membership is set-like, so each present kind is sorted.
_SCOPE_KINDS = (
    "domains",
    "wildcard_domains",
    "urls",
    "hosts",
    "cidrs",
    "network_endpoints",
    "mobile_apps",
    "repositories",
    "contracts",
)


def _sorted_str_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise TypeError("expected a list of strings")
    items = [item for item in value]
    if any(not isinstance(item, str) for item in items):
        raise TypeError("scope entries must be strings")
    # Set-like normalization: de-duplicate and sort so ordering and repetition
    # never change the digest.
    return sorted(set(items))


def _scope_section_projection(section: Mapping[str, object]) -> dict[str, list[str]]:
    projected: dict[str, list[str]] = {}
    for kind in _SCOPE_KINDS:
        if kind in section:
            projected[kind] = _sorted_str_list(section[kind])
    return projected


def _policy_projection(testing_rules: Mapping[str, object]) -> dict[str, object]:
    policy: dict[str, object] = {}
    for field in _POLICY_NUMERIC_FIELDS:
        if field in testing_rules:
            policy[field] = testing_rules[field]
    for field in sorted(POLICY_BOOLEAN_FIELDS):
        if field in testing_rules:
            policy[field] = testing_rules[field]
    for field in _POLICY_LIST_FIELDS:
        if field in testing_rules:
            policy[field] = _sorted_str_list(testing_rules[field])
    if "restricted_hours" in testing_rules:
        policy["restricted_hours"] = testing_rules["restricted_hours"]
    return policy


def _runner_projection(runner: Mapping[str, object] | None) -> object:
    if runner is None:
        return None
    projected: dict[str, object] = {}
    for dotted in RUNNER_SECURITY_PROJECTION_FIELDS:
        node: object = runner
        found = True
        for part in dotted.split("."):
            if isinstance(node, Mapping) and part in node:
                node = node[part]
            else:
                found = False
                break
        if not found:
            continue
        target = projected
        parts = dotted.split(".")
        for part in parts[:-1]:
            child = target.get(part)
            if not isinstance(child, dict):
                child = {}
                target[part] = child
            target = child
        target[parts[-1]] = node
    return projected


def security_projection(
    *,
    program: Mapping[str, object],
    scope: Mapping[str, object],
    runner: Mapping[str, object] | None,
) -> dict[str, object]:
    """Return the canonical security-relevant projection of an authority set.

    The projection excludes non-security content (notes, comments, key order,
    local private-key paths, connection timeouts, and any secret material) and
    normalizes set-like scope/impact lists so that only a security-relevant
    change alters the resulting canonical bytes.
    """

    testing_rules = program.get("testing_rules")
    if not isinstance(testing_rules, Mapping):
        raise TypeError("program.testing_rules must be a mapping")
    in_scope = scope.get("in_scope")
    out_of_scope = scope.get("out_of_scope")
    if not isinstance(in_scope, Mapping) or not isinstance(out_of_scope, Mapping):
        raise TypeError("scope in_scope/out_of_scope must be mappings")
    return {
        "profile": program.get("profile"),
        "policy": _policy_projection(testing_rules),
        "scope": {
            "in_scope": _scope_section_projection(in_scope),
            "out_of_scope": _scope_section_projection(out_of_scope),
        },
        "runner": _runner_projection(runner),
    }


def projection_digest(projection: Mapping[str, object]) -> str:
    """Return the authority digest of a security projection."""

    return authority_digest(projection)


def engagement_identity(authority_digest_value: str) -> str:
    """Return the stable engagement namespace identity for a confirmed authority.

    The identity is a domain-separated digest of the confirmed authority digest.
    It changes exactly when the security-relevant authority changes and, being a
    hash, embeds no secret, local path, or timestamp.
    """

    return digest_value(
        {"contract": ENGAGEMENT_NAMESPACE_FORMAT, "authority_digest": authority_digest_value}
    )
