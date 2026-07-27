"""Read-only v1 -> v2 engagement migration analysis.

This module is pure: it accepts already-parsed and v1-validated documents and
returns a proposed v2 tree plus warnings. It performs no filesystem I/O and,
being analysis-only, never writes, backs up, or publishes anything. Effective
migration, backup, and restore are delivered later (P7); the CLI that reaches
this analyzer is responsible for reading and v1-validating the source engagement.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from hackbot.engagement_v2.constants import (
    AUTHORIZATION_SCHEMA_VERSION,
    POLICY_BOOLEAN_FIELDS,
    PROGRAM_SCHEMA_VERSION,
    SCOPE_SCHEMA_VERSION,
    Profile,
)

_POLICY_NUMERIC_FIELDS = (
    "max_requests_per_second",
    "concurrency",
    "timeout_seconds",
    "output_cap_bytes",
    "max_targets_per_action",
)

# Conservative per-profile scaffold defaults used only when a v1 engagement does
# not already carry a compatible numeric value forward.
_PROFILE_NUMERIC_DEFAULTS: dict[str, dict[str, int]] = {
    Profile.BUG_BOUNTY.value: {
        "max_requests_per_second": 5,
        "concurrency": 2,
        "timeout_seconds": 30,
        "output_cap_bytes": 1_048_576,
        "max_targets_per_action": 64,
    },
    Profile.LOCAL_LAB.value: {
        "max_requests_per_second": 50,
        "concurrency": 8,
        "timeout_seconds": 120,
        "output_cap_bytes": 4_194_304,
        "max_targets_per_action": 1_024,
    },
    Profile.PRIVATE_PENTEST.value: {
        "max_requests_per_second": 10,
        "concurrency": 4,
        "timeout_seconds": 60,
        "output_cap_bytes": 2_097_152,
        "max_targets_per_action": 256,
    },
}


class MigrationError(ValueError):
    """Raised when a migration analysis cannot proceed (never writes anything)."""


@dataclass(frozen=True)
class MigrationAnalysis:
    """The proposed v2 tree and warnings from a read-only migration analysis."""

    profile: str
    proposed: Mapping[str, object]
    warnings: tuple[str, ...]
    ready: bool


def _proposed_program(
    v1_program: Mapping[str, object], profile: str
) -> tuple[dict[str, object], list[str]]:
    warnings: list[str] = []
    v1_rules = v1_program.get("testing_rules")
    v1_rules = v1_rules if isinstance(v1_rules, Mapping) else {}
    defaults = _PROFILE_NUMERIC_DEFAULTS[profile]
    testing_rules: dict[str, object] = {}
    for field in _POLICY_NUMERIC_FIELDS:
        carried = v1_rules.get(field)
        if isinstance(carried, int) and not isinstance(carried, bool):
            testing_rules[field] = carried
        else:
            testing_rules[field] = defaults[field]
    # Every sensitive capability is written explicitly and defaulted to false.
    for field in sorted(POLICY_BOOLEAN_FIELDS):
        testing_rules[field] = False
        if v1_rules.get(field) is True:
            warnings.append(
                f"v1 enabled '{field}'; v2 defaults it to false pending explicit re-declaration"
            )

    program_section = v1_program.get("program")
    program_section = dict(program_section) if isinstance(program_section, Mapping) else {}
    reporting_value = v1_program.get("reporting")
    reporting = (
        dict(reporting_value)
        if isinstance(reporting_value, Mapping)
        else {"duplicate_policy": "first-wins"}
    )

    proposed = {
        "schema_version": PROGRAM_SCHEMA_VERSION,
        "profile": profile,
        "program": program_section,
        "testing_rules": testing_rules,
        "reporting": reporting,
    }
    return proposed, warnings


def _proposed_scope(v1_scope: Mapping[str, object]) -> dict[str, object]:
    in_scope = v1_scope.get("in_scope")
    out_of_scope = v1_scope.get("out_of_scope")
    return {
        "schema_version": SCOPE_SCHEMA_VERSION,
        # Preserve the exact authoritative scope; no silent widening.
        "in_scope": dict(in_scope) if isinstance(in_scope, Mapping) else {},
        "out_of_scope": dict(out_of_scope) if isinstance(out_of_scope, Mapping) else {},
    }


def _proposed_authorization(v1_authorization: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_version": AUTHORIZATION_SCHEMA_VERSION,
        # v2 requires an explicit reconfirmation bound to the authority digest.
        "confirmed": False,
        "confirmation_timestamp": v1_authorization.get("confirmation_timestamp"),
        "confirmed_by": v1_authorization.get("confirmed_by"),
        "confirmed_authority_digest": None,
        "note": "migrated from v1; reconfirm in v2 before any active testing",
    }


def analyze_migration(
    *,
    v1_program: Mapping[str, object],
    v1_scope: Mapping[str, object],
    v1_authorization: Mapping[str, object],
    profile: str,
) -> MigrationAnalysis:
    """Return a proposed v2 tree and warnings without writing anything."""

    if profile not in {member.value for member in Profile}:
        raise MigrationError(f"unknown profile: {profile!r}")

    program, warnings = _proposed_program(v1_program, profile)
    scope = _proposed_scope(v1_scope)
    authorization = _proposed_authorization(v1_authorization)

    # v2 execution (P2 policy, P3 executor, P4 remote) is not yet delivered, so
    # an effective migration cannot be enforced. Analysis stays read-only and is
    # never presented as ready to apply.
    warnings.append(
        "effective migration unavailable: v2 policy/executor/remote subsystems are not "
        "yet delivered; this is analysis only and writes nothing"
    )
    warnings.append(
        "existing v1 approval artifacts are recorded as historical and are ineffective in v2"
    )

    proposed = {
        "program.yaml": program,
        "scope.yaml": scope,
        "authorization.json": authorization,
        # An empty action manifest is proposed unless the operator supplies one.
        "actions.yaml": {"schema_version": 1, "actions": []},
    }
    return MigrationAnalysis(
        profile=profile, proposed=proposed, warnings=tuple(warnings), ready=False
    )
