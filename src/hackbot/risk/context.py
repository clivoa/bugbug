"""Fail-closed conversion of engagement files into a frozen policy context."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hackbot.programs.loader import ProgramError, load_program_file, load_scope_file
from hackbot.programs.schema import ValidationError, validate_testing_policy
from hackbot.risk.identity import EngagementIdentityError, canonical_engagement_identity
from hackbot.risk.models import AuthorizationState, PolicyContext, TestingPolicy

_AUTHORIZATION_KEYS = frozenset({"confirmed", "confirmation_timestamp", "confirmed_by", "note"})
_REQUIRED_AUTHORIZATION_KEYS = frozenset({"confirmed", "confirmation_timestamp", "confirmed_by"})
_IDENTIFIER_LIMIT = 128
_NOTE_LIMIT = 8_192


class ContextError(Exception):
    """Raised when any engagement input cannot produce a safe policy context."""


class _DuplicateJSONKey(ValueError):
    pass


def _bounded_text(value: object, *, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ContextError(f"{name}: expected a non-empty string up to {limit} characters")
    return value.strip()


def _parse_utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ContextError("confirmation_timestamp: expected a UTC ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContextError("confirmation_timestamp: invalid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(None):
        raise ContextError("confirmation_timestamp: timestamp must be UTC")
    return parsed.astimezone(UTC)


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJSONKey(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_authorization(path: str | Path) -> AuthorizationState:
    """Load strict, non-secret authorization state; unknown keys fail closed."""
    authorization_path = Path(path)
    try:
        value = json.loads(
            authorization_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except _DuplicateJSONKey as exc:
        raise ContextError(f"authorization: {exc}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ContextError(f"authorization: unable to read {authorization_path}") from exc
    if not isinstance(value, dict):
        raise ContextError("authorization: expected a JSON object")
    keys = set(value)
    unknown = keys - _AUTHORIZATION_KEYS
    missing = _REQUIRED_AUTHORIZATION_KEYS - keys
    if unknown:
        raise ContextError(f"authorization: unknown field {sorted(unknown)[0]!r}")
    if missing:
        raise ContextError(f"authorization: missing field {sorted(missing)[0]!r}")
    note = value.get("note")
    if "note" in value and (not isinstance(note, str) or len(note) > _NOTE_LIMIT):
        raise ContextError(f"authorization.note: expected a string up to {_NOTE_LIMIT} characters")

    confirmed = value["confirmed"]
    timestamp = value["confirmation_timestamp"]
    confirmed_by = value["confirmed_by"]
    if not isinstance(confirmed, bool):
        raise ContextError("authorization.confirmed: expected boolean")
    if not confirmed:
        if timestamp is not None or confirmed_by is not None:
            raise ContextError("authorization: denied state must not include confirmation details")
        return AuthorizationState(False, None, None)
    return AuthorizationState(
        True,
        _parse_utc_timestamp(timestamp),
        _bounded_text(confirmed_by, name="confirmed_by", limit=_IDENTIFIER_LIMIT),
    )


def _program_id(program_document: dict[str, Any]) -> str:
    program = program_document.get("program")
    if not isinstance(program, dict):
        raise ContextError("program: missing program identity")
    return _bounded_text(program.get("name"), name="program.name", limit=_IDENTIFIER_LIMIT)


def _canonical_policy_data(
    *,
    engagement_id: str,
    engagement_path: str,
    program_id: str,
    authorization: AuthorizationState,
    scope_in: tuple[str, ...],
    scope_out: tuple[str, ...],
    testing_policy: TestingPolicy,
    active_profile: str | None,
) -> dict[str, object]:
    return {
        "engagement_id": engagement_id,
        "engagement_path": engagement_path,
        "program_id": program_id,
        "authorization": {
            "confirmed": authorization.confirmed,
            "confirmation_timestamp": authorization.confirmation_timestamp.isoformat()
            if authorization.confirmation_timestamp
            else None,
            "confirmed_by": authorization.confirmed_by,
        },
        "scope": {"in_scope": scope_in, "out_of_scope": scope_out},
        "testing_policy": {
            "max_requests_per_second": testing_policy.max_requests_per_second,
            "concurrency": testing_policy.concurrency,
            "automated_scanning_allowed": testing_policy.automated_scanning_allowed,
            "authenticated_testing_allowed": testing_policy.authenticated_testing_allowed,
            "account_creation_allowed": testing_policy.account_creation_allowed,
            "multiple_accounts_allowed": testing_policy.multiple_accounts_allowed,
            "social_engineering_allowed": testing_policy.social_engineering_allowed,
            "denial_of_service_allowed": testing_policy.denial_of_service_allowed,
            "out_of_band_testing_allowed": testing_policy.out_of_band_testing_allowed,
            "source_ip_requirements": testing_policy.source_ip_requirements,
            "required_headers": testing_policy.required_headers,
            "restricted_hours": testing_policy.restricted_hours,
            "restricted_hours_timezone": testing_policy.restricted_hours_timezone,
            "prohibited_tools": testing_policy.prohibited_tools,
            "prohibited_vulnerability_types": testing_policy.prohibited_vulnerability_types,
            "excluded_impacts": testing_policy.excluded_impacts,
        },
        "active_profile": active_profile,
    }


def _policy_digest(value: dict[str, object]) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _scope_snapshot(
    scope_in: tuple[str, ...], scope_out: tuple[str, ...]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return tuple(sorted(scope_in)), tuple(sorted(scope_out))


def load_policy_context(
    engagement_dir: str | Path,
    profile: str | None = None,
    now: datetime | None = None,
) -> PolicyContext:
    """Load an independently validated engagement snapshot, or fail closed."""
    del now  # Evaluation, not loading, applies restricted-hour checks against an injected clock.
    try:
        engagement_path, engagement_id = canonical_engagement_identity(engagement_dir)
    except EngagementIdentityError as exc:
        raise ContextError(str(exc)) from exc
    directory = Path(engagement_path)
    try:
        program_document, program_scope = load_program_file(
            directory / "program.yaml", name=directory.name
        )
        scope = load_scope_file(directory / "scope.yaml", name=directory.name)
        testing_policy = validate_testing_policy(program_document.get("testing_rules", {}))
        authorization = load_authorization(directory / "authorization.json")
    except (ContextError, ProgramError, ValidationError, OSError) as exc:
        if isinstance(exc, ContextError):
            raise
        raise ContextError(f"engagement policy could not be loaded: {exc}") from exc
    if not authorization.confirmed:
        raise ContextError("authorization: confirmation is required")
    program_snapshot = _scope_snapshot(program_scope.in_scope, program_scope.out_of_scope)
    standalone_snapshot = _scope_snapshot(scope.in_scope, scope.out_of_scope)
    if standalone_snapshot != program_snapshot:
        raise ContextError("scope: standalone scope must exactly match the embedded program scope")
    program_id = _program_id(program_document)
    active_profile = (
        _bounded_text(profile, name="profile", limit=_IDENTIFIER_LIMIT)
        if profile is not None
        else None
    )
    digest_data = _canonical_policy_data(
        engagement_id=engagement_id,
        engagement_path=engagement_path,
        program_id=program_id,
        authorization=authorization,
        scope_in=standalone_snapshot[0],
        scope_out=standalone_snapshot[1],
        testing_policy=testing_policy,
        active_profile=active_profile,
    )
    return PolicyContext(
        engagement_id=engagement_id,
        engagement_path=engagement_path,
        program_id=program_id,
        authorization=authorization,
        scope=scope,
        testing_policy=testing_policy,
        active_profile=active_profile,
        policy_digest=_policy_digest(digest_data),
    )
