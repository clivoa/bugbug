"""Fail-closed conversion of engagement files into a frozen policy context."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hackbot.programs.loader import ProgramError, load_program_file, load_scope_file
from hackbot.programs.schema import ValidationError, validate_testing_policy
from hackbot.risk.models import AuthorizationState, PolicyContext, TestingPolicy

_AUTHORIZATION_KEYS = frozenset({"confirmed", "confirmation_timestamp", "confirmed_by", "note"})
_REQUIRED_AUTHORIZATION_KEYS = frozenset({"confirmed", "confirmation_timestamp", "confirmed_by"})
_IDENTIFIER_LIMIT = 128
_NOTE_LIMIT = 8_192


class ContextError(Exception):
    """Raised when any engagement input cannot produce a safe policy context."""


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


def load_authorization(path: str | Path) -> AuthorizationState:
    """Load strict, non-secret authorization state; unknown keys fail closed."""
    authorization_path = Path(path)
    try:
        value = json.loads(authorization_path.read_text(encoding="utf-8"))
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
    program_id: str,
    authorization: AuthorizationState,
    scope_in: tuple[str, ...],
    scope_out: tuple[str, ...],
    testing_policy: TestingPolicy,
    active_profile: str | None,
) -> dict[str, object]:
    return {
        "engagement_id": engagement_id,
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


def load_policy_context(
    engagement_dir: str | Path,
    profile: str | None = None,
    now: datetime | None = None,
) -> PolicyContext:
    """Load an independently validated engagement snapshot, or fail closed."""
    del now  # Evaluation, not loading, applies restricted-hour checks against an injected clock.
    directory = Path(engagement_dir)
    try:
        program_document, _ = load_program_file(directory / "program.yaml", name=directory.name)
        scope = load_scope_file(directory / "scope.yaml", name=directory.name)
        testing_policy = validate_testing_policy(program_document.get("testing_rules", {}))
        authorization = load_authorization(directory / "authorization.json")
    except (ContextError, ProgramError, ValidationError, OSError) as exc:
        if isinstance(exc, ContextError):
            raise
        raise ContextError(f"engagement policy could not be loaded: {exc}") from exc
    if not authorization.confirmed:
        raise ContextError("authorization: confirmation is required")
    engagement_id = _bounded_text(directory.name, name="engagement_id", limit=_IDENTIFIER_LIMIT)
    program_id = _program_id(program_document)
    active_profile = (
        _bounded_text(profile, name="profile", limit=_IDENTIFIER_LIMIT)
        if profile is not None
        else None
    )
    digest_data = _canonical_policy_data(
        engagement_id=engagement_id,
        program_id=program_id,
        authorization=authorization,
        scope_in=scope.in_scope,
        scope_out=scope.out_of_scope,
        testing_policy=testing_policy,
        active_profile=active_profile,
    )
    return PolicyContext(
        engagement_id=engagement_id,
        program_id=program_id,
        authorization=authorization,
        scope=scope,
        testing_policy=testing_policy,
        active_profile=active_profile,
        policy_digest=_policy_digest(digest_data),
    )
