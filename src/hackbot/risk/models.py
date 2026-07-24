"""Secret-free, immutable values used by Hackbot's risk policy gate."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntEnum
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from hackbot.scope import Scope

_IDENTIFIER_LIMIT = 128
_TARGET_AND_RULE_LIMIT = 2_048
_ARGV_ITEM_LIMIT = 4_096
_ARGV_LIMIT = 128
_DESCRIPTIVE_LIMIT = 8_192
_RATE_MIN = 1
_RATE_MAX = 1_000
_CONCURRENCY_MIN = 1
_CONCURRENCY_MAX = 100
_HEADER_FIELD_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$", re.ASCII)


class RiskLevel(IntEnum):
    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3


class DecisionKind(str, Enum):
    ALLOW = "allow"
    REQUIRES_APPROVAL = "requires-approval"
    DENY = "deny"


def _text(value: object, *, name: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    if len(value) > limit:
        raise ValueError(f"{name} exceeds {limit} characters")
    return value


def _tuple_of_strings(
    value: object,
    *,
    name: str,
    item_limit: int,
    maximum_items: int | None = None,
    allow_empty_items: bool = True,
) -> tuple[str, ...]:
    if isinstance(value, str):
        raise ValueError(f"{name} must be a sequence of strings")
    try:
        items: tuple[object, ...] = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError(f"{name} must be a sequence of strings") from exc
    if maximum_items is not None and len(items) > maximum_items:
        raise ValueError(f"{name} contains more than {maximum_items} items")
    return tuple(
        _text(item, name=f"{name}[{index}]", limit=item_limit, allow_empty=allow_empty_items)
        for index, item in enumerate(items)
    )


def _bounded_optional_int(
    value: object,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} through {maximum}")
    return value


def _bounded_int(value: object, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} through {maximum}")
    return value


def _bool(value: object, *, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _normalized_unique_strings(value: object, *, name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        raise ValueError(f"{name} must be a sequence of strings")
    try:
        values: tuple[object, ...] = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError(f"{name} must be a sequence of strings") from exc
    normalized = tuple(
        _text(item, name=f"{name}[{index}]", limit=_DESCRIPTIVE_LIMIT).strip().lower()
        for index, item in enumerate(values)
    )
    if any(not item for item in normalized):
        raise ValueError(f"{name} values must be non-empty")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{name} values must be unique")
    return normalized


def _header_field_names(value: object) -> tuple[str, ...]:
    names = _normalized_unique_strings(value, name="required_headers")
    if any(_HEADER_FIELD_NAME_RE.fullmatch(name) is None for name in names):
        raise ValueError("required_headers must contain RFC token-like field names only")
    return names


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    action_id: str
    minimum_risk: RiskLevel
    network_access: bool = False
    low_impact_allowlisted: bool = False
    state_changing: bool = False
    high_volume: bool = False
    touches_third_party: bool = False
    required_profile: str | None = None

    @property
    def effective_floor(self) -> RiskLevel:
        elevated = self.state_changing or self.high_volume or self.touches_third_party
        return max(self.minimum_risk, RiskLevel.L2 if elevated else self.minimum_risk)


@dataclass(frozen=True, slots=True)
class ActionRequest:
    engagement_id: str
    engagement_path: str
    action_id: str
    target: str
    argv: tuple[str, ...]
    hypothesis_id: str
    rationale: str
    rate: int | None
    concurrency: int | None
    data_touched: str
    expected_impact: str
    stop_condition: str
    cleanup_plan: str
    program_rule: str
    required_headers: tuple[str, ...] = ()
    requested_risk: RiskLevel | None = None

    def __post_init__(self) -> None:
        _text(self.engagement_id, name="engagement_id", limit=_IDENTIFIER_LIMIT)
        _text(self.engagement_path, name="engagement_path", limit=_TARGET_AND_RULE_LIMIT)
        _text(self.action_id, name="action_id", limit=_IDENTIFIER_LIMIT)
        _text(self.target, name="target", limit=_TARGET_AND_RULE_LIMIT)
        object.__setattr__(
            self,
            "argv",
            _tuple_of_strings(
                self.argv,
                name="argv",
                item_limit=_ARGV_ITEM_LIMIT,
                maximum_items=_ARGV_LIMIT,
            ),
        )
        _text(
            self.hypothesis_id,
            name="hypothesis_id",
            limit=_IDENTIFIER_LIMIT,
            allow_empty=True,
        )
        _text(self.rationale, name="rationale", limit=_DESCRIPTIVE_LIMIT, allow_empty=True)
        rate = _bounded_optional_int(self.rate, name="rate", minimum=_RATE_MIN, maximum=_RATE_MAX)
        concurrency = _bounded_optional_int(
            self.concurrency,
            name="concurrency",
            minimum=_CONCURRENCY_MIN,
            maximum=_CONCURRENCY_MAX,
        )
        if (rate is None) != (concurrency is None):
            raise ValueError("rate and concurrency must be supplied together")
        active = rate is not None
        if active:
            _text(self.hypothesis_id, name="hypothesis_id", limit=_IDENTIFIER_LIMIT)
        _text(self.data_touched, name="data_touched", limit=_DESCRIPTIVE_LIMIT, allow_empty=True)
        _text(
            self.expected_impact,
            name="expected_impact",
            limit=_DESCRIPTIVE_LIMIT,
            allow_empty=True,
        )
        _text(
            self.stop_condition,
            name="stop_condition",
            limit=_DESCRIPTIVE_LIMIT,
            allow_empty=not active,
        )
        _text(
            self.cleanup_plan,
            name="cleanup_plan",
            limit=_DESCRIPTIVE_LIMIT,
            allow_empty=not active,
        )
        _text(self.program_rule, name="program_rule", limit=_TARGET_AND_RULE_LIMIT)
        object.__setattr__(
            self,
            "required_headers",
            _tuple_of_strings(
                self.required_headers,
                name="required_headers",
                item_limit=_IDENTIFIER_LIMIT,
                allow_empty_items=False,
            ),
        )
        if self.requested_risk is not None and not isinstance(self.requested_risk, RiskLevel):
            raise ValueError("requested_risk must be a RiskLevel or None")

    def effective_risk(self, definition: ActionDefinition) -> RiskLevel:
        return max(definition.effective_floor, self.requested_risk or RiskLevel.L0)


@dataclass(frozen=True, slots=True)
class TestingPolicy:
    max_requests_per_second: int
    concurrency: int
    automated_scanning_allowed: bool
    authenticated_testing_allowed: bool
    account_creation_allowed: bool
    multiple_accounts_allowed: bool
    social_engineering_allowed: bool
    denial_of_service_allowed: bool
    out_of_band_testing_allowed: bool
    source_ip_requirements: tuple[str, ...] = ()
    required_headers: tuple[str, ...] = ()
    restricted_hours: tuple[str, ...] = ()
    restricted_hours_timezone: str | None = None
    prohibited_tools: tuple[str, ...] = ()
    prohibited_vulnerability_types: tuple[str, ...] = ()
    excluded_impacts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _bounded_int(
            self.max_requests_per_second,
            name="max_requests_per_second",
            minimum=_RATE_MIN,
            maximum=_RATE_MAX,
        )
        _bounded_int(
            self.concurrency,
            name="concurrency",
            minimum=_CONCURRENCY_MIN,
            maximum=_CONCURRENCY_MAX,
        )
        for name in (
            "automated_scanning_allowed",
            "authenticated_testing_allowed",
            "account_creation_allowed",
            "multiple_accounts_allowed",
            "social_engineering_allowed",
            "denial_of_service_allowed",
            "out_of_band_testing_allowed",
        ):
            _bool(getattr(self, name), name=name)
        if self.social_engineering_allowed is not False:
            raise ValueError("social_engineering_allowed must be false")
        if self.denial_of_service_allowed is not False:
            raise ValueError("denial_of_service_allowed must be false")
        for name in (
            "source_ip_requirements",
            "restricted_hours",
            "prohibited_tools",
            "prohibited_vulnerability_types",
            "excluded_impacts",
        ):
            object.__setattr__(
                self,
                name,
                _normalized_unique_strings(getattr(self, name), name=name),
            )
        object.__setattr__(self, "required_headers", _header_field_names(self.required_headers))
        timezone = self.restricted_hours_timezone
        if timezone is not None:
            timezone = _text(
                timezone,
                name="restricted_hours_timezone",
                limit=_IDENTIFIER_LIMIT,
            ).strip()
            try:
                ZoneInfo(timezone)
            except ZoneInfoNotFoundError as exc:
                raise ValueError("restricted_hours_timezone must be a valid IANA name") from exc
            object.__setattr__(self, "restricted_hours_timezone", timezone)
        if bool(self.restricted_hours) != bool(timezone):
            raise ValueError(
                "restricted_hours and restricted_hours_timezone must be supplied together"
            )


@dataclass(frozen=True, slots=True)
class AuthorizationState:
    confirmed: bool
    confirmation_timestamp: datetime | None
    confirmed_by: str | None


@dataclass(frozen=True, slots=True)
class PolicyContext:
    engagement_id: str
    engagement_path: str
    program_id: str
    authorization: AuthorizationState
    scope: Scope
    testing_policy: TestingPolicy
    active_profile: str | None
    policy_digest: str


@dataclass(frozen=True, slots=True)
class ApprovalChallenge:
    engagement_id: str
    program_id: str
    target: str
    action_id: str
    argv: tuple[str, ...]
    effective_risk: RiskLevel
    rationale: str
    hypothesis_id: str
    expected_impact: str
    rate: int
    concurrency: int
    data_touched: str
    stop_condition: str
    program_rule: str
    cleanup_plan: str
    scope_digest: str
    policy_digest: str
    created_at: datetime
    expires_at: datetime
    nonce: str
    challenge_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "argv",
            _tuple_of_strings(
                self.argv,
                name="argv",
                item_limit=_ARGV_ITEM_LIMIT,
                maximum_items=_ARGV_LIMIT,
            ),
        )


@dataclass(frozen=True, slots=True)
class ApprovalGrant:
    challenge_digest: str
    policy_digest: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    kind: DecisionKind
    effective_risk: RiskLevel
    reason_code: str
    explanation: str
    scope_rule: str | None
    program_rule: str | None
    policy_digest: str
    challenge: ApprovalChallenge | None = None

    @classmethod
    def deny(
        cls,
        reason_code: str,
        effective_risk: RiskLevel = RiskLevel.L0,
        *,
        explanation: str = "",
        scope_rule: str | None = None,
        program_rule: str | None = None,
        policy_digest: str = "",
    ) -> PolicyDecision:
        return cls(
            DecisionKind.DENY,
            effective_risk,
            reason_code,
            explanation,
            scope_rule,
            program_rule,
            policy_digest,
        )

    @classmethod
    def allow(
        cls,
        effective_risk: RiskLevel,
        policy_digest: str,
        *,
        explanation: str = "",
        scope_rule: str | None = None,
        program_rule: str | None = None,
    ) -> PolicyDecision:
        return cls(
            DecisionKind.ALLOW,
            effective_risk,
            "ALLOW",
            explanation,
            scope_rule,
            program_rule,
            policy_digest,
        )
