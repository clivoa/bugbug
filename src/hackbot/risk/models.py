"""Secret-free, immutable values used by Hackbot's risk policy gate."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntEnum
from pathlib import PurePath, PureWindowsPath
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from hackbot.risk.identity import EngagementIdentityError, canonical_engagement_identity
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
_CODE_IDENTITY_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$", re.ASCII)
_SHELL_EXECUTABLE_BASENAMES = frozenset(
    {
        "sh",
        "sh.exe",
        "bash",
        "bash.exe",
        "zsh",
        "zsh.exe",
        "fish",
        "fish.exe",
        "dash",
        "dash.exe",
        "ksh",
        "ksh.exe",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "env",
        "env.exe",
        "busybox",
        "busybox.exe",
        "csh",
        "csh.exe",
        "tcsh",
        "tcsh.exe",
    }
)
_ARGV_PLACEHOLDERS = frozenset({"{target}", "{rate}", "{concurrency}"})
_SHELL_COMMAND_MODES = frozenset({"-c", "--command"})


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
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError(f"{name} contains invalid Unicode")
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


def _header_field_names(value: object, *, maximum_items: int | None = None) -> tuple[str, ...]:
    items = _tuple_of_strings(
        value,
        name="required_headers",
        item_limit=_IDENTIFIER_LIMIT,
        maximum_items=maximum_items,
        allow_empty_items=False,
    )
    names = tuple(item.strip().lower() for item in items)
    if any(not name for name in names) or len(set(names)) != len(names):
        raise ValueError("required_headers values must be non-empty and unique")
    if any(_HEADER_FIELD_NAME_RE.fullmatch(name) is None for name in names):
        raise ValueError("required_headers must contain RFC token-like field names only")
    return names


def _code_identity(value: object, *, name: str) -> str:
    text = _text(value, name=name, limit=_IDENTIFIER_LIMIT)
    if text != text.strip().lower() or _CODE_IDENTITY_RE.fullmatch(text) is None:
        raise ValueError(f"{name} must be a canonical code-owned identity")
    return text


def _canonical_absolute_path(value: object, *, name: str) -> str:
    path = _text(value, name=name, limit=_TARGET_AND_RULE_LIMIT)
    if path != path.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in path
    ):
        raise ValueError(f"{name} must be a canonical absolute path")
    normalized = path.replace("\\", "/").lower()
    if normalized.startswith("/"):
        remainder = normalized[1:]
    elif re.fullmatch(r"[a-z]:/.*", normalized) is not None:
        remainder = normalized[3:]
    else:
        raise ValueError(f"{name} must be a canonical absolute path")
    segments = remainder.split("/")
    if not segments or any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError(f"{name} must be a canonical absolute path")
    return normalized


def canonical_tool_identity(value: object, *, name: str = "tool identity") -> str:
    """Return a pure lexical canonical tool ID or absolute executable path."""
    text = _text(value, name=name, limit=_TARGET_AND_RULE_LIMIT)
    if "/" in text or "\\" in text:
        return _canonical_absolute_path(text, name=name)
    return _code_identity(text, name=name)


def _code_classifications(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"{name} must be an immutable tuple of code-owned identities")
    for item in value:
        _code_identity(item, name=name)
    if len(set(value)) != len(value):
        raise ValueError(f"{name} values must be unique")
    return value


def _argv_template(value: object, *, executable: str) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise ValueError("argv_template must be an immutable tuple")
    template = _tuple_of_strings(
        value,
        name="argv_template",
        item_limit=_ARGV_ITEM_LIMIT,
        maximum_items=_ARGV_LIMIT,
        allow_empty_items=False,
    )
    if not template or template[0] != executable:
        raise ValueError("argv_template[0] must exactly equal executable")
    placeholders: set[str] = set()
    for token in template[1:]:
        if "{" in token or "}" in token:
            if token not in _ARGV_PLACEHOLDERS or token in placeholders:
                raise ValueError(
                    "argv_template placeholders must be unique whole-token placeholders"
                )
            placeholders.add(token)
    return template


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
    tool_id: str | None = None
    executable: str | None = None
    uses_external_tool: bool = False
    argv_template: tuple[str, ...] = ()
    vulnerability_types: tuple[str, ...] = ()
    impacts: tuple[str, ...] = ()
    automated: bool = False
    authenticated: bool = False
    creates_account: bool = False
    uses_multiple_accounts: bool = False
    out_of_band: bool = False
    honors_required_headers: bool = False
    shell_execution: bool = False

    def __post_init__(self) -> None:
        if self.executable is not None:
            object.__setattr__(
                self, "executable", canonical_tool_identity(self.executable, name="executable")
            )
        self.validate()

    def validate(self) -> None:
        """Validate a code-owned definition before registry admission or use."""
        _code_identity(self.action_id, name="action_id")
        if type(self.minimum_risk) is not RiskLevel:
            raise ValueError("minimum_risk must be an exact RiskLevel")
        for name in (
            "network_access",
            "low_impact_allowlisted",
            "state_changing",
            "high_volume",
            "touches_third_party",
            "automated",
            "authenticated",
            "creates_account",
            "uses_multiple_accounts",
            "out_of_band",
            "honors_required_headers",
            "shell_execution",
            "uses_external_tool",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if self.required_profile is not None:
            _code_identity(self.required_profile, name="required_profile")
        if self.tool_id is not None:
            _code_identity(self.tool_id, name="tool_id")
        if self.executable is not None:
            if self.executable != canonical_tool_identity(self.executable, name="executable"):
                raise ValueError("executable must be a canonical absolute path")
        if self.uses_external_tool and self.executable is None:
            raise ValueError("external tools require a trusted executable")
        if not self.uses_external_tool and (
            self.tool_id is not None or self.executable is not None
        ):
            raise ValueError("tool_id and executable require uses_external_tool=true")
        if self.shell_execution and (not self.uses_external_tool or self.executable is None):
            raise ValueError("shell_execution requires an external executable")
        if self.uses_external_tool:
            if self.executable is None:  # mypy narrowness and defense in depth
                raise ValueError("external tools require a trusted executable")
            _argv_template(self.argv_template, executable=self.executable)
        elif self.argv_template != ():
            raise ValueError("no-tool definitions must use an empty argv_template")
        if self.executable is not None:
            basenames = {
                PurePath(self.executable).name.lower(),
                PureWindowsPath(self.executable).name.lower(),
            }
            if not basenames.isdisjoint(_SHELL_EXECUTABLE_BASENAMES) and not self.shell_execution:
                raise ValueError("known shell executables require shell_execution=true")
        if (
            any(token in _SHELL_COMMAND_MODES for token in self.argv_template)
            and not self.shell_execution
        ):
            raise ValueError("shell command modes require shell_execution=true")
        _code_classifications(self.vulnerability_types, name="vulnerability_types")
        _code_classifications(self.impacts, name="impacts")

    @property
    def effective_floor(self) -> RiskLevel:
        if self.shell_execution:
            return RiskLevel.L3
        l2 = (
            self.state_changing
            or self.high_volume
            or self.touches_third_party
            or self.creates_account
            or self.uses_multiple_accounts
            or self.out_of_band
        )
        l1 = self.automated or self.authenticated
        return max(
            self.minimum_risk,
            RiskLevel.L2 if l2 else RiskLevel.L1 if l1 else self.minimum_risk,
        )

    def render_argv(self, request: ActionRequest) -> tuple[str, ...] | None:
        """Render the small, code-owned template without shell parsing or splitting."""
        if not self.uses_external_tool:
            return ()
        if (
            isinstance(request.rate, bool)
            or not isinstance(request.rate, int)
            or isinstance(request.concurrency, bool)
            or not isinstance(request.concurrency, int)
        ):
            return None
        values = {
            "{target}": request.target,
            "{rate}": str(request.rate),
            "{concurrency}": str(request.concurrency),
        }
        return tuple(values.get(token, token) for token in self.argv_template)


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
        try:
            engagement_path, engagement_id = canonical_engagement_identity(self.engagement_path)
        except EngagementIdentityError as exc:
            raise ValueError(str(exc)) from exc
        if self.engagement_id != engagement_id:
            raise ValueError("engagement_id must match the canonical engagement_path")
        object.__setattr__(self, "engagement_path", engagement_path)
        object.__setattr__(self, "engagement_id", engagement_id)
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
            _header_field_names(self.required_headers, maximum_items=_ARGV_LIMIT),
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
            except (ZoneInfoNotFoundError, ValueError) as exc:
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
        _text(self.engagement_id, name="engagement_id", limit=_IDENTIFIER_LIMIT)
        _text(self.program_id, name="program_id", limit=_IDENTIFIER_LIMIT)
        _text(self.target, name="target", limit=_TARGET_AND_RULE_LIMIT)
        _text(self.action_id, name="action_id", limit=_IDENTIFIER_LIMIT)
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
        _text(self.rationale, name="rationale", limit=_DESCRIPTIVE_LIMIT, allow_empty=True)
        _text(self.hypothesis_id, name="hypothesis_id", limit=_IDENTIFIER_LIMIT, allow_empty=True)
        _text(
            self.expected_impact,
            name="expected_impact",
            limit=_DESCRIPTIVE_LIMIT,
            allow_empty=True,
        )
        _bounded_int(self.rate, name="rate", minimum=_RATE_MIN, maximum=_RATE_MAX)
        _bounded_int(
            self.concurrency,
            name="concurrency",
            minimum=_CONCURRENCY_MIN,
            maximum=_CONCURRENCY_MAX,
        )
        _text(self.data_touched, name="data_touched", limit=_DESCRIPTIVE_LIMIT, allow_empty=True)
        _text(
            self.stop_condition,
            name="stop_condition",
            limit=_DESCRIPTIVE_LIMIT,
            allow_empty=True,
        )
        _text(self.program_rule, name="program_rule", limit=_TARGET_AND_RULE_LIMIT)
        _text(self.cleanup_plan, name="cleanup_plan", limit=_DESCRIPTIVE_LIMIT, allow_empty=True)
        _text(self.scope_digest, name="scope_digest", limit=_IDENTIFIER_LIMIT)
        _text(self.policy_digest, name="policy_digest", limit=_IDENTIFIER_LIMIT)
        _text(self.nonce, name="nonce", limit=_IDENTIFIER_LIMIT)
        _text(self.challenge_digest, name="challenge_digest", limit=_IDENTIFIER_LIMIT)


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
