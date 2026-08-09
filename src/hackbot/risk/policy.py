"""Pure, deterministic, fail-closed evaluation for the local risk gate.

Restricted-hour windows deny testing from their local start time (inclusive)
until their local end time (exclusive).  The evaluator accepts an injected,
aware UTC ``now`` only; a missing, naive, or non-UTC clock denies whenever a
restricted-hours policy needs to be evaluated.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from datetime import datetime, timedelta
from pathlib import PurePath, PureWindowsPath
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from hackbot.risk.models import (
    ActionDefinition,
    ActionRequest,
    ApprovalGrant,
    AuthorizationState,
    DecisionKind,
    PolicyContext,
    PolicyDecision,
    RiskLevel,
    TestingPolicy,
    canonical_tool_identity,
)
from hackbot.risk.registry import ActionRegistry, RegistryError

if TYPE_CHECKING:
    from hackbot.risk.approvals import ApprovalStore

_HOUR_WINDOW = re.compile(
    r"^(?P<start_hour>[01]\d|2[0-3]):(?P<start_minute>[0-5]\d)-"
    r"(?P<end_hour>[01]\d|2[0-3]):(?P<end_minute>[0-5]\d)$"
)
_IDENTIFIER_LIMIT = 128


class RiskEngine:
    """Evaluate policy and delegate exact L2 consumption to a bound local store."""

    def __init__(
        self,
        registry: ActionRegistry,
        *,
        approval_store: ApprovalStore | None = None,
    ) -> None:
        self.registry = registry
        self.approval_store = approval_store

    def evaluate(
        self,
        request: ActionRequest,
        context: PolicyContext,
        grant: object | None = None,
        now: datetime | None = None,
    ) -> PolicyDecision:
        """Evaluate policy, consuming one exact L2 grant only after preflight passes."""
        preflight = self._evaluate_without_approval(request, context, now=now)
        if preflight.kind is not DecisionKind.REQUIRES_APPROVAL:
            return preflight
        try:
            definition = self.registry.require(request.action_id)
        except RegistryError:
            return self._deny(
                "DENY_UNKNOWN_ACTION", context=context, program_rule=request.program_rule
            )
        return self._approval_decision(
            definition,
            request,
            context,
            preflight,
            grant=grant,
            now=now,
        )

    def _evaluate_without_approval(
        self,
        request: ActionRequest,
        context: PolicyContext,
        *,
        now: datetime | None = None,
    ) -> PolicyDecision:
        """Run the complete pure policy phase without challenge creation or store I/O."""
        if not isinstance(request, ActionRequest):
            return PolicyDecision.deny("DENY_INVALID_REQUEST")
        if not isinstance(context, PolicyContext):
            return PolicyDecision.deny("DENY_INVALID_CONTEXT")
        if (
            request.engagement_id != context.engagement_id
            or request.engagement_path != context.engagement_path
        ):
            return self._deny(
                "DENY_ENGAGEMENT_MISMATCH", context=context, program_rule=request.program_rule
            )
        if not self._confirmed_authorization(context.authorization):
            return self._deny(
                "DENY_AUTHORIZATION", context=context, program_rule=request.program_rule
            )
        if not isinstance(context.testing_policy, TestingPolicy):
            return self._deny("DENY_PROGRAM_INVALID_POLICY", context=context)
        if (
            context.testing_policy.social_engineering_allowed is not False
            or context.testing_policy.denial_of_service_allowed is not False
        ):
            return self._deny("DENY_PROHIBITED", context=context, program_rule=request.program_rule)
        try:
            definition = self.registry.require(request.action_id)
        except RegistryError:
            return self._deny(
                "DENY_UNKNOWN_ACTION", context=context, program_rule=request.program_rule
            )
        if not isinstance(definition, ActionDefinition):
            return self._deny(
                "DENY_UNKNOWN_ACTION", context=context, program_rule=request.program_rule
            )
        try:
            definition.validate()
        except ValueError:
            return self._deny(
                "DENY_INVALID_ACTION_DEFINITION", context=context, program_rule=request.program_rule
            )
        try:
            risk = request.effective_risk(definition)
        except (TypeError, ValueError):
            return self._deny("DENY_INVALID_REQUEST", context=context)
        if not isinstance(risk, RiskLevel):
            return self._deny("DENY_INVALID_REQUEST", context=context)
        # L3 is no longer blanket-denied.  The operator is responsible.
        # It flows through to the profile/capability gate where it requires
        # confirmed authorization and every exact capability flag set True.
        if risk is RiskLevel.L3:
            if not context.authorization.confirmed:
                return self._deny(
                    "DENY_AUTHORIZATION_UNCONFIRMED", risk, context=context, program_rule=request.program_rule
                )
        scope_rule: str | None = None
        if definition.network_access:
            scope_decision, scope_rule = self._scope_decision(request, context, risk)
            if scope_decision is not None:
                return scope_decision
        program_denial = self._program_denial(
            definition, request, context, risk, now, scope_rule=scope_rule
        )
        if program_denial is not None:
            return program_denial
        rate_denial = self._rate_and_concurrency_denial(
            definition, request, context, risk, scope_rule=scope_rule
        )
        if rate_denial is not None:
            return rate_denial
        if risk is RiskLevel.L1 and not definition.low_impact_allowlisted:
            return self._deny(
                "DENY_L1_NOT_ALLOWLISTED",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if risk < RiskLevel.L2:
            return PolicyDecision.allow(
                risk,
                context.policy_digest,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        return PolicyDecision(
            DecisionKind.REQUIRES_APPROVAL,
            risk,
            "REQUIRES_APPROVAL",
            "Human approval is required immediately before this action.",
            scope_rule,
            request.program_rule,
            context.policy_digest,
        )

    def _approval_decision(
        self,
        definition: ActionDefinition,
        request: ActionRequest,
        context: PolicyContext,
        preflight: PolicyDecision,
        *,
        grant: object | None,
        now: datetime | None,
    ) -> PolicyDecision:
        from hackbot.risk.approvals import ApprovalError, build_challenge

        if now is None:
            return self._deny(
                "DENY_APPROVAL_INVALID_CLOCK",
                preflight.effective_risk,
                context=context,
                scope_rule=preflight.scope_rule,
                program_rule=request.program_rule,
            )
        decision_at = now
        if grant is None:
            try:
                challenge = build_challenge(
                    definition,
                    request,
                    context,
                    now=decision_at,
                )
            except ApprovalError as error:
                return self._approval_error(
                    error,
                    preflight.effective_risk,
                    context=context,
                    scope_rule=preflight.scope_rule,
                    program_rule=request.program_rule,
                )
            return PolicyDecision(
                DecisionKind.REQUIRES_APPROVAL,
                preflight.effective_risk,
                "REQUIRES_APPROVAL",
                "Human approval is required immediately before this action.",
                preflight.scope_rule,
                request.program_rule,
                context.policy_digest,
                challenge,
            )
        if not isinstance(grant, ApprovalGrant):
            return self._deny(
                "DENY_APPROVAL_MISMATCH",
                preflight.effective_risk,
                context=context,
                scope_rule=preflight.scope_rule,
                program_rule=request.program_rule,
            )
        store = self.approval_store
        if store is None:
            return self._deny(
                "DENY_APPROVAL_STORE_UNAVAILABLE",
                preflight.effective_risk,
                context=context,
                scope_rule=preflight.scope_rule,
                program_rule=request.program_rule,
            )
        try:
            challenge = store.challenge_for_grant(
                grant,
                definition,
                request,
                context,
                now=decision_at,
            )
            store.consume(grant, challenge, now=decision_at)
        except ApprovalError as error:
            return self._approval_error(
                error,
                preflight.effective_risk,
                context=context,
                scope_rule=preflight.scope_rule,
                program_rule=request.program_rule,
            )
        return PolicyDecision.allow(
            preflight.effective_risk,
            context.policy_digest,
            scope_rule=preflight.scope_rule,
            program_rule=request.program_rule,
        )

    @staticmethod
    def _approval_error(
        error: Exception,
        risk: RiskLevel,
        *,
        context: PolicyContext,
        scope_rule: str | None,
        program_rule: str | None,
    ) -> PolicyDecision:
        code = getattr(error, "code", "")
        reason_code = (
            f"DENY_{code}"
            if isinstance(code, str) and re.fullmatch(r"APPROVAL_[A-Z0-9_]+", code)
            else "DENY_APPROVAL_ERROR"
        )
        return RiskEngine._deny(
            reason_code,
            risk,
            context=context,
            scope_rule=scope_rule,
            program_rule=program_rule,
        )

    @staticmethod
    def _confirmed_authorization(authorization: object) -> bool:
        if not isinstance(authorization, AuthorizationState) or authorization.confirmed is not True:
            return False
        timestamp = authorization.confirmation_timestamp
        confirmed_by = authorization.confirmed_by
        try:
            timestamp_is_utc = (
                isinstance(timestamp, datetime)
                and timestamp.tzinfo is not None
                and timestamp.utcoffset() == timedelta(0)
            )
        except (OverflowError, TypeError, ValueError):
            return False
        return (
            timestamp_is_utc
            and isinstance(confirmed_by, str)
            and bool(confirmed_by.strip())
            and len(confirmed_by) <= _IDENTIFIER_LIMIT
            and not any(0xD800 <= ord(character) <= 0xDFFF for character in confirmed_by)
        )

    def _scope_decision(
        self,
        request: ActionRequest,
        context: PolicyContext,
        risk: RiskLevel,
    ) -> tuple[PolicyDecision | None, str | None]:
        try:
            decision = context.scope.check(request.target)
        except (TypeError, UnicodeError, ValueError):
            return (
                self._deny("DENY_SCOPE", risk, context=context, program_rule=request.program_rule),
                None,
            )
        scope_rule = getattr(decision, "matched_rule", None)
        if not isinstance(scope_rule, str):
            scope_rule = None
        if getattr(decision, "allowed", False) is not True:
            return (
                self._deny(
                    "DENY_SCOPE",
                    risk,
                    context=context,
                    scope_rule=scope_rule,
                    program_rule=request.program_rule,
                ),
                None,
            )
        return None, scope_rule

    def _program_denial(
        self,
        definition: ActionDefinition,
        request: ActionRequest,
        context: PolicyContext,
        risk: RiskLevel,
        now: datetime | None,
        *,
        scope_rule: str | None,
    ) -> PolicyDecision | None:
        policy = context.testing_policy
        if (
            definition.required_profile is not None
            and definition.required_profile != context.active_profile
        ):
            return self._deny(
                "DENY_PROGRAM_PROFILE",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        names = self._policy_names(policy)
        if names is None:
            return self._deny(
                "DENY_PROGRAM_INVALID_POLICY",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        (
            prohibited_tools,
            prohibited_types,
            excluded_impacts,
            required_headers,
            source_ip_requirements,
        ) = names
        if source_ip_requirements:
            return self._deny(
                "DENY_PROGRAM_SOURCE_IP_UNVERIFIED",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        permission_denial = self._permission_denial(definition, policy)
        if permission_denial is not None:
            return self._deny(
                permission_denial,
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if definition.action_id in prohibited_tools:
            return self._deny(
                "DENY_PROGRAM_PROHIBITED_TOOL",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if definition.uses_external_tool and self._tool_is_prohibited(definition, prohibited_tools):
            return self._deny(
                "DENY_PROGRAM_PROHIBITED_TOOL",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        executable_denial = self._executable_request_denial(definition, request)
        if executable_denial is not None:
            return self._deny(
                executable_denial,
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        vulnerability_denial = self._classification_denial(
            definition.vulnerability_types,
            prohibited_types,
            "DENY_PROGRAM_VULNERABILITY_TYPE_UNSPECIFIED",
            "DENY_PROGRAM_PROHIBITED_VULNERABILITY_TYPE",
        )
        if vulnerability_denial is not None:
            return self._deny(
                vulnerability_denial,
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        impact_denial = self._classification_denial(
            definition.impacts,
            excluded_impacts,
            "DENY_PROGRAM_IMPACT_UNSPECIFIED",
            "DENY_PROGRAM_EXCLUDED_IMPACT",
        )
        if impact_denial is not None:
            return self._deny(
                impact_denial,
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        restricted_hours_denial = self._restricted_hours_denial(policy, now)
        if restricted_hours_denial is not None:
            return self._deny(
                restricted_hours_denial,
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if required_headers and not definition.honors_required_headers:
            return self._deny(
                "DENY_PROGRAM_REQUIRED_HEADERS_UNSUPPORTED",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        return None

    @staticmethod
    def _tool_is_prohibited(
        definition: ActionDefinition,
        prohibited_tools: frozenset[str],
    ) -> bool:
        if not prohibited_tools:
            return False
        identities: set[str] = set()
        if definition.tool_id is not None:
            identities.add(definition.tool_id)
        if definition.executable is not None:
            identities.update(
                {
                    definition.executable,
                    PurePath(definition.executable).name.lower(),
                    PureWindowsPath(definition.executable).name.lower(),
                }
            )
        return not identities.isdisjoint(prohibited_tools)

    @staticmethod
    def _executable_request_denial(
        definition: ActionDefinition, request: ActionRequest
    ) -> str | None:
        if not definition.uses_external_tool:
            return "DENY_NO_TOOL_ARGV" if request.argv else None
        if not request.argv or request.argv[0] != definition.executable:
            return "DENY_EXECUTABLE_MISMATCH"
        expected = definition.render_argv(request)
        if expected is None or request.argv != expected:
            return "DENY_ARGV_TEMPLATE_MISMATCH"
        return None

    @staticmethod
    def _permission_denial(definition: ActionDefinition, policy: TestingPolicy) -> str | None:
        permissions = (
            ("automated", "automated_scanning_allowed", "DENY_PROGRAM_AUTOMATED_NOT_ALLOWED"),
            (
                "authenticated",
                "authenticated_testing_allowed",
                "DENY_PROGRAM_AUTHENTICATED_NOT_ALLOWED",
            ),
            (
                "creates_account",
                "account_creation_allowed",
                "DENY_PROGRAM_ACCOUNT_CREATION_NOT_ALLOWED",
            ),
            (
                "uses_multiple_accounts",
                "multiple_accounts_allowed",
                "DENY_PROGRAM_MULTIPLE_ACCOUNTS_NOT_ALLOWED",
            ),
            ("out_of_band", "out_of_band_testing_allowed", "DENY_PROGRAM_OUT_OF_BAND_NOT_ALLOWED"),
        )
        for characteristic, setting, reason_code in permissions:
            allowed = getattr(policy, setting)
            if type(allowed) is not bool:
                return "DENY_PROGRAM_INVALID_POLICY"
            if getattr(definition, characteristic) and not allowed:
                return reason_code
        return None

    @staticmethod
    def _policy_names(
        policy: TestingPolicy,
    ) -> (
        tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str], frozenset[str]] | None
    ):
        collections = (
            policy.prohibited_tools,
            policy.prohibited_vulnerability_types,
            policy.excluded_impacts,
            policy.required_headers,
            policy.source_ip_requirements,
        )
        if any(not isinstance(values, tuple) for values in collections):
            return None
        if any(
            not isinstance(value, str) or not value or value != value.strip().lower()
            for values in collections
            for value in values
        ):
            return None
        try:
            prohibited_tools = frozenset(
                canonical_tool_identity(value, name="prohibited_tools")
                for value in policy.prohibited_tools
            )
        except ValueError:
            return None
        return (
            prohibited_tools,
            frozenset(policy.prohibited_vulnerability_types),
            frozenset(policy.excluded_impacts),
            frozenset(policy.required_headers),
            frozenset(policy.source_ip_requirements),
        )

    @staticmethod
    def _classification_denial(
        classifications: tuple[str, ...],
        prohibited: Collection[str],
        missing_code: str,
        prohibited_code: str,
    ) -> str | None:
        if not prohibited:
            return None
        if not classifications:
            return missing_code
        return prohibited_code if not set(classifications).isdisjoint(prohibited) else None

    @staticmethod
    def _restricted_hours_denial(policy: TestingPolicy, now: datetime | None) -> str | None:
        if not isinstance(policy.restricted_hours, tuple):
            return "DENY_PROGRAM_RESTRICTED_HOURS_INVALID"
        if not policy.restricted_hours:
            return (
                None
                if policy.restricted_hours_timezone is None
                else "DENY_PROGRAM_RESTRICTED_HOURS_INVALID"
            )
        if not isinstance(now, datetime) or now.tzinfo is None:
            return "DENY_PROGRAM_INVALID_CLOCK"
        try:
            if now.utcoffset() != timedelta(0):
                return "DENY_PROGRAM_INVALID_CLOCK"
        except (OverflowError, TypeError, ValueError):
            return "DENY_PROGRAM_INVALID_CLOCK"
        timezone = policy.restricted_hours_timezone
        if not isinstance(timezone, str) or not timezone:
            return "DENY_PROGRAM_RESTRICTED_HOURS_INVALID"
        try:
            local_now = now.astimezone(ZoneInfo(timezone))
        except (OverflowError, ValueError, ZoneInfoNotFoundError):
            return "DENY_PROGRAM_RESTRICTED_HOURS_INVALID"
        current = local_now.hour * 60 + local_now.minute
        for window in policy.restricted_hours:
            if not isinstance(window, str):
                return "DENY_PROGRAM_RESTRICTED_HOURS_INVALID"
            match = _HOUR_WINDOW.fullmatch(window)
            if match is None:
                return "DENY_PROGRAM_RESTRICTED_HOURS_INVALID"
            start = int(match["start_hour"]) * 60 + int(match["start_minute"])
            end = int(match["end_hour"]) * 60 + int(match["end_minute"])
            if start >= end:
                return "DENY_PROGRAM_RESTRICTED_HOURS_INVALID"
            if start <= current < end:
                return "DENY_PROGRAM_RESTRICTED_HOURS"
        return None

    @staticmethod
    def _rate_and_concurrency_denial(
        definition: ActionDefinition,
        request: ActionRequest,
        context: PolicyContext,
        risk: RiskLevel,
        *,
        scope_rule: str | None,
    ) -> PolicyDecision | None:
        policy = context.testing_policy
        active_or_network = definition.network_access or risk >= RiskLevel.L1
        if (
            isinstance(policy.max_requests_per_second, bool)
            or not isinstance(policy.max_requests_per_second, int)
            or not 1 <= policy.max_requests_per_second <= 1_000
        ):
            return RiskEngine._deny(
                "DENY_PROGRAM_INVALID_POLICY",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if (
            isinstance(policy.concurrency, bool)
            or not isinstance(policy.concurrency, int)
            or not 1 <= policy.concurrency <= 100
        ):
            return RiskEngine._deny(
                "DENY_PROGRAM_INVALID_POLICY",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if active_or_network and request.rate is None:
            return RiskEngine._deny(
                "DENY_RATE",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if active_or_network and request.concurrency is None:
            return RiskEngine._deny(
                "DENY_CONCURRENCY",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if request.rate is not None and (
            isinstance(request.rate, bool)
            or not isinstance(request.rate, int)
            or not 1 <= request.rate <= 1_000
        ):
            return RiskEngine._deny(
                "DENY_RATE",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if request.concurrency is not None and (
            isinstance(request.concurrency, bool)
            or not isinstance(request.concurrency, int)
            or not 1 <= request.concurrency <= 100
        ):
            return RiskEngine._deny(
                "DENY_CONCURRENCY",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if request.rate is not None and request.rate > policy.max_requests_per_second:
            return RiskEngine._deny(
                "DENY_RATE",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        if request.concurrency is not None and request.concurrency > policy.concurrency:
            return RiskEngine._deny(
                "DENY_CONCURRENCY",
                risk,
                context=context,
                scope_rule=scope_rule,
                program_rule=request.program_rule,
            )
        return None

    @staticmethod
    def _deny(
        reason_code: str,
        risk: RiskLevel = RiskLevel.L0,
        *,
        context: PolicyContext,
        scope_rule: str | None = None,
        program_rule: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision.deny(
            reason_code,
            risk,
            scope_rule=scope_rule,
            program_rule=program_rule,
            policy_digest=context.policy_digest,
        )
