"""Non-executing CLI wiring for the risk gate and L2 approval lifecycle.

This module contains no policy logic: it strictly parses a local request file,
loads the validated engagement context, drives the pure ``RiskEngine`` against a
small immutable fixture registry, and persists an L2 pending challenge through
the descriptor-owned ``ApprovalStore``. It never executes an action, opens a
socket, contacts a provider or target, or reads a secret. Confirmation authority
lives only in ``hackbot.cli.main._read_approval_from_tty`` (interactive TTY).

Stable exit codes (shared with ``main``):

* ``0`` — allow, successful grant, or a reported status;
* ``1`` — policy/approval deny or a persistence failure;
* ``2`` — invalid local request/context/digest or a missing ``config`` extra;
* ``3`` — interactive TTY unavailable or confirmation mismatch;
* ``4`` — a valid L2 action was persisted as pending.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - type-only imports keep --help stdlib-only
    from hackbot.risk.models import ActionRequest, PolicyContext

EXIT_ALLOW = 0
EXIT_DENY = 1
EXIT_INVALID = 2
EXIT_APPROVAL_UNAVAILABLE = 3
EXIT_REQUIRES_APPROVAL = 4

_MAX_REQUEST_BYTES = 64 * 1024
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_KEYS = frozenset(
    {
        "action_id",
        "target",
        "argv",
        "hypothesis_id",
        "rationale",
        "rate",
        "concurrency",
        "data_touched",
        "expected_impact",
        "stop_condition",
        "cleanup_plan",
        "program_rule",
        "required_headers",
        "requested_risk",
    }
)


class CliInputError(Exception):
    """Raised for any invalid, unsafe, or oversized local CLI input."""


# --------------------------------------------------------------- parsing ----
def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise CliInputError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_constant(_token: str) -> object:
    raise CliInputError("non-finite JSON constants are not allowed")


def _strict_parse(raw: bytes) -> dict[str, object]:
    if len(raw) > _MAX_REQUEST_BYTES:
        raise CliInputError("request file exceeds the 64 KiB limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise CliInputError("request file must be UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except CliInputError:
        raise
    except RecursionError as exc:
        raise CliInputError("request file is too deeply nested") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise CliInputError("request file is not valid JSON") from exc
    if not isinstance(value, dict):
        raise CliInputError("request must be a JSON object")
    return value


def _check_keys(value: dict[str, object]) -> None:
    for key in value:
        if key not in _REQUEST_KEYS:
            raise CliInputError(f"unknown field {key!r}")
    for key in _REQUEST_KEYS:
        if key not in value:
            raise CliInputError(f"missing field {key!r}")


def _build_request(value: dict[str, object], context: PolicyContext) -> ActionRequest:
    from hackbot.risk.models import ActionRequest, RiskLevel

    requested_risk = value["requested_risk"]
    if requested_risk is not None:
        if (
            isinstance(requested_risk, bool)
            or not isinstance(requested_risk, int)
            or requested_risk not in (0, 1, 2, 3)
        ):
            raise CliInputError("requested_risk must be an integer 0..3 or null")
        requested_risk = RiskLevel(requested_risk)
    argv = value["argv"]
    if not isinstance(argv, list):
        raise CliInputError("argv must be a list of strings")
    headers = value["required_headers"]
    if not isinstance(headers, list):
        raise CliInputError("required_headers must be a list of strings")
    try:
        return ActionRequest(
            engagement_id=context.engagement_id,
            engagement_path=context.engagement_path,
            action_id=value["action_id"],  # type: ignore[arg-type]
            target=value["target"],  # type: ignore[arg-type]
            argv=tuple(argv),
            hypothesis_id=value["hypothesis_id"],  # type: ignore[arg-type]
            rationale=value["rationale"],  # type: ignore[arg-type]
            rate=value["rate"],  # type: ignore[arg-type]
            concurrency=value["concurrency"],  # type: ignore[arg-type]
            data_touched=value["data_touched"],  # type: ignore[arg-type]
            expected_impact=value["expected_impact"],  # type: ignore[arg-type]
            stop_condition=value["stop_condition"],  # type: ignore[arg-type]
            cleanup_plan=value["cleanup_plan"],  # type: ignore[arg-type]
            program_rule=value["program_rule"],  # type: ignore[arg-type]
            required_headers=tuple(headers),
            requested_risk=requested_risk,
        )
    except (ValueError, TypeError) as exc:
        raise CliInputError(f"invalid request field: {exc}") from exc


# ------------------------------------------------------------ loading -------
def _load_context(engagement: str) -> PolicyContext:
    from hackbot.programs.schema import ValidationError
    from hackbot.risk.context import ContextError, load_policy_context

    try:
        return load_policy_context(engagement)
    except (ContextError, ValidationError) as exc:
        raise CliInputError(f"engagement context is invalid: {exc}") from exc


def _emit(payload: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for key, item in payload.items():
            print(f"{key}: {item}")


# ------------------------------------------------------------ commands ------
def cmd_evaluate(engagement: str, request_path: str, *, as_json: bool) -> int:
    try:
        context = _load_context(engagement)
    except CliInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    try:
        raw = Path(request_path).read_bytes()
    except OSError as exc:
        print(f"error: cannot read request file: {exc}", file=sys.stderr)
        return EXIT_INVALID
    try:
        value = _strict_parse(raw)
        _check_keys(value)
        request = _build_request(value, context)
    except CliInputError as exc:
        print(f"invalid request: {exc}", file=sys.stderr)
        return EXIT_INVALID

    from hackbot.risk.fixtures import FIXTURE_ACTIONS
    from hackbot.risk.models import DecisionKind
    from hackbot.risk.policy import RiskEngine

    now = datetime.now(UTC)
    engine = RiskEngine(FIXTURE_ACTIONS)
    decision = engine.evaluate(request, context, now=now)

    if decision.kind is DecisionKind.ALLOW:
        _emit(
            {
                "decision": decision.kind.value,
                "reason_code": decision.reason_code,
                "effective_risk": decision.effective_risk.name,
                "policy_digest": decision.policy_digest,
            },
            as_json=as_json,
        )
        return EXIT_ALLOW

    if decision.kind is DecisionKind.DENY:
        _emit(
            {
                "decision": decision.kind.value,
                "reason_code": decision.reason_code,
                "effective_risk": decision.effective_risk.name,
            },
            as_json=as_json,
        )
        return EXIT_DENY

    # REQUIRES_APPROVAL: persist a pending challenge bound to this exact action.
    return _persist_pending(engagement, request, context, decision, now, as_json=as_json)


def _persist_pending(
    engagement: str,
    request: ActionRequest,
    context: PolicyContext,
    decision: object,
    now: datetime,
    *,
    as_json: bool,
) -> int:
    from hackbot.risk.approvals import ApprovalError, ApprovalStore
    from hackbot.risk.fixtures import FIXTURE_ACTIONS

    challenge = getattr(decision, "challenge", None)
    if challenge is None:
        print("error: approval challenge could not be built", file=sys.stderr)
        return EXIT_DENY
    definition = FIXTURE_ACTIONS.require(request.action_id)
    try:
        store = ApprovalStore(engagement)
    except ApprovalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    approval_status = "pending"
    try:
        try:
            store.create_pending(definition, request, context, now=now, nonce=challenge.nonce)
        except ApprovalError as exc:
            if exc.code == "APPROVAL_EXISTS":
                # A record for this exact digest already exists (only reachable on
                # a digest collision, since the digest binds created_at + a random
                # nonce). Report its true stored state rather than assuming pending.
                approval_status = store.status(challenge.challenge_digest)
            else:
                print(f"error: could not persist approval request: {exc}", file=sys.stderr)
                return EXIT_DENY
    finally:
        store.close()
    _emit(
        {
            "decision": "requires-approval",
            "reason_code": decision.reason_code,  # type: ignore[attr-defined]
            "effective_risk": decision.effective_risk.name,  # type: ignore[attr-defined]
            "challenge_id": challenge.challenge_digest,
            "approval_status": approval_status,
        },
        as_json=as_json,
    )
    return EXIT_REQUIRES_APPROVAL


class GrantAborted(Exception):
    """Raised inside the interactive grant flow with a stable CLI exit code."""

    def __init__(self, exit_code: int, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


def interactive_grant(engagement, store, registry, challenge_id, *, context):
    """Reconstruct the pending challenge, confirm at the TTY, and grant it once.

    Returns ``(grant, fresh_context)`` — the grant and the reloaded context it was
    created under, so the caller executes against the same context. Raises
    :class:`GrantAborted` with a stable CLI exit code on any failure.
    """
    from hackbot.cli import main as cli_main
    from hackbot.risk.approvals import ApprovalError

    try:
        challenge = store.challenge_for_pending(
            challenge_id, registry, context, now=datetime.now(UTC)
        )
    except ApprovalError as exc:
        raise GrantAborted(EXIT_DENY, f"error: {exc}") from exc

    # Interactive confirmation authority lives only at the TTY.
    try:
        cli_main._read_approval_from_tty(challenge)
    except OSError as exc:
        raise GrantAborted(EXIT_APPROVAL_UNAVAILABLE, str(exc)) from exc

    # Reload and reconstruct after the prompt: deny if anything changed.
    try:
        fresh_context = _load_context(engagement)
    except CliInputError as exc:
        raise GrantAborted(EXIT_INVALID, f"error: {exc}") from exc
    granted_at = datetime.now(UTC)
    try:
        confirmed = store.challenge_for_pending(
            challenge_id, registry, fresh_context, now=granted_at
        )
    except ApprovalError as exc:
        raise GrantAborted(EXIT_DENY, f"error: {exc}") from exc
    if confirmed.challenge_digest != challenge.challenge_digest:
        raise GrantAborted(EXIT_DENY, "error: approval changed during confirmation")
    approved_by = fresh_context.authorization.confirmed_by
    if not approved_by:
        raise GrantAborted(EXIT_DENY, "error: engagement authorization actor is missing")
    try:
        grant = store.grant(confirmed, approved_by=approved_by, now=granted_at)
    except ApprovalError as exc:
        raise GrantAborted(EXIT_DENY, f"error: could not grant approval: {exc}") from exc
    return grant, fresh_context


def cmd_grant(engagement: str, challenge_id: str, *, as_json: bool) -> int:
    if _DIGEST_RE.fullmatch(challenge_id) is None:
        print("error: challenge id must be a 64-character hex digest", file=sys.stderr)
        return EXIT_INVALID
    try:
        context = _load_context(engagement)
    except CliInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID

    from hackbot.risk.approvals import ApprovalError, ApprovalStore
    from hackbot.risk.fixtures import FIXTURE_ACTIONS

    try:
        store = ApprovalStore(engagement)
    except ApprovalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    try:
        try:
            grant, _fresh = interactive_grant(
                engagement, store, FIXTURE_ACTIONS, challenge_id, context=context
            )
        except GrantAborted as exc:
            print(exc.message, file=sys.stderr)
            return exc.exit_code
    finally:
        store.close()
    _emit(
        {
            "challenge_id": challenge_id,
            "approval_status": "granted",
            "approved_by": grant.approved_by,
        },
        as_json=as_json,
    )
    return EXIT_ALLOW


def cmd_status(engagement: str, challenge_id: str, *, as_json: bool) -> int:
    if _DIGEST_RE.fullmatch(challenge_id) is None:
        print(
            "error: challenge id must be a 64-character hex digest",
            file=sys.stderr,
        )
        return EXIT_INVALID
    from hackbot.risk.approvals import ApprovalError, ApprovalStore

    try:
        store = ApprovalStore(engagement)
    except ApprovalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    try:
        stored_state = store.status(challenge_id)
    except ApprovalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    finally:
        store.close()
    _emit(
        {"challenge_id": challenge_id, "stored_state": stored_state},
        as_json=as_json,
    )
    return EXIT_ALLOW
