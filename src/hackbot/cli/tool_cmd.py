"""Non-executing-by-default CLI wiring for gated tool runs.

`hackbot tool run` evaluates a code-owned action against the risk gate and
executes it **only** on an ALLOW. Raw tool output is never printed by default;
only the decision, exit status, sizes, and a stdout digest are reported.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from hackbot.cli.risk_cmd import (
    CliInputError,
    _build_request,
    _check_keys,
    _load_context,
    _strict_parse,
)

EXIT_OK = 0
EXIT_DENY = 1
EXIT_INVALID = 2
EXIT_REQUIRES_APPROVAL = 4


def _emit(payload: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for key, item in payload.items():
            print(f"{key}: {item}")


def _make_runner(engagement: str, name: str):
    from hackbot.tools.runner import CommandRunner

    if name == "local":
        return CommandRunner()
    if name == "remote":
        from hackbot.tools.remote import RemoteError, RemoteRunner, load_remote_config

        try:
            config = load_remote_config(str(Path(engagement) / "runner.json"))
            return RemoteRunner(config)
        except RemoteError as exc:
            raise CliInputError(f"remote runner config: {exc}") from exc
    raise CliInputError(f"unknown runner: {name}")


def cmd_run(
    engagement: str,
    action_id: str,
    request_path: str,
    *,
    as_json: bool,
    approve: bool = False,
    runner: str = "local",
) -> int:
    from hackbot.audit.tool_runs import AuditError, AuditSink
    from hackbot.cli.risk_cmd import GrantAborted, interactive_grant
    from hackbot.evidence.store import EvidenceError, EvidenceStore
    from hackbot.risk.approvals import ApprovalError, ApprovalStore
    from hackbot.risk.models import DecisionKind
    from hackbot.risk.registry import ActionRegistry, RegistryError
    from hackbot.tools.actions import REAL_ACTIONS
    from hackbot.tools.adapter import run_action
    from hackbot.tools.runner import RunnerError

    try:
        definition = REAL_ACTIONS.require(action_id)
    except RegistryError:
        print(f"error: unknown or unavailable action: {action_id}", file=sys.stderr)
        return EXIT_INVALID
    try:
        context = _load_context(engagement)
    except CliInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    try:
        raw = Path(request_path).read_bytes()
        value = _strict_parse(raw)
        _check_keys(value)
        request = _build_request(value, context)
    except (CliInputError, OSError) as exc:
        print(f"invalid request: {exc}", file=sys.stderr)
        return EXIT_INVALID
    if request.action_id != action_id:
        print("error: request action_id does not match the command", file=sys.stderr)
        return EXIT_INVALID

    try:
        tool_runner = _make_runner(engagement, runner)
    except CliInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    audit = AuditSink(engagement)
    evidence = EvidenceStore(engagement)
    try:
        store = ApprovalStore(engagement)
    except ApprovalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID

    challenge_id: str | None = None
    now = datetime.now(UTC)
    try:
        try:
            outcome = run_action(
                definition,
                request,
                context,
                now=now,
                runner=tool_runner,
                audit=audit,
                evidence=evidence,
                approval_store=store,
            )
        except (RunnerError, AuditError, EvidenceError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INVALID

        if outcome.decision.kind is DecisionKind.REQUIRES_APPROVAL:
            challenge = outcome.decision.challenge
            if challenge is None:
                print("error: approval challenge could not be built", file=sys.stderr)
                return EXIT_DENY
            try:
                store.create_pending(definition, request, context, now=now, nonce=challenge.nonce)
            except ApprovalError as exc:
                if exc.code != "APPROVAL_EXISTS":
                    print(f"error: could not persist approval request: {exc}", file=sys.stderr)
                    return EXIT_DENY
            challenge_id = challenge.challenge_digest
            if not approve:
                _emit(
                    {
                        "action_id": action_id,
                        "decision": "requires-approval",
                        "reason_code": outcome.decision.reason_code,
                        "executed": False,
                        "challenge_id": challenge_id,
                        "approval_status": "pending",
                        "evidence_run_id": None,
                    },
                    as_json=as_json,
                )
                return EXIT_REQUIRES_APPROVAL
            try:
                grant, fresh_context = interactive_grant(
                    engagement, store, ActionRegistry([definition]), challenge_id, context=context
                )
            except GrantAborted as exc:
                print(exc.message, file=sys.stderr)
                return exc.exit_code
            try:
                outcome = run_action(
                    definition,
                    request,
                    fresh_context,
                    grant=grant,
                    now=datetime.now(UTC),
                    runner=tool_runner,
                    audit=audit,
                    evidence=evidence,
                    approval_store=store,
                )
            except (RunnerError, AuditError, EvidenceError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return EXIT_INVALID
    finally:
        store.close()

    result = outcome.command_result
    _emit(
        {
            "action_id": action_id,
            "decision": outcome.decision.kind.value,
            "reason_code": outcome.decision.reason_code,
            "executed": outcome.executed,
            "exit_code": result.exit_code if result else None,
            "timed_out": result.timed_out if result else None,
            "truncated": result.truncated if result else None,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest() if result else None,
            "stdout_bytes": len(result.stdout) if result else None,
            "evidence_run_id": outcome.evidence_run_id,
            "challenge_id": challenge_id,
        },
        as_json=as_json,
    )
    if outcome.decision.kind is DecisionKind.DENY:
        return EXIT_DENY
    if result is None or result.exit_code != 0 or result.timed_out:
        return EXIT_DENY
    return EXIT_OK
