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


def cmd_run(engagement: str, action_id: str, request_path: str, *, as_json: bool) -> int:
    from hackbot.audit.tool_runs import AuditError, AuditSink
    from hackbot.risk.models import DecisionKind
    from hackbot.risk.registry import RegistryError
    from hackbot.tools.actions import REAL_ACTIONS
    from hackbot.tools.adapter import run_action
    from hackbot.tools.runner import CommandRunner, RunnerError

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
        outcome = run_action(
            definition,
            request,
            context,
            now=datetime.now(UTC),
            runner=CommandRunner(),
            audit=AuditSink(engagement),
        )
    except (RunnerError, AuditError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
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
        },
        as_json=as_json,
    )
    if outcome.decision.kind is DecisionKind.REQUIRES_APPROVAL:
        return EXIT_REQUIRES_APPROVAL
    if outcome.decision.kind is DecisionKind.DENY:
        return EXIT_DENY
    if result is None or result.exit_code != 0 or result.timed_out:
        return EXIT_DENY
    return EXIT_OK
