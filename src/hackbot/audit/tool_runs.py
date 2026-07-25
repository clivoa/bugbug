"""Append-only, secret-free audit trail for tool executions.

One compact JSON line per ``run_action`` outcome under
``<engagement>/audit/tool-runs.jsonl`` (dir ``0700``, file ``0600``). Records
carry digests and sizes, never raw tool output, and are scanned for secrets by
the approval store's scanner before they are written.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from hackbot.risk.approvals import ApprovalError, _reject_secrets
from hackbot.risk.models import RiskLevel
from hackbot.tools.runner import CommandResult


class AuditError(Exception):
    """Raised when an audit record cannot be written safely."""


class AuditSink:
    def __init__(self, engagement_dir: str | Path) -> None:
        self._dir = Path(engagement_dir) / "audit"
        self._path = self._dir / "tool-runs.jsonl"

    def record_run(
        self,
        *,
        action_id: str,
        effective_risk: RiskLevel,
        target: str,
        argv: Sequence[str],
        decision_kind: str,
        reason_code: str,
        result: CommandResult | None,
        now: datetime,
    ) -> None:
        record: dict[str, object] = {
            "timestamp": now.astimezone().isoformat(),
            "action_id": action_id,
            "effective_risk": int(effective_risk),
            "target": target,
            "argv": list(argv),
            "decision": decision_kind,
            "reason_code": reason_code,
            "exit_code": result.exit_code if result else None,
            "timed_out": result.timed_out if result else None,
            "truncated": result.truncated if result else None,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest() if result else None,
            "stdout_bytes": len(result.stdout) if result else None,
            "stderr_bytes": len(result.stderr) if result else None,
            "duration_ms": result.duration_ms if result else None,
        }
        try:
            _reject_secrets(record)
        except ApprovalError as exc:
            raise AuditError("refusing to write a secret-bearing audit record") from exc
        line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        self._dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self._dir, 0o700)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
