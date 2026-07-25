"""Redacted, run-linked evidence for executed actions.

Writes redacted stdout/stderr plus a secret-scanned meta.json under
``<engagement>/evidence/<run_id>/`` (dir 0700, files 0600). Raw output is never
stored. meta.json is scanned before any file is written, so a rejection persists
nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from hackbot.evidence.redact import redact_bytes
from hackbot.risk.approvals import ApprovalError, _reject_secrets
from hackbot.risk.models import ActionRequest
from hackbot.tools.runner import CommandResult


class EvidenceError(Exception):
    """Raised when evidence cannot be persisted safely."""


class EvidenceStore:
    def __init__(self, engagement_dir: str | Path) -> None:
        self._root = Path(engagement_dir) / "evidence"

    def record(
        self,
        *,
        action_id: str,
        request: ActionRequest,
        result: CommandResult,
        decision_kind: str,
        reason_code: str,
        now: datetime,
    ) -> str:
        stdout = redact_bytes(result.stdout)
        stderr = redact_bytes(result.stderr)
        stdout_sha256 = hashlib.sha256(stdout).hexdigest()
        run_id = f"{now.astimezone(UTC):%Y%m%dT%H%M%SZ}-{stdout_sha256[:12]}"
        meta: dict[str, object] = {
            "run_id": run_id,
            "timestamp": now.astimezone(UTC).isoformat(),
            "action_id": action_id,
            "target": request.target,
            "argv": list(request.argv),
            "hypothesis_id": request.hypothesis_id,
            "rationale": request.rationale,
            "expected_impact": request.expected_impact,
            "decision": decision_kind,
            "reason_code": reason_code,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "truncated": result.truncated,
            "stdout_sha256": stdout_sha256,
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
        }
        try:
            _reject_secrets(meta)
        except ApprovalError as exc:
            raise EvidenceError("refusing to store secret-bearing evidence metadata") from exc
        run_dir = self._root / run_id
        try:
            self._root.mkdir(mode=0o700, exist_ok=True)
            os.chmod(self._root, 0o700)
            run_dir.mkdir(mode=0o700, exist_ok=True)
            os.chmod(run_dir, 0o700)
            self._write(run_dir / "stdout", stdout)
            self._write(run_dir / "stderr", stderr)
            self._write(
                run_dir / "meta.json",
                (json.dumps(meta, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            )
        except OSError as exc:
            raise EvidenceError(f"could not write evidence: {exc}") from exc
        return run_id

    @staticmethod
    def _write(path: Path, data: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
