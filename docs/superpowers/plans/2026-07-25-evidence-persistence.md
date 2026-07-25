# Evidence Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist the untrusted output of an executed action, redacted of known
secrets, per engagement, linked to the run and its recorded hypothesis —
completing the `context → evaluate → allow → run → evidence` path.

**Architecture:** A best-effort `redact_bytes` over untrusted output, an
`EvidenceStore` that writes redacted `stdout`/`stderr` + a secret-scanned
`meta.json` under `<engagement>/evidence/<run_id>/`, wired into `run_action`
(audit first, evidence second) and reported by `hackbot tool run`.

**Tech Stack:** Python 3.11+ standard library (`hashlib`, `json`, `os`, `re`,
`pathlib`, `datetime`), the existing `hackbot.risk` secret patterns, pytest,
Ruff, mypy.

## Global Constraints

- Core package stays standard-library only.
- Evidence is stored **redacted, never raw**; raw output is never printed.
- Redaction is best-effort (defense in depth), not a guarantee.
- Audit is written before evidence, so the audit trail exists even if evidence
  capture fails.
- Only executed (post-`ALLOW`) runs capture evidence; deny / requires-approval
  capture none.
- `meta.json` is secret-scanned before any file is written; a rejection persists
  nothing.
- Evidence directories/files are `0700`/`0600` under git-ignored `engagements/**`.
- The reviewed `hackbot.risk` package is not modified.
- Production behavior is written test-first; each test is observed failing for
  the intended reason before implementation.

---

### Task 1: Best-effort secret redactor

**Files:**
- Create: `src/hackbot/evidence/redact.py`
- Create: `tests/evidence/__init__.py`
- Create: `tests/evidence/test_redact.py`

**Interfaces:**
- Consumes: `hackbot.risk.approvals._SECRET_MATERIAL_RE`,
  `_SECRET_ASSIGNMENT_RE`, `_is_secret_name`.
- Produces: `redact_bytes(data: bytes) -> bytes`.

- [ ] **Step 1: Write failing redactor tests**

```python
from hackbot.evidence.redact import redact_bytes


def test_redacts_authorization_and_cookie_headers():
    out = redact_bytes(b"Authorization: Bearer abc.def.ghi\r\nSet-Cookie: s=xyz\r\n")
    assert b"abc.def.ghi" not in out
    assert b"xyz" not in out
    assert b"[REDACTED]" in out


def test_redacts_known_token_shapes():
    assert b"AKIAIOSFODNN7EXAMPLE" not in redact_bytes(b"key AKIAIOSFODNN7EXAMPLE end")
    assert b"[REDACTED]" in redact_bytes(b"jwt eyJab.cdEF12.ghIJ34 end")


def test_redacts_secret_name_assignments_keeping_the_name():
    out = redact_bytes(b"password=hunter2 kept")
    assert b"hunter2" not in out
    assert b"password" in out and b"[REDACTED]" in out


def test_benign_text_is_unchanged():
    body = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nlab-ok"
    assert redact_bytes(body) == body


def test_arbitrary_bytes_are_preserved():
    data = b"\xff\xfe binary \x00 body"
    assert redact_bytes(data) == data
```

- [ ] **Step 2: Run the redactor tests and verify RED**

Run: `.venv/bin/python -m pytest tests/evidence/test_redact.py -q`
Expected: collection fails — `hackbot.evidence.redact` does not exist.

- [ ] **Step 3: Implement redact_bytes**

```python
"""Best-effort secret redaction over untrusted tool output.

Defense in depth, not a guarantee: this replaces known secret shapes (private
keys, Authorization/Cookie headers, JWTs, AKIA…/sk_… tokens, and secret-name
assignments) with a placeholder. It does not remove every possible secret or
PII. Evidence is also never printed and lives only in the git-ignored engagement
directory.
"""

from __future__ import annotations

import re

from hackbot.risk.approvals import (
    _SECRET_ASSIGNMENT_RE,
    _SECRET_MATERIAL_RE,
    _is_secret_name,
)

_PLACEHOLDER = "[REDACTED]"


def _redact_assignment(match: re.Match[str]) -> str:
    if not _is_secret_name(match.group("name")):
        return match.group(0)
    prefix = match.group(0)[: match.start("value") - match.start(0)]
    return prefix + _PLACEHOLDER


def redact_bytes(data: bytes) -> bytes:
    text = data.decode("latin-1")
    text = _SECRET_MATERIAL_RE.sub(_PLACEHOLDER, text)
    text = _SECRET_ASSIGNMENT_RE.sub(_redact_assignment, text)
    return text.encode("latin-1")
```

- [ ] **Step 4: Run the redactor tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/evidence/test_redact.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/evidence/redact.py tests/evidence/__init__.py tests/evidence/test_redact.py
git commit -m "feat: add best-effort evidence redactor"
```

---

### Task 2: Redacted, run-linked EvidenceStore

**Files:**
- Create: `src/hackbot/evidence/store.py`
- Create: `tests/evidence/test_store.py`

**Interfaces:**
- Consumes: `redact_bytes` (Task 1), `CommandResult`
  (`hackbot.tools.runner`), `ActionRequest`, `RiskLevel`
  (`hackbot.risk.models`), `hackbot.risk.approvals._reject_secrets`,
  `ApprovalError`.
- Produces: `EvidenceStore`, `EvidenceError`,
  `EvidenceStore.record(*, action_id, request, result, decision_kind,
  reason_code, now) -> str`.

- [ ] **Step 1: Write failing store tests**

```python
import json
import stat
from datetime import UTC, datetime

import pytest

from hackbot.evidence.store import EvidenceError, EvidenceStore
from hackbot.risk.models import ActionRequest
from hackbot.tools.runner import CommandResult

_NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)


def _request(rationale="Fetch one in-scope lab URL once."):
    return ActionRequest(
        engagement_id="local-lab",
        engagement_path="/tmp/local-lab",
        action_id="net.http-get",
        target="http://127.0.0.1/",
        argv=("/usr/bin/curl", "-sS", "--max-time", "10", "http://127.0.0.1/"),
        hypothesis_id="hyp-1",
        rationale=rationale,
        rate=1,
        concurrency=1,
        data_touched="Public lab response.",
        expected_impact="One GET.",
        stop_condition="Stop on error.",
        cleanup_plan="None.",
        program_rule="Authorized lab fetch.",
        required_headers=(),
        requested_risk=None,
    )


def test_record_writes_redacted_stdout_and_meta(tmp_path):
    store = EvidenceStore(tmp_path)
    result = CommandResult(0, b"Set-Cookie: s=topsecretvalue\r\n\r\nlab-ok", b"", 9, False, False)
    run_id = store.record(
        action_id="net.http-get",
        request=_request(),
        result=result,
        decision_kind="allow",
        reason_code="ALLOW",
        now=_NOW,
    )
    run_dir = tmp_path / "evidence" / run_id
    stdout = (run_dir / "stdout").read_bytes()
    assert b"topsecretvalue" not in stdout and b"lab-ok" in stdout
    meta = json.loads((run_dir / "meta.json").read_text())
    assert meta["action_id"] == "net.http-get"
    assert meta["hypothesis_id"] == "hyp-1"
    assert meta["exit_code"] == 0
    assert stat.S_IMODE((run_dir / "stdout").stat().st_mode) == 0o600
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700


def test_record_rejects_secret_bearing_rationale_and_writes_nothing(tmp_path):
    store = EvidenceStore(tmp_path)
    result = CommandResult(0, b"lab-ok", b"", 1, False, False)
    with pytest.raises(EvidenceError):
        store.record(
            action_id="net.http-get",
            request=_request(rationale="token aws_secret_access_key=AKIAIOSFODNN7EXAMPLEabcd"),
            result=result,
            decision_kind="allow",
            reason_code="ALLOW",
            now=_NOW,
        )
    assert not (tmp_path / "evidence").exists() or not any((tmp_path / "evidence").iterdir())


def test_run_id_is_filesystem_safe(tmp_path):
    store = EvidenceStore(tmp_path)
    run_id = store.record(
        action_id="net.http-get",
        request=_request(),
        result=CommandResult(0, b"lab-ok", b"", 1, False, False),
        decision_kind="allow",
        reason_code="ALLOW",
        now=_NOW,
    )
    assert "/" not in run_id and ":" not in run_id
    assert run_id.startswith("20260725T120000Z-")
```

- [ ] **Step 2: Run the store tests and verify RED**

Run: `.venv/bin/python -m pytest tests/evidence/test_store.py -q`
Expected: collection fails — `hackbot.evidence.store` does not exist.

- [ ] **Step 3: Implement EvidenceStore**

```python
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
```

- [ ] **Step 4: Run the store tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/evidence/test_store.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/evidence/store.py tests/evidence/test_store.py
git commit -m "feat: add redacted run-linked evidence store"
```

---

### Task 3: Wire evidence into run_action and the CLI

**Files:**
- Modify: `src/hackbot/tools/adapter.py`
- Modify: `src/hackbot/cli/tool_cmd.py`
- Modify: `tests/tools/test_adapter.py`
- Modify: `tests/tools/test_cli.py`

**Interfaces:**
- Consumes: `EvidenceStore` (Task 2).
- Produces: `run_action(..., evidence: EvidenceStore | None = None)`;
  `ActionOutcome.evidence_run_id: str | None`; `tool run` reports
  `evidence_run_id`.

- [ ] **Step 1: Write failing adapter integration tests**

Add to `tests/tools/test_adapter.py`:

```python
from hackbot.evidence.store import EvidenceStore


def test_allow_captures_evidence(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.echo",
        RiskLevel.L0,
        uses_external_tool=True,
        executable=_ECHO,
        argv_template=(_ECHO, "ok"),
    )
    outcome = run_action(
        definition,
        _request(context, "test.echo"),
        context,
        now=datetime.now(UTC),
        runner=FakeRunner(),
        audit=AuditSink(lab_engagement),
        evidence=EvidenceStore(lab_engagement),
    )
    assert outcome.evidence_run_id is not None
    run_dir = lab_engagement / "evidence" / outcome.evidence_run_id
    assert (run_dir / "stdout").exists()
    assert (run_dir / "meta.json").exists()


def test_deny_captures_no_evidence(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.prohibited",
        RiskLevel.L3,
        uses_external_tool=True,
        executable=_ECHO,
        argv_template=(_ECHO, "x"),
    )
    outcome = run_action(
        definition,
        _request(context, "test.prohibited"),
        context,
        now=datetime.now(UTC),
        runner=FakeRunner(),
        audit=AuditSink(lab_engagement),
        evidence=EvidenceStore(lab_engagement),
    )
    assert outcome.evidence_run_id is None
    assert not (lab_engagement / "evidence").exists()
```

- [ ] **Step 2: Run the adapter tests and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_adapter.py -q`
Expected: `TypeError` — `run_action` has no `evidence` parameter.

- [ ] **Step 3: Add the evidence field and parameter**

In `src/hackbot/tools/adapter.py`, add the field and wire capture:

```python
@dataclass(frozen=True, slots=True)
class ActionOutcome:
    decision: PolicyDecision
    command_result: CommandResult | None
    evidence_run_id: str | None = None

    @property
    def executed(self) -> bool:
        return self.command_result is not None
```

Add `evidence: "EvidenceStore | None" = None` to `run_action`'s keyword-only
parameters (import `EvidenceStore` from `hackbot.evidence.store`), and after the
audit call:

```python
    evidence_run_id: str | None = None
    if result is not None and evidence is not None:
        evidence_run_id = evidence.record(
            action_id=request.action_id,
            request=request,
            result=result,
            decision_kind=decision.kind.value,
            reason_code=decision.reason_code,
            now=decision_at,
        )
    return ActionOutcome(decision, result, evidence_run_id)
```

- [ ] **Step 4: Run the adapter tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_adapter.py -q`
Expected: all pass.

- [ ] **Step 5: Write failing CLI evidence test**

Add to `tests/tools/test_cli.py`:

```python
@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_reports_and_writes_evidence(lab_engagement, tmp_path, capsys, local_server):
    request = _write_request(tmp_path, local_server, "net.http-get")
    code = app(
        ["tool", "run", "net.http-get", str(request), "--engagement", str(lab_engagement), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    run_id = payload["evidence_run_id"]
    assert run_id
    stdout = (lab_engagement / "evidence" / run_id / "stdout").read_bytes()
    assert b"lab-ok" in stdout
    assert "stdout" not in payload  # raw output still never printed
```

- [ ] **Step 6: Run the CLI test and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_cli.py -q`
Expected: `KeyError: 'evidence_run_id'` (curl present) or skipped.

- [ ] **Step 7: Wire evidence into the CLI**

In `src/hackbot/cli/tool_cmd.py`: import `EvidenceStore` and `EvidenceError`
from `hackbot.evidence.store`, pass `evidence=EvidenceStore(engagement)` to
`run_action`, add `EvidenceError` to the caught exceptions with a clear message
("run executed and audited, but evidence capture failed: …", exit `EXIT_INVALID`),
and add `"evidence_run_id": outcome.evidence_run_id` to the emitted payload.

- [ ] **Step 8: Run the CLI and adapter tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_cli.py tests/tools/test_adapter.py -q`
Expected: all pass (curl-gated cases skip when curl is absent).

- [ ] **Step 9: Commit**

```bash
git add src/hackbot/tools/adapter.py src/hackbot/cli/tool_cmd.py \
  tests/tools/test_adapter.py tests/tools/test_cli.py
git commit -m "feat: capture redacted evidence for executed tool runs"
```

---

### Task 4: Documentation and final regression

**Files:**
- Modify: `docs/tool-execution.md`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `docs/next-steps.md`

- [ ] **Step 1: Document evidence**

Add an "Evidence" section to `docs/tool-execution.md`: the redacted-only,
run-linked layout (`<engagement>/evidence/<run_id>/{stdout,stderr,meta.json}`),
the `run_id` format, that redaction is best-effort, that raw output is never
printed or stored un-redacted, and that `meta.json` links evidence to the
hypothesis. Update README (test count, one-line evidence note) and SECURITY
(evidence is stored redacted, locally, per engagement; best-effort redaction).
Update `docs/next-steps.md` to mark evidence persistence done and re-point the
roadmap (item 1 becomes L2 execution over the CLI).

- [ ] **Step 2: Run all verification gates**

```bash
.venv/bin/python -m pytest -q -ra
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
scripts/smoke_test.sh
git diff --check
```

Expected: zero failures, Ruff clean, formatting clean, mypy clean, offline smoke
pass, no whitespace errors. Update the README/next-steps test count from the
fresh final collection.

- [ ] **Step 3: Commit**

```bash
git add docs/tool-execution.md README.md SECURITY.md docs/next-steps.md
git commit -m "docs: document evidence persistence and verify"
```

---

## Plan self-review

- **Spec coverage:** redactor (Task 1), EvidenceStore with secret-scanned meta
  and modes (Task 2), run_action + CLI integration with audit-before-evidence and
  no capture on deny (Task 3), docs + regression (Task 4). All spec sections map
  to a task.
- **Placeholder scan:** none — every step carries real code or an exact command.
- **Type consistency:** `redact_bytes`, `EvidenceStore.record`, `EvidenceError`,
  `ActionOutcome.evidence_run_id`, and the `run_action(..., evidence=...)`
  signature match across tasks.
- **Safety boundary:** evidence is redacted-only, local, per engagement, captured
  only for executed runs, written after the audit line; raw output is never
  printed or stored un-redacted.
```
