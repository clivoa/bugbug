# Tool Execution Substrate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Hackbot's first *executing* layer — a validated, gate-bound
subprocess substrate — and prove it end to end with one real low-impact network
action (`net.http-get` via `curl`) restricted to in-scope targets.

**Architecture:** A policy-free `CommandRunner` (subprocess, `shell=False`,
timeout, sanitized env, output caps), a `run_action` adapter that executes only
on a `RiskEngine` `ALLOW`, a code-owned real action registry, and a secret-free
per-engagement audit sink, wired behind a non-executing-by-default
`hackbot tool run` CLI.

**Tech Stack:** Python 3.11+ standard library (`subprocess`, `os`, `signal`,
`hashlib`, `json`, `pathlib`, `datetime`), existing `hackbot.risk` package,
PyYAML behind the `config` extra (tests only), pytest, Ruff, mypy. `curl` is the
only external tool, resolved from a small absolute-path allowlist.

## Global Constraints

- Core package stays standard-library only; YAML stays behind the `config` extra.
- Nothing executes unless `RiskEngine.evaluate` returns `ALLOW`. Fail-closed.
- Never build argv from model or target content; only render code-owned
  `argv_template`s. No shell (`shell_execution` is L3 and never run here).
- The reviewed `hackbot.risk` package is not modified by this plan.
- Child processes get a sanitized environment (no operator env, no secrets), a
  mandatory bounded timeout, closed stdin, and byte-capped output.
- Audit records are append-only and secret-free; raw tool output is never
  written to the audit log.
- Production behavior is written test-first; each test is observed failing for
  the intended reason before implementation.

---

### Task 1: Policy-free CommandRunner

**Files:**
- Create: `src/hackbot/tools/__init__.py` (leave as the existing empty stub)
- Create: `src/hackbot/tools/runner.py`
- Create: `tests/tools/__init__.py`
- Create: `tests/tools/test_runner.py`

**Interfaces:**
- Produces: `CommandResult`, `CommandRunner`, `RunnerError`.
- Consumes: nothing from this plan.

`CommandResult` is a frozen slotted dataclass:
`exit_code: int | None`, `stdout: bytes`, `stderr: bytes`, `duration_ms: int`,
`timed_out: bool`, `truncated: bool`.

`CommandRunner(*, timeout_seconds: float = 30.0, output_cap_bytes: int = 1_048_576,
env: Mapping[str, str] | None = None)` with `run(argv: Sequence[str]) -> CommandResult`.

- [ ] **Step 1: Write failing runner tests**

```python
import os

import pytest

from hackbot.tools.runner import CommandResult, CommandRunner, RunnerError


def test_captures_stdout_and_zero_exit():
    result = CommandRunner().run(("/bin/echo", "hello"))
    assert result.exit_code == 0
    assert result.stdout.strip() == b"hello"
    assert result.timed_out is False
    assert result.truncated is False


def test_argv_is_never_shell_interpreted():
    result = CommandRunner().run(("/bin/echo", "a; rm -rf /"))
    assert b"a; rm -rf /" in result.stdout


def test_environment_is_sanitized(monkeypatch):
    monkeypatch.setenv("HACKBOT_TEST_SECRET", "topsecret")
    result = CommandRunner().run(("/usr/bin/env",))
    assert b"HACKBOT_TEST_SECRET" not in result.stdout
    assert b"topsecret" not in result.stdout


def test_timeout_kills_process_group():
    result = CommandRunner(timeout_seconds=0.5).run(("/bin/sleep", "5"))
    assert result.timed_out is True
    assert result.exit_code is None
    assert result.duration_ms < 4000


def test_output_is_capped_and_marked_truncated():
    result = CommandRunner(output_cap_bytes=10).run(("/bin/echo", "x" * 1000))
    assert result.truncated is True
    assert len(result.stdout) <= 10


def test_missing_executable_fails_closed():
    with pytest.raises(RunnerError):
        CommandRunner().run(("/nonexistent/tool-xyz",))


def test_empty_argv_fails_closed():
    with pytest.raises(RunnerError):
        CommandRunner().run(())
```

- [ ] **Step 2: Run the runner tests and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_runner.py -q`
Expected: collection fails — `hackbot.tools.runner` does not exist.

- [ ] **Step 3: Implement CommandRunner**

```python
"""Policy-free subprocess execution: argv arrays only, never a shell."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

_DEFAULT_ENV: dict[str, str] = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


class RunnerError(Exception):
    """Raised for a malformed argv or a missing executable (fail-closed)."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool
    truncated: bool


class CommandRunner:
    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        output_cap_bytes: int = 1_048_576,
        env: Mapping[str, str] | None = None,
    ) -> None:
        if timeout_seconds <= 0 or output_cap_bytes <= 0:
            raise RunnerError("timeout and output cap must be positive")
        self._timeout = float(timeout_seconds)
        self._cap = int(output_cap_bytes)
        self._env = dict(env) if env is not None else dict(_DEFAULT_ENV)

    def _truncate(self, data: bytes) -> tuple[bytes, bool]:
        return (data[: self._cap], True) if len(data) > self._cap else (data, False)

    def run(self, argv: Sequence[str]) -> CommandResult:
        items = tuple(argv)
        if not items:
            raise RunnerError("argv must be non-empty")
        executable = items[0]
        if not (os.path.isabs(executable) and os.path.isfile(executable)):
            raise RunnerError(f"executable not found: {executable}")
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                list(items),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            raise RunnerError(f"could not start executable: {executable}") from exc
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=self._timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            stdout, stderr = proc.communicate()
        duration_ms = int((time.monotonic() - start) * 1000)
        stdout, out_trunc = self._truncate(stdout)
        stderr, err_trunc = self._truncate(stderr)
        return CommandResult(
            exit_code=None if timed_out else proc.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            truncated=out_trunc or err_trunc,
        )
```

- [ ] **Step 4: Run the runner tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_runner.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/tools/runner.py tests/tools/__init__.py tests/tools/test_runner.py
git commit -m "feat: add policy-free command runner"
```

---

### Task 2: Secret-free per-engagement audit sink

**Files:**
- Create: `src/hackbot/audit/tool_runs.py`
- Create: `tests/audit/__init__.py`
- Create: `tests/audit/test_tool_runs.py`

**Interfaces:**
- Consumes: `CommandResult` (Task 1); `PolicyDecision`, `RiskLevel` from
  `hackbot.risk`; `hackbot.risk.approvals._reject_secrets` and `ApprovalError`.
- Produces: `AuditSink`, `AuditError`.

`AuditSink(engagement_dir: str | Path)` with
`record_run(*, action_id: str, effective_risk: RiskLevel, target: str,
argv: Sequence[str], decision_kind: str, reason_code: str,
result: CommandResult | None, now: datetime) -> None`.

- [ ] **Step 1: Write failing audit tests**

```python
import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hackbot.audit.tool_runs import AuditError, AuditSink
from hackbot.tools.runner import CommandResult


def _result() -> CommandResult:
    return CommandResult(0, b"body", b"", 12, False, False)


def test_record_writes_one_secret_free_line(tmp_path):
    sink = AuditSink(tmp_path)
    sink.record_run(
        action_id="net.http-get",
        effective_risk=__import__("hackbot.risk", fromlist=["RiskLevel"]).RiskLevel.L0,
        target="http://127.0.0.1/",
        argv=("/usr/bin/curl", "http://127.0.0.1/"),
        decision_kind="allow",
        reason_code="ALLOW",
        result=_result(),
        now=datetime(2026, 7, 25, tzinfo=UTC),
    )
    log = tmp_path / "audit" / "tool-runs.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["action_id"] == "net.http-get"
    assert record["exit_code"] == 0
    assert record["stdout_sha256"]  # digest present
    assert "stdout" not in record and "body" not in lines[0]  # no raw output
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "audit").stat().st_mode) == 0o700


def test_record_appends(tmp_path):
    sink = AuditSink(tmp_path)
    for _ in range(2):
        sink.record_run(
            action_id="net.http-get",
            effective_risk=__import__("hackbot.risk", fromlist=["RiskLevel"]).RiskLevel.L0,
            target="http://127.0.0.1/",
            argv=("/usr/bin/curl", "http://127.0.0.1/"),
            decision_kind="allow",
            reason_code="ALLOW",
            result=_result(),
            now=datetime(2026, 7, 25, tzinfo=UTC),
        )
    log = tmp_path / "audit" / "tool-runs.jsonl"
    assert len(log.read_text(encoding="utf-8").splitlines()) == 2


def test_record_rejects_secret_bearing_argv(tmp_path):
    sink = AuditSink(tmp_path)
    with pytest.raises(AuditError):
        sink.record_run(
            action_id="net.http-get",
            effective_risk=__import__("hackbot.risk", fromlist=["RiskLevel"]).RiskLevel.L0,
            target="http://127.0.0.1/",
            argv=("/usr/bin/curl", "aws_secret_access_key=AKIAIOSFODNN7EXAMPLEabcd"),
            decision_kind="allow",
            reason_code="ALLOW",
            result=_result(),
            now=datetime(2026, 7, 25, tzinfo=UTC),
        )
    assert not (tmp_path / "audit" / "tool-runs.jsonl").exists()


def test_record_without_execution_uses_nulls(tmp_path):
    sink = AuditSink(tmp_path)
    sink.record_run(
        action_id="net.http-get",
        effective_risk=__import__("hackbot.risk", fromlist=["RiskLevel"]).RiskLevel.L0,
        target="http://evil.example/",
        argv=("/usr/bin/curl", "http://evil.example/"),
        decision_kind="deny",
        reason_code="DENY_SCOPE",
        result=None,
        now=datetime(2026, 7, 25, tzinfo=UTC),
    )
    record = json.loads((tmp_path / "audit" / "tool-runs.jsonl").read_text().splitlines()[0])
    assert record["decision"] == "deny"
    assert record["exit_code"] is None and record["stdout_sha256"] is None
```

- [ ] **Step 2: Run the audit tests and verify RED**

Run: `.venv/bin/python -m pytest tests/audit/test_tool_runs.py -q`
Expected: collection fails — `hackbot.audit.tool_runs` does not exist.

- [ ] **Step 3: Implement AuditSink**

```python
"""Append-only, secret-free audit trail for tool executions."""

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
```

- [ ] **Step 4: Run the audit tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/audit/test_tool_runs.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/audit/tool_runs.py tests/audit/__init__.py tests/audit/test_tool_runs.py
git commit -m "feat: add secret-free tool-run audit sink"
```

---

### Task 3: Gate-bound run_action adapter

**Files:**
- Create: `src/hackbot/tools/adapter.py`
- Create: `tests/tools/conftest.py`
- Create: `tests/tools/test_adapter.py`

**Interfaces:**
- Consumes: `CommandRunner`/`CommandResult` (Task 1), `AuditSink` (Task 2),
  `RiskEngine`, `ActionRegistry`, `ActionDefinition`, `ActionRequest`,
  `PolicyContext`, `ApprovalGrant`, `DecisionKind`, `PolicyDecision` from
  `hackbot.risk`.
- Produces: `ActionOutcome`, `run_action(...)`.

`run_action(definition, request, context, *, grant=None, now=None, runner,
audit, approval_store=None) -> ActionOutcome`. `ActionOutcome` is a frozen
slotted dataclass `decision: PolicyDecision`, `command_result: CommandResult | None`
with a read-only `executed` property (`command_result is not None`).

- [ ] **Step 1: Write the shared tool-test conftest**

```python
"""Local-lab engagement fixture for tool tests (loopback scope, confirmed auth)."""

import json
from pathlib import Path

import pytest
import yaml

_PROGRAM = {
    "schema_version": 1,
    "program": {"name": "local-lab", "platform": "local-lab", "source": "manual"},
    "authorization": {"confirmed": False},
    "scope": {"in_scope": {"cidrs": ["127.0.0.0/8"]}},
    "testing_rules": {"max_requests_per_second": 2},
    "reporting": {"duplicate_policy": "first-reporter"},
}


@pytest.fixture
def lab_engagement(tmp_path: Path) -> Path:
    engagement = tmp_path / "local-lab"
    engagement.mkdir()
    (engagement / "program.yaml").write_text(yaml.safe_dump(_PROGRAM, sort_keys=False))
    (engagement / "scope.yaml").write_text(
        yaml.safe_dump({"schema_version": 1, **_PROGRAM["scope"]}, sort_keys=False)
    )
    (engagement / "authorization.json").write_text(
        json.dumps(
            {
                "confirmed": True,
                "confirmation_timestamp": "2000-01-01T00:00:00Z",
                "confirmed_by": "lab-operator",
            }
        )
    )
    return engagement
```

- [ ] **Step 2: Write failing adapter tests**

Use `/bin/echo`-backed synthetic definitions (they run only in the ALLOW test).

```python
from datetime import UTC, datetime

from hackbot.audit.tool_runs import AuditSink
from hackbot.risk.context import load_policy_context
from hackbot.risk.models import ActionDefinition, ActionRequest, DecisionKind, RiskLevel
from hackbot.tools.adapter import ActionOutcome, run_action
from hackbot.tools.runner import CommandResult


class FakeRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv):
        self.calls.append(tuple(argv))
        return CommandResult(0, b"ran", b"", 3, False, False)


def _request(context, action_id, *, active=False):
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id=action_id,
        target="http://127.0.0.1/",
        argv=("/bin/echo", "ok") if action_id == "test.echo" else ("/bin/echo", "x"),
        hypothesis_id="hyp-1" if active else "",
        rationale="lab probe" if active else "",
        rate=1 if active else None,
        concurrency=1 if active else None,
        data_touched="none" if active else "",
        expected_impact="none" if active else "",
        stop_condition="stop on block" if active else "",
        cleanup_plan="none" if active else "",
        program_rule="lab rule",
        required_headers=(),
        requested_risk=None,
    )


_ECHO = "/bin/echo"


def test_allow_executes_and_audits(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.echo", RiskLevel.L0, uses_external_tool=True, executable=_ECHO,
        argv_template=(_ECHO, "ok"),
    )
    runner = FakeRunner()
    audit = AuditSink(lab_engagement)
    outcome = run_action(
        definition, _request(context, "test.echo"), context,
        now=datetime.now(UTC), runner=runner, audit=audit,
    )
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert runner.calls == [(_ECHO, "ok")]
    log = (lab_engagement / "audit" / "tool-runs.jsonl").read_text().splitlines()
    assert len(log) == 1


def test_deny_never_executes(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.prohibited", RiskLevel.L3, uses_external_tool=True, executable=_ECHO,
        argv_template=(_ECHO, "x"),
    )
    runner = FakeRunner()
    outcome = run_action(
        definition, _request(context, "test.prohibited"), context,
        now=datetime.now(UTC), runner=runner, audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.executed is False
    assert runner.calls == []


def test_requires_approval_without_grant_never_executes(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.intrusive", RiskLevel.L1, uses_external_tool=True, executable=_ECHO,
        argv_template=(_ECHO, "x"), high_volume=True,
    )
    runner = FakeRunner()
    outcome = run_action(
        definition, _request(context, "test.intrusive", active=True), context,
        now=datetime.now(UTC), runner=runner, audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert outcome.executed is False
    assert runner.calls == []
```

- [ ] **Step 3: Run the adapter tests and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_adapter.py -q`
Expected: collection fails — `hackbot.tools.adapter` does not exist.

- [ ] **Step 4: Implement run_action**

```python
"""Gate-bound execution: run an action only after a RiskEngine ALLOW."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from hackbot.audit.tool_runs import AuditSink
from hackbot.risk.models import (
    ActionDefinition,
    ActionRequest,
    ApprovalGrant,
    DecisionKind,
    PolicyContext,
    PolicyDecision,
)
from hackbot.risk.registry import ActionRegistry
from hackbot.tools.runner import CommandResult, CommandRunner


@dataclass(frozen=True, slots=True)
class ActionOutcome:
    decision: PolicyDecision
    command_result: CommandResult | None

    @property
    def executed(self) -> bool:
        return self.command_result is not None


def run_action(
    definition: ActionDefinition,
    request: ActionRequest,
    context: PolicyContext,
    *,
    grant: ApprovalGrant | None = None,
    now: datetime | None = None,
    runner: CommandRunner,
    audit: AuditSink,
    approval_store: object | None = None,
) -> ActionOutcome:
    decision_at = now if now is not None else datetime.now(UTC)
    from hackbot.risk.policy import RiskEngine

    engine = RiskEngine(ActionRegistry([definition]), approval_store=approval_store)  # type: ignore[arg-type]
    decision = engine.evaluate(request, context, grant=grant, now=decision_at)
    rendered = definition.render_argv(request) or ()
    result: CommandResult | None = None
    if decision.kind is DecisionKind.ALLOW and definition.uses_external_tool and rendered:
        result = runner.run(rendered)
    audit.record_run(
        action_id=request.action_id,
        effective_risk=decision.effective_risk,
        target=request.target,
        argv=rendered,
        decision_kind=decision.kind.value,
        reason_code=decision.reason_code,
        result=result,
        now=decision_at,
    )
    return ActionOutcome(decision, result)
```

- [ ] **Step 5: Run the adapter tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_adapter.py -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/hackbot/tools/adapter.py tests/tools/conftest.py tests/tools/test_adapter.py
git commit -m "feat: add gate-bound run_action adapter"
```

---

### Task 4: Code-owned real action registry (net.http-get)

**Files:**
- Create: `src/hackbot/tools/actions.py`
- Create: `tests/tools/test_actions.py`

**Interfaces:**
- Consumes: `ActionDefinition`, `RiskLevel`, `ActionRegistry`.
- Produces: `resolve_executable(candidates) -> str | None`, `curl_path() -> str | None`,
  `REAL_ACTIONS: ActionRegistry`.

- [ ] **Step 1: Write failing action-registry tests**

```python
import os

import pytest

from hackbot.tools.actions import REAL_ACTIONS, curl_path, resolve_executable


def test_resolve_executable_returns_first_existing_absolute_path(tmp_path):
    real = tmp_path / "tool"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    assert resolve_executable(("/nonexistent/x", str(real))) == str(real)
    assert resolve_executable(("/nonexistent/x",)) is None
    assert resolve_executable(("relative/tool",)) is None  # non-absolute rejected


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_http_get_is_registered_and_curl_backed():
    definition = REAL_ACTIONS.require("net.http-get")
    assert definition.minimum_risk.name == "L0"
    assert definition.network_access is True
    assert definition.uses_external_tool is True
    assert definition.shell_execution is False
    assert os.path.isabs(definition.executable) and definition.argv_template[-1] == "{target}"
```

- [ ] **Step 2: Run the action tests and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py -q`
Expected: collection fails — `hackbot.tools.actions` does not exist.

- [ ] **Step 3: Implement the real action registry**

```python
"""Immutable, code-owned real action definitions. CLI input cannot register one."""

from __future__ import annotations

import os
from collections.abc import Sequence

from hackbot.risk.models import ActionDefinition, RiskLevel
from hackbot.risk.registry import ActionRegistry

_CURL_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/curl",
    "/opt/homebrew/bin/curl",
    "/usr/local/bin/curl",
)


def resolve_executable(candidates: Sequence[str]) -> str | None:
    for candidate in candidates:
        if os.path.isabs(candidate) and os.path.isfile(candidate):
            return candidate
    return None


def curl_path() -> str | None:
    return resolve_executable(_CURL_CANDIDATES)


def _build_actions() -> ActionRegistry:
    definitions: list[ActionDefinition] = []
    curl = curl_path()
    if curl is not None:
        definitions.append(
            ActionDefinition(
                "net.http-get",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=curl,
                argv_template=(curl, "-sS", "--max-time", "10", "{target}"),
            )
        )
    return ActionRegistry(definitions)


REAL_ACTIONS = _build_actions()

__all__ = ["REAL_ACTIONS", "curl_path", "resolve_executable"]
```

- [ ] **Step 4: Run the action tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py -q`
Expected: all pass (the curl-backed test runs when curl is installed).

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/tools/actions.py tests/tools/test_actions.py
git commit -m "feat: add code-owned net.http-get action"
```

---

### Task 5: End-to-end HTTP probe against a local server

**Files:**
- Create: `tests/tools/test_http_get_e2e.py`

**Interfaces:**
- Consumes: `REAL_ACTIONS`, `curl_path`, `run_action`, `CommandRunner`,
  `AuditSink`, `load_policy_context`, `ActionRequest`, `lab_engagement` fixture.

- [ ] **Step 1: Write the failing end-to-end test**

```python
import http.server
import threading
from datetime import UTC, datetime

import pytest

from hackbot.audit.tool_runs import AuditSink
from hackbot.risk.context import load_policy_context
from hackbot.risk.models import ActionRequest, DecisionKind
from hackbot.tools.actions import REAL_ACTIONS, curl_path
from hackbot.tools.adapter import run_action
from hackbot.tools.runner import CommandRunner

pytestmark = pytest.mark.skipif(curl_path() is None, reason="curl not installed")


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"lab-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.fixture
def local_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


def _request(context, target):
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id="net.http-get",
        target=target,
        argv=(curl_path(), "-sS", "--max-time", "10", target),
        hypothesis_id="hyp-1",
        rationale="Fetch one in-scope lab URL once.",
        rate=1,
        concurrency=1,
        data_touched="Public lab response.",
        expected_impact="One low-rate GET against a local lab.",
        stop_condition="Stop on any error.",
        cleanup_plan="No state created.",
        program_rule="Authorized lab fetch.",
        required_headers=(),
        requested_risk=None,
    )


def test_http_get_fetches_in_scope_lab_url(lab_engagement, local_server):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("net.http-get")
    outcome = run_action(
        definition, _request(context, local_server), context,
        now=datetime.now(UTC), runner=CommandRunner(), audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert outcome.command_result.exit_code == 0
    assert b"lab-ok" in outcome.command_result.stdout


def test_http_get_out_of_scope_is_denied_without_execution(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("net.http-get")
    outcome = run_action(
        definition, _request(context, "http://10.0.0.5/"), context,
        now=datetime.now(UTC), runner=CommandRunner(), audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.reason_code == "DENY_SCOPE"
    assert outcome.executed is False
```

Note: the argv in the request must exactly equal `definition.render_argv(request)`
(the model binds request argv to the code-owned template), which is why the test
builds it from `curl_path()` and the same flags.

- [ ] **Step 2: Run the e2e test and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_http_get_e2e.py -q`
Expected: fails only if an earlier task is incomplete; otherwise this validates
the full path. If curl is absent the module is skipped — note that in the report.

- [ ] **Step 3: No new production code**

This task is integration coverage over Tasks 1–4. If a test fails, fix the
responsible unit in its own file, not here.

- [ ] **Step 4: Run the e2e test and verify GREEN (or SKIPPED)**

Run: `.venv/bin/python -m pytest tests/tools/test_http_get_e2e.py -q`
Expected: pass (curl present) or skipped (curl absent).

- [ ] **Step 5: Commit**

```bash
git add tests/tools/test_http_get_e2e.py
git commit -m "test: cover net.http-get end to end against a local lab server"
```

---

### Task 6: Non-executing-by-default `hackbot tool run` CLI

**Files:**
- Create: `src/hackbot/cli/tool_cmd.py`
- Modify: `src/hackbot/cli/main.py`
- Create: `tests/tools/test_cli.py`

**Interfaces:**
- Consumes: `risk_cmd._load_context`, `risk_cmd._strict_parse`,
  `risk_cmd._check_keys`, `risk_cmd._build_request`, `risk_cmd.CliInputError`;
  `REAL_ACTIONS`; `run_action`; `CommandRunner`; `AuditSink`.
- Produces: `cmd_run(engagement, action_id, request_path, *, as_json) -> int`;
  a `tool run` subparser.

- [ ] **Step 1: Write failing CLI tests**

Reuse an inert L0 non-network action by pointing `tool run` at a request whose
target is in scope; drive both an executing case (skip if curl absent) and the
policy-only cases with a real registry action.

```python
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hackbot.cli.main import app
from hackbot.tools.actions import curl_path


def _write_request(path: Path, target: str, action_id: str) -> Path:
    request = path / "request.json"
    request.write_text(
        json.dumps(
            {
                "action_id": action_id,
                "target": target,
                "argv": [curl_path() or "/usr/bin/curl", "-sS", "--max-time", "10", target],
                "hypothesis_id": "hyp-1",
                "rationale": "Fetch one in-scope lab URL once.",
                "rate": 1,
                "concurrency": 1,
                "data_touched": "Public lab response.",
                "expected_impact": "One low-rate GET.",
                "stop_condition": "Stop on any error.",
                "cleanup_plan": "No state created.",
                "program_rule": "Authorized lab fetch.",
                "required_headers": [],
                "requested_risk": None,
            }
        )
    )
    return request


def test_tool_run_unknown_action_is_invalid(lab_engagement, tmp_path, capsys):
    request = _write_request(tmp_path, "http://127.0.0.1/", "net.nonexistent")
    code = app(
        ["tool", "run", "net.nonexistent", str(request),
         "--engagement", str(lab_engagement), "--json"]
    )
    assert code == 2


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_out_of_scope_denies(lab_engagement, tmp_path, capsys):
    request = _write_request(tmp_path, "http://10.0.0.5/", "net.http-get")
    code = app(
        ["tool", "run", "net.http-get", str(request),
         "--engagement", str(lab_engagement), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["reason_code"] == "DENY_SCOPE"
    assert payload["executed"] is False


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_executes_in_scope(lab_engagement, tmp_path, capsys, local_server):
    request = _write_request(tmp_path, local_server, "net.http-get")
    code = app(
        ["tool", "run", "net.http-get", str(request),
         "--engagement", str(lab_engagement), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["executed"] is True
    assert payload["exit_code"] == 0
    assert "stdout" not in payload  # raw output never printed by default
```

Add a `local_server` fixture in `tests/tools/conftest.py` (move it there from the
e2e test so both files share it — replace the e2e file's local copy with the
shared fixture in the same commit).

- [ ] **Step 2: Run the CLI tests and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_cli.py -q`
Expected: `SystemExit: 2` — argparse has no `tool` subcommand.

- [ ] **Step 3: Implement cmd_run**

```python
"""Non-executing-by-default CLI wiring for gated tool runs."""

from __future__ import annotations

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
    import json

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
            "stdout_sha256": __import__("hashlib").sha256(result.stdout).hexdigest()
            if result
            else None,
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
```

Then wire the subparser in `src/hackbot/cli/main.py` (add a `_cmd_tool` handler
mirroring `_cmd_risk`, and register a `tool` subparser with a `run` action taking
`action_id`, `request`, `--engagement` (required), and `--json`).

```python
def _cmd_tool(args: argparse.Namespace) -> int:
    from hackbot.cli import tool_cmd

    if args.taction == "run":
        return tool_cmd.cmd_run(
            args.engagement, args.action_id, args.request, as_json=args.json
        )
    return 2
```

```python
    tl = sub.add_parser("tool", help="run a code-owned action through the risk gate")
    tl_sub = tl.add_subparsers(dest="taction", required=True)
    tl_run = tl_sub.add_parser("run", help="evaluate then run an action (only if allowed)")
    tl_run.add_argument("action_id", help="code-owned action id (e.g. net.http-get)")
    tl_run.add_argument("request", help="local request JSON file")
    tl_run.add_argument("--engagement", required=True, help="engagement directory")
    tl_run.add_argument("--json", action="store_true")
    tl.set_defaults(func=_cmd_tool)
```

- [ ] **Step 4: Run the CLI tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_cli.py -q`
Expected: all pass (curl-gated cases skip when curl is absent).

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/cli/tool_cmd.py src/hackbot/cli/main.py tests/tools/test_cli.py tests/tools/conftest.py
git commit -m "feat: add non-executing-by-default hackbot tool run CLI"
```

---

### Task 7: Documentation, packaging, and final safety regression

**Files:**
- Create: `docs/tool-execution.md`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `docs/next-steps.md`
- Modify: `scripts/smoke_test.sh`
- Modify: `tests/packaging/test_offline_install.py`

- [ ] **Step 1: Document the substrate**

`docs/tool-execution.md` must document: the gate-bound execution contract
(`ALLOW`-only), `CommandRunner` guarantees (no shell, sanitized env, timeout,
output caps), the `net.http-get` action and curl resolution, the audit-log
layout and fields, the CLI (`tool run`) exit codes, that raw output is never
printed by default, and a worked example against a `127.0.0.1` lab. Update
README (status, test count, command list) and SECURITY (first subprocess layer:
what it can and cannot do). Update `docs/next-steps.md` to mark the substrate
done and point at the next step (evidence persistence + more reviewed actions).

- [ ] **Step 2: Extend the offline smoke test**

Add to `scripts/smoke_test.sh` (no network/target request):

```bash
( cd /tmp && "$HACKBOT" tool --help >/dev/null ) && echo "tool help ok"
( cd /tmp && "$HACKBOT" tool run --help >/dev/null ) && echo "tool run help ok"
```

- [ ] **Step 3: Extend offline packaging coverage**

In `tests/packaging/test_offline_install.py` add: `hackbot tool --help` exits 0
and lists `run`; and `hackbot tool run net.http-get <req> --engagement <yaml-eng>`
without the `config` extra fails cleanly with exit 2, guidance, no traceback, and
no `audit/` directory created.

- [ ] **Step 4: Run all verification gates**

```bash
.venv/bin/python -m pytest -q -ra
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
scripts/smoke_test.sh
git diff --check
```

Expected: zero failures, Ruff clean, formatting clean, mypy clean, offline smoke
pass (curl-gated tests skip cleanly where curl is absent), no whitespace errors.

- [ ] **Step 5: Commit**

```bash
git add docs/tool-execution.md README.md SECURITY.md docs/next-steps.md \
  scripts/smoke_test.sh tests/packaging/test_offline_install.py
git commit -m "docs: document and verify the tool execution substrate"
```

---

## Plan self-review

- **Spec coverage:** CommandRunner (Task 1), audit sink (Task 2), gate-bound
  adapter (Task 3), real `net.http-get` action + curl resolution (Task 4),
  end-to-end + out-of-scope deny (Task 5), CLI + exit codes (Task 6), docs +
  packaging + regression (Task 7). All spec sections map to a task.
- **Placeholder scan:** none — every step carries real code or an exact command.
- **Type consistency:** `CommandResult`, `CommandRunner.run`, `AuditSink.record_run`,
  `ActionOutcome`, `run_action`, `REAL_ACTIONS`, `curl_path`, and `cmd_run`
  signatures match across tasks.
- **Safety boundary:** the only executable is a resolved absolute `curl`; the only
  argv is a code-owned template; execution happens only after `ALLOW`; env is
  sanitized; output is capped; audit is secret-free; no shell path exists.
```
