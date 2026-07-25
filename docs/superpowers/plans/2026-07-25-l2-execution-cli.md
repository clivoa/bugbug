# L2 Execution Over the CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run an intrusive (L2) action once over the CLI after an interactive TTY
approval that is consumed atomically — completing the L2 path end to end.

**Architecture:** Add the first real L2 action (`net.http-post`), extract a shared
`interactive_grant` TTY helper from `cmd_grant`, and wire `hackbot tool run
--approve` to persist a pending challenge, grant it at the TTY, and execute once
via `run_action(grant=…, approval_store=…)`.

**Tech Stack:** Python 3.11+ standard library, the existing `hackbot.risk`
approval engine and `hackbot.tools`/`hackbot.evidence`/`hackbot.audit` modules,
pytest, Ruff, mypy. `curl` is the only external tool.

## Global Constraints

- Nothing executes unless `RiskEngine.evaluate` returns `ALLOW`. Fail-closed.
- L2 approval is interactive-TTY only (`_read_approval_from_tty`); no argv, env,
  stdin, or model path. A grant is single-use and consumed atomically once.
- Never build argv from model/target content; only render code-owned templates.
- The reviewed `hackbot.risk` package is not modified.
- `--approve` on a non-L2 action is inert.
- Production behavior is written test-first; each test is observed failing for the
  intended reason before implementation.

---

### Task 1: First real L2 action — net.http-post

**Files:**
- Modify: `src/hackbot/tools/actions.py`
- Modify: `tests/tools/test_actions.py`

**Interfaces:**
- Produces: `net.http-post` in `REAL_ACTIONS`.

- [ ] **Step 1: Write the failing action test**

Add to `tests/tools/test_actions.py`:

```python
@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_http_post_is_registered_l2_and_state_changing():
    from hackbot.risk.models import RiskLevel

    definition = REAL_ACTIONS.require("net.http-post")
    assert definition.state_changing is True
    assert definition.effective_floor is RiskLevel.L2
    assert definition.network_access is True
    assert definition.uses_external_tool is True
    assert definition.shell_execution is False
    assert definition.argv_template[-1] == "{target}"
```

- [ ] **Step 2: Run the action test and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py -q`
Expected: `RegistryError` — `net.http-post` is not registered.

- [ ] **Step 3: Register net.http-post**

In `src/hackbot/tools/actions.py`, inside `_build_actions`, after the
`net.http-get` append:

```python
        definitions.append(
            ActionDefinition(
                "net.http-post",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                state_changing=True,
                executable=curl,
                argv_template=(curl, "-sS", "-X", "POST", "--max-time", "10", "{target}"),
            )
        )
```

- [ ] **Step 4: Run the action test and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/tools/actions.py tests/tools/test_actions.py
git commit -m "feat: add L2 net.http-post action"
```

---

### Task 2: Shared interactive_grant helper

**Files:**
- Modify: `src/hackbot/cli/risk_cmd.py`
- Modify: `tests/risk/test_cli.py`

**Interfaces:**
- Produces: `GrantAborted`,
  `interactive_grant(engagement, store, registry, challenge_id, *, context)
  -> tuple[ApprovalGrant, PolicyContext]`.
- Consumes: `challenge_for_pending`, `_read_approval_from_tty`.

- [ ] **Step 1: Confirm existing grant tests describe the behavior to preserve**

The existing `tests/risk/test_cli.py` cases
`test_grant_succeeds_when_tty_confirms`, `test_grant_refuses_without_tty`, and
`test_grant_rejects_non_digest_id` are the behavior contract. They must stay
green after the refactor. No new test file is needed for the helper; Task 3
exercises it through `tool run`.

- [ ] **Step 2: Add GrantAborted and interactive_grant**

In `src/hackbot/cli/risk_cmd.py`, add near the other imports
`from hackbot.risk.registry import ActionRegistry` (for the type only; runtime
callers pass a registry) and implement:

```python
class GrantAborted(Exception):
    """Raised inside the interactive grant flow with a stable CLI exit code."""

    def __init__(self, exit_code: int, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


def interactive_grant(
    engagement: str,
    store: object,
    registry: object,
    challenge_id: str,
    *,
    context: object,
):
    """Reconstruct the pending challenge, confirm at the TTY, and grant it once.

    Returns (grant, fresh_context) — the grant and the reloaded context it was
    created under. Raises GrantAborted(exit_code, message) on any failure.
    """
    from hackbot.cli import main as cli_main
    from hackbot.risk.approvals import ApprovalError

    try:
        challenge = store.challenge_for_pending(  # type: ignore[attr-defined]
            challenge_id, registry, context, now=datetime.now(UTC)
        )
    except ApprovalError as exc:
        raise GrantAborted(EXIT_DENY, f"error: {exc}") from exc
    try:
        cli_main._read_approval_from_tty(challenge)
    except OSError as exc:
        raise GrantAborted(EXIT_APPROVAL_UNAVAILABLE, str(exc)) from exc
    try:
        fresh_context = _load_context(engagement)
    except CliInputError as exc:
        raise GrantAborted(EXIT_INVALID, f"error: {exc}") from exc
    granted_at = datetime.now(UTC)
    try:
        confirmed = store.challenge_for_pending(  # type: ignore[attr-defined]
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
        grant = store.grant(confirmed, approved_by=approved_by, now=granted_at)  # type: ignore[attr-defined]
    except ApprovalError as exc:
        raise GrantAborted(EXIT_DENY, f"error: could not grant approval: {exc}") from exc
    return grant, fresh_context
```

- [ ] **Step 3: Refactor cmd_grant to use the helper**

Replace the body of `cmd_grant` between constructing `store` and the `finally`
with:

```python
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
```

- [ ] **Step 4: Run the grant CLI tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/risk/test_cli.py -q`
Expected: all pass, including the three grant cases (behavior unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/cli/risk_cmd.py
git commit -m "refactor: extract interactive_grant TTY helper"
```

---

### Task 3: hackbot tool run --approve

**Files:**
- Modify: `src/hackbot/cli/tool_cmd.py`
- Modify: `src/hackbot/cli/main.py`
- Modify: `tests/tools/conftest.py`
- Modify: `tests/tools/test_cli.py`

**Interfaces:**
- Consumes: `interactive_grant`, `GrantAborted`, `REAL_ACTIONS`, `run_action`,
  `ApprovalStore`, `CommandRunner`, `AuditSink`, `EvidenceStore`.
- Produces: `cmd_run(engagement, action_id, request_path, *, as_json, approve)`;
  a `--approve` flag on `tool run`.

- [ ] **Step 1: Add a POST handler to the shared local server**

In `tests/tools/conftest.py`, add to `_Handler`:

```python
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        body = b"post-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
```

- [ ] **Step 2: Write failing L2 CLI tests**

Add to `tests/tools/test_cli.py`:

```python
def _write_post_request(path: Path, target: str) -> Path:
    request = path / "request.json"
    request.write_text(
        json.dumps(
            {
                "action_id": "net.http-post",
                "target": target,
                "argv": [
                    curl_path() or "/usr/bin/curl",
                    "-sS",
                    "-X",
                    "POST",
                    "--max-time",
                    "10",
                    target,
                ],
                "hypothesis_id": "hyp-1",
                "rationale": "Send one authorized POST to a lab endpoint.",
                "rate": 1,
                "concurrency": 1,
                "data_touched": "Lab request/response.",
                "expected_impact": "One low-rate state-changing POST.",
                "stop_condition": "Stop on any error.",
                "cleanup_plan": "Lab state reset out of band.",
                "program_rule": "Authorized intrusive lab testing.",
                "required_headers": [],
                "requested_risk": None,
            }
        )
    )
    return request


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_l2_without_approve_writes_pending(lab_engagement, tmp_path, capsys):
    request = _write_post_request(tmp_path, "http://127.0.0.1/")
    code = app(
        ["tool", "run", "net.http-post", str(request), "--engagement", str(lab_engagement), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 4
    assert payload["approval_status"] == "pending"
    assert payload["executed"] is False
    challenge_id = payload["challenge_id"]
    assert (lab_engagement / "approvals" / "pending" / f"{challenge_id}.json").exists()


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_l2_approve_executes_and_consumes(
    lab_engagement, tmp_path, capsys, monkeypatch, local_server
):
    monkeypatch.setattr("hackbot.cli.main._read_approval_from_tty", lambda _c: None)
    request = _write_post_request(tmp_path, local_server)
    code = app(
        [
            "tool",
            "run",
            "net.http-post",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--approve",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["executed"] is True
    assert payload["exit_code"] == 0
    assert payload["evidence_run_id"]
    challenge_id = payload["challenge_id"]
    from hackbot.risk.approvals import ApprovalStore

    with ApprovalStore(lab_engagement) as store:
        assert store.status(challenge_id) == "consumed"


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_l2_approve_without_tty_does_not_execute(
    lab_engagement, tmp_path, capsys, monkeypatch
):
    def _no_tty(_challenge):
        raise OSError("interactive TTY required")

    monkeypatch.setattr("hackbot.cli.main._read_approval_from_tty", _no_tty)
    request = _write_post_request(tmp_path, "http://127.0.0.1/")
    code = app(
        [
            "tool",
            "run",
            "net.http-post",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--approve",
        ]
    )
    assert code == 3
    assert "interactive TTY required" in capsys.readouterr().err
    assert not (lab_engagement / "evidence").exists()
```

- [ ] **Step 3: Run the L2 CLI tests and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_cli.py -q`
Expected: failures — `tool run` has no `--approve` and does not persist pending.

- [ ] **Step 4: Rewrite cmd_run to handle L2**

Replace `src/hackbot/cli/tool_cmd.py`'s `cmd_run` with:

```python
def cmd_run(
    engagement: str, action_id: str, request_path: str, *, as_json: bool, approve: bool = False
) -> int:
    from hackbot.audit.tool_runs import AuditError, AuditSink
    from hackbot.cli.risk_cmd import GrantAborted, interactive_grant
    from hackbot.evidence.store import EvidenceError, EvidenceStore
    from hackbot.risk.approvals import ApprovalError, ApprovalStore
    from hackbot.risk.models import DecisionKind
    from hackbot.risk.registry import ActionRegistry, RegistryError
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

    runner = CommandRunner()
    audit = AuditSink(engagement)
    evidence = EvidenceStore(engagement)
    try:
        store = ApprovalStore(engagement)
    except ApprovalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    now = datetime.now(UTC)
    try:
        try:
            outcome = run_action(
                definition, request, context, now=now,
                runner=runner, audit=audit, evidence=evidence, approval_store=store,
            )
        except (RunnerError, AuditError, EvidenceError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INVALID

        challenge_id: str | None = None
        if outcome.decision.kind is DecisionKind.REQUIRES_APPROVAL:
            challenge = outcome.decision.challenge
            try:
                store.create_pending(
                    definition, request, context, now=now, nonce=challenge.nonce
                )
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
                    definition, request, fresh_context, grant=grant, now=datetime.now(UTC),
                    runner=runner, audit=audit, evidence=evidence, approval_store=store,
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
```

The captured `now` is passed to both the first `run_action` and `create_pending`,
so the rebuilt challenge digest matches (no `ActionOutcome` change needed).

- [ ] **Step 5: Wire the --approve flag in main.py**

In `build_parser`, add to the `tool run` subparser:

```python
    tl_run.add_argument("--approve", action="store_true", help="approve an L2 action at the TTY and run it once")
```

and in `_cmd_tool`:

```python
        return tool_cmd.cmd_run(
            args.engagement, args.action_id, args.request, as_json=args.json, approve=args.approve
        )
```

- [ ] **Step 6: Run the tool CLI and adapter tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools -q`
Expected: all pass (curl-gated cases skip when curl is absent).

- [ ] **Step 7: Commit**

```bash
git add src/hackbot/cli/tool_cmd.py src/hackbot/cli/main.py src/hackbot/tools/adapter.py \
  tests/tools/conftest.py tests/tools/test_cli.py
git commit -m "feat: run an L2 action once via hackbot tool run --approve"
```

---

### Task 4: Documentation and final regression

**Files:**
- Modify: `docs/tool-execution.md`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `docs/next-steps.md`
- Modify: `scripts/smoke_test.sh`

- [ ] **Step 1: Document L2 over the CLI**

Add to `docs/tool-execution.md`: `net.http-post` (first L2 action), the
`tool run --approve` flow (persist pending → TTY grant → single-use atomic
consume → execute once), the `4`/`3` exit codes for L2, and that each run is a
fresh single-use approval. Update README (test count, one-line L2 note),
SECURITY (L2 executed only after a fresh TTY-typed, single-use approval), and
`docs/next-steps.md` (mark L2-over-CLI done; next = more reviewed actions +
findings/reporting).

- [ ] **Step 2: Extend the offline smoke test**

In `scripts/smoke_test.sh`, alongside the existing tool help checks:

```bash
"$HACKBOT" tool run --help | grep -q -- --approve && echo "tool run --approve present"
```

- [ ] **Step 3: Run all verification gates**

```bash
.venv/bin/python -m pytest -q -ra
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
scripts/smoke_test.sh
git diff --check
```

Expected: zero failures, Ruff clean, formatting clean, mypy clean, offline smoke
pass, no whitespace errors. Refresh the README/next-steps test count from the
fresh collection.

- [ ] **Step 4: Commit**

```bash
git add docs/tool-execution.md README.md SECURITY.md docs/next-steps.md scripts/smoke_test.sh
git commit -m "docs: document L2 execution over the CLI and verify"
```

---

## Plan self-review

- **Spec coverage:** net.http-post L2 action (Task 1), interactive_grant helper +
  cmd_grant refactor (Task 2), tool run --approve with pending/grant/execute and
  exit codes (Task 3), docs + regression (Task 4). All spec sections map to a
  task.
- **Placeholder scan:** none — every step carries real code or an exact command.
- **Type consistency:** `interactive_grant`/`GrantAborted`,
  `ActionOutcome.decision_at`, `cmd_run(..., approve=...)`, and the `--approve`
  flag match across tasks.
- **Safety boundary:** L2 runs only after a fresh TTY-typed, single-use approval
  consumed atomically by `evaluate`; no TTY → exit 3, pending unconsumed; audit
  and redacted evidence captured; no argv from model/target content.
```
