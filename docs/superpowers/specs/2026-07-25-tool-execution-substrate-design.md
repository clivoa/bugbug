# Tool execution substrate + first local HTTP probe — design

**Status:** approved (2026-07-25)

**Goal:** Introduce the first *executing* layer of Hackbot — a validated,
gate-bound subprocess substrate — and prove it end to end with one real,
low-impact network action (`net.http-get`) restricted to in-scope targets
(local labs in this increment). Every execution must pass the existing
`RiskEngine` gate before anything runs.

**Non-goals:** No provider/model call, no MCP, no evidence persistence of raw
output, no L2 execution over the CLI (that needs the grant handshake and comes
later), no broad tool registry, no shell execution (always L3). The reviewed
`hackbot.risk` package is not modified.

## Context

`hackbot.risk` already provides a deterministic, fail-closed L0–L3 policy gate
and a single-use L2 approval store. `ActionDefinition` already models external
tools (`uses_external_tool`, canonical `executable`, `argv_template` with
whole-token placeholders `{target}`/`{rate}`/`{concurrency}`) and renders argv
via `ActionDefinition.render_argv(request)`. `shell_execution=True` is an L3
floor. `src/hackbot/tools/`, `src/hackbot/audit/`, and `src/hackbot/evidence/`
are empty stubs.

This increment fills `tools/` and `audit/` and adds a `hackbot tool run` CLI.

## Architecture

Three isolated units plus an audit sink and a CLI command.

### 1. `src/hackbot/tools/runner.py` — `CommandRunner`

Pure execution mechanics; contains **no policy**.

- Input: an already-rendered, non-empty `argv: tuple[str, ...]` whose `argv[0]`
  is an existing absolute executable path.
- Executes with `subprocess.run(argv, shell=False)`; `stdin` is closed/empty.
- **Mandatory timeout** (caller-supplied, bounded). On timeout the child process
  group is killed (`start_new_session=True` + `os.killpg`), and the result is
  marked `timed_out=True`.
- **Sanitized environment**: a small curated env only (`PATH=/usr/bin:/bin`,
  `LC_ALL=C`), never the operator's environment, so no secret env var leaks into
  a child.
- Captures `stdout` and `stderr` as **bytes**, each capped at a byte limit;
  output over the cap is truncated and `truncated=True` is set.
- Returns a frozen `CommandResult(exit_code, stdout, stderr, duration_ms,
  timed_out, truncated)`. Never raises for a non-zero tool exit; raises only for
  a malformed argv or a missing executable (fail-closed).

### 2. `src/hackbot/tools/adapter.py` — `run_action(...)`

Binds execution to the gate; the only sanctioned way to run an action.

```python
def run_action(
    definition: ActionDefinition,
    request: ActionRequest,
    context: PolicyContext,
    *,
    grant: ApprovalGrant | None = None,
    now: datetime | None = None,
    runner: CommandRunner = ...,
    audit: AuditSink = ...,
) -> ActionOutcome: ...
```

1. `decision = RiskEngine(ActionRegistry([definition]), approval_store=...).evaluate(request, context, grant=grant, now=now)`
   — the passed code-owned `definition` is wrapped in a one-item registry for
   evaluation, exactly as `build_challenge` already does.
2. Execute **only** when `decision.kind is ALLOW`. `DENY` and
   `REQUIRES_APPROVAL` (no/invalid grant) return an `ActionOutcome` with
   `command_result=None` and **do not execute**. Fail-closed by construction.
3. For external-tool definitions, render argv via `definition.render_argv(request)`;
   a `None`/empty render refuses. Non-external (fixture-like) definitions are not
   runnable here and refuse.
4. Run via the injected `runner`.
5. Write exactly one secret-free audit line via `audit`; if the audit write
   fails, the call reports failure rather than a misleading success.
6. Return `ActionOutcome(decision, command_result | None)`. Captured output is
   untrusted data — never interpreted as instructions.

### 3. `src/hackbot/tools/actions.py` — code-owned real action registry

An immutable `ActionRegistry` (like `fixtures.py`, but real). First member:

- `net.http-get` — L0, `network_access=True`, `uses_external_tool=True`,
  `executable=<resolved absolute curl path>`,
  `argv_template=("<curl>", "-sS", "--fail", "--max-time", "{target}")`
  (the exact flag set is finalized in the plan; `{target}` is the only
  placeholder). `network_access=True` forces `scope.check(target)`, so the
  action only runs against in-scope targets.

`resolve_executable(name, candidates)` returns the first existing absolute path
from a small allowlist (`/usr/bin/curl`, `/opt/homebrew/bin/curl`,
`/usr/local/bin/curl`) and fails closed if none exist; the CLI reports the tool
as unavailable (exit 2) without a traceback. CLI input can never register or
mutate an action.

### Audit — `src/hackbot/audit/`

`AuditSink` appends to `<engagement>/audit/tool-runs.jsonl` (append-only, dir
`0700`, file `0600`), one compact JSON object per run, **secret-free** (reuses
the approval store's secret scanner before writing):

`timestamp, engagement_id, action_id, effective_risk, target, argv (code-owned
rendered), decision, exit_code, timed_out, truncated, stdout_sha256,
stdout_bytes, stderr_bytes, duration_ms`.

Raw stdout/stderr are **not** written to the audit log (that belongs to a later
`evidence/` phase).

### CLI — `hackbot tool run`

```text
hackbot tool run ACTION_ID REQUEST.json --engagement DIR [--json]
```

- Loads the context, strictly parses the request (the same parser as
  `risk evaluate`: ≤64 KiB, UTF-8, no duplicate keys, no non-finite constants,
  no bool-as-int; engagement identity from the context, never the request file).
- Resolves `ACTION_ID` only from `actions.py`.
- Calls `run_action`. L0/L1 → execute and report the outcome (decision,
  exit_code, sizes, `stdout_sha256`); **raw output is not printed by default**.
  L2 → report `requires-approval` without executing. L3/deny → report without
  executing.

## Error handling

All paths fail closed:

- No `ALLOW` decision → never executes.
- Missing/unresolved executable → clean refusal, exit 2, guidance, no traceback.
- Timeout → kill the process group, `timed_out=True`, exit 1, audited.
- Output over the cap → truncated, `truncated=True`, audited.
- Audit write failure → do not report success.
- Errors disclose only names, reason codes, and safe paths — never secrets,
  request bodies, or environment contents.

## Exit codes (CLI)

| Code | Meaning |
|------|---------|
| `0` | executed; tool exit `0` |
| `1` | policy deny, or tool exited non-zero / timed out |
| `2` | invalid input/context/action id, or tool unavailable |
| `4` | L2 requires-approval (not executed) |

## Testing strategy (test-first)

- **`CommandRunner`** against a portable inert binary (`/bin/echo`): output
  capture; timeout via a sleeping command; byte-cap truncation; env sanitization
  (a secret env var set in the test does not reach the child); no shell (argv
  containing shell metacharacters is passed literally, not interpreted).
- **`run_action` / gate binding** with an **injected fake runner** for
  determinism: refuse on `DENY`, refuse on `REQUIRES_APPROVAL` without a grant,
  execute only on `ALLOW`, write exactly one secret-free audit line, treat output
  as data.
- **`net.http-get` end-to-end** against a local `http.server` on `127.0.0.1`
  with the real `curl` action; **skipped if `curl` is not installed**. An
  out-of-scope target returns `DENY_SCOPE` with no execution.
- **CLI `tool run`**: L0 executes (exit 0), deny (exit 1), invalid input
  (exit 2), L2 requires-approval (exit 4, no execution).
- **Regression**: full suite, Ruff, format, mypy, and the offline smoke test
  (no smoke step performs a target/provider request).

## Safety boundary

This is the first code that runs a subprocess. It runs **only** a code-owned
executable with a code-owned argv template, **only** after an `ALLOW` from the
gate, **only** against in-scope targets, with a sanitized environment, a
mandatory timeout, and a secret-free audit trail. There is no shell path
(`shell_execution` is L3), no argv built from model or target content, and no
way to execute without passing the gate.
