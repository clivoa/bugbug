# Tool execution substrate

`src/hackbot/tools/` is Hackbot's first *executing* layer: a validated,
gate-bound way to run a code-owned external tool. It exists so that reviewed
tool adapters can run real actions **only** after passing the risk gate
(`docs/risk-and-approval.md`). This increment ships one real action —
`net.http-get`, a low-impact passive fetch via `curl`, restricted to in-scope
targets (local labs).

## The execution contract

`hackbot.tools.adapter.run_action(definition, request, context, *, grant=None,
now=None, runner, audit, approval_store=None) -> ActionOutcome` is the **only**
sanctioned way to execute an action. It:

1. Evaluates the request with `RiskEngine.evaluate`.
2. Executes **only** when the decision is `ALLOW`. `DENY` and `REQUIRES_APPROVAL`
   (no/invalid grant) return without executing (`ActionOutcome.executed is False`).
3. Runs **only** the code-owned rendered `argv_template`
   (`definition.render_argv(request)`) — never argv built from model or target
   content.
4. Records exactly one secret-free audit line, then returns the outcome.

There is no path to execute without an `ALLOW`.

## CommandRunner guarantees

`hackbot.tools.runner.CommandRunner` performs only execution mechanics:

- `subprocess.run`-style execution with **`shell=False`**; stdin is closed.
- A **mandatory bounded timeout**; on expiry the child **process group** is
  killed (`start_new_session=True` + `killpg`) and `timed_out=True` is set.
- A **sanitized environment** (`PATH=/usr/bin:/bin`, `LC_ALL=C`) — never the
  operator's environment, so no secret env var reaches a child.
- `stdout`/`stderr` captured as **bytes**, each **byte-capped** (over-cap output
  is truncated and `truncated=True`).
- Fails closed (`RunnerError`) on an empty argv or a non-absolute / missing
  executable. `shell_execution` is an L3 floor and is never run here.

## The `net.http-get` action

Code-owned in `hackbot.tools.actions.REAL_ACTIONS` (CLI input can never register
or mutate an action):

- L0, `network_access=True` (so `scope.check(target)` is mandatory),
  `uses_external_tool=True`.
- `executable` is a resolved absolute `curl` path (from the allowlist
  `/usr/bin/curl`, `/opt/homebrew/bin/curl`, `/usr/local/bin/curl`); if none
  exists the action is not registered and the CLI reports it unavailable.
- `argv_template = (curl, "-sS", "--max-time", "10", "{target}")`. Only
  `{target}` is substituted (with the scope-validated request target).

## Audit log

`hackbot.audit.tool_runs.AuditSink` appends to
`<engagement>/audit/tool-runs.jsonl` (dir `0700`, file `0600`), one compact JSON
object per `run_action` outcome, **secret-free** (scanned by the approval
store's secret scanner before writing):

`timestamp, action_id, effective_risk, target, argv (code-owned rendered),
decision, reason_code, exit_code, timed_out, truncated, stdout_sha256,
stdout_bytes, stderr_bytes, duration_ms`.

Raw stdout/stderr are **never** written to the audit log (that belongs to a
later `evidence/` phase). If a record would carry a secret, the write is refused
(`AuditError`) and nothing is persisted.

## CLI

```text
hackbot tool run ACTION_ID REQUEST.json --engagement DIR [--json]
```

Loads the context, strictly parses the request (the same parser as
`risk evaluate`: ≤ 64 KiB, UTF-8, no duplicate keys / non-finite constants /
bool-as-int; engagement identity comes from the context, never the request
file), resolves `ACTION_ID` only from `REAL_ACTIONS`, and calls `run_action`.
**Raw tool output is never printed by default** — only the decision, exit status,
sizes, and a `stdout_sha256`.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | executed; tool exit `0` |
| `1` | policy deny, or tool exited non-zero / timed out |
| `2` | invalid input/context/action id, or tool unavailable / missing `config` extra |
| `4` | L2 requires-approval (not executed) |

L2 execution over the CLI (the grant handshake) is intentionally not wired yet.

## Example (local lab)

With an engagement whose scope lists a loopback range (a `local-lab` profile,
`scope.in_scope.cidrs: ["127.0.0.0/8"]`) and a request file targeting a local
server:

```bash
# request.json: action_id net.http-get, target http://127.0.0.1:8000/,
# argv [<curl>, -sS, --max-time, 10, http://127.0.0.1:8000/], rate 1, concurrency 1, ...
hackbot tool run net.http-get request.json --engagement engagements/local-lab --json
```

An in-scope target runs curl once and reports `executed: true, exit_code: 0`; an
out-of-scope target reports `DENY_SCOPE` with `executed: false` and never runs.

## Boundary

This is the first code that runs a subprocess. It runs **only** a code-owned
executable with a code-owned argv template, **only** after an `ALLOW` from the
gate, **only** against in-scope targets, with a sanitized environment, a
mandatory timeout, and a secret-free audit trail. There is no shell path, no
argv from model/target content, and no way to execute without passing the gate.
