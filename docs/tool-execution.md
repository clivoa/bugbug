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
- A **mandatory finite, positive timeout**; `NaN` and infinities fail closed
  before spawn. On expiry the child **process group** is killed
  (`start_new_session=True` + `killpg`) and `timed_out=True` is set.
- A **sanitized environment** (`PATH=/usr/bin:/bin`, `LC_ALL=C`) — never the
  operator's environment, so no secret env var reaches a child.
- `stdout` and `stderr` are drained concurrently while the child runs and captured
  as **bytes**. Each stream retains only its first configured byte prefix; any
  excess bytes are discarded, never persisted or interpreted. Reaching exactly
  the cap is not truncation, but any additional byte on either stream sets the
  combined `truncated=True`. Partial chunks extend the prefix through a
  zero-copy view that is released, with its payload reference, before the next
  pipe read.
- Exceeding an output cap neither kills the tool nor replaces its real exit code.
  The mandatory timeout covers both process execution and inherited pipe EOF; on
  expiry, the launch-time process group is killed before the group leader is
  reaped. During normal monitoring the leader is not polled until both stream
  readers have stopped. Cleanup may add at most one second, plus scheduler
  overhead.
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

Two more L0 passive probes share the same shape (curl, in-scope only):
`net.http-head` (`curl -I`, response headers only) and `net.http-options`
(`curl -i -X OPTIONS`, allowed methods). OPTIONS is safe/idempotent, so it stays
L0 (not `state_changing`).

Two **non-curl** L0 actions show the substrate generalizes across tools (each
registered only when its tool resolves, in-scope only):

- **`dns.lookup`** — `dig +short {target}` (a resolver lookup; `target` is a
  hostname, scope-matched by domain, or an in-scope IP).
- **`tls.cert`** — `openssl s_client -connect {target}` (`target` is `host:port`,
  scope-matched by CIDR). `s_client` exits non-zero when it cannot verify a
  self-signed certificate — expected for a probe; the certificate is still
  captured in the (redacted) evidence.

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

## Evidence

Every **executed** run (post-`ALLOW`) captures its output as evidence, so the
`context → evaluate → allow → run → evidence` path is complete. `run_action`
writes the audit line **first**, then evidence, so the audit trail exists even if
evidence capture fails.

`hackbot.evidence.store.EvidenceStore` writes under
`<engagement>/evidence/<run_id>/` (dir `0700`, files `0600`):

- `stdout`, `stderr` — the tool output **redacted** of known secrets
  (`hackbot.evidence.redact.redact_bytes`).
- `meta.json` — `run_id`, timestamp, `action_id`, `target`, `argv`,
  `hypothesis_id` / `rationale` / `expected_impact` (linking evidence to the
  recorded hypothesis), decision, `exit_code`, `timed_out`, `truncated`,
  `stdout_sha256` (of the redacted content), and sizes. `meta.json` is
  secret-scanned before any file is written; a secret-bearing field (e.g. an
  operator `rationale` containing a token) raises `EvidenceError` and nothing is
  persisted.

`run_id = <UTC timestamp>-<12 hex of the redacted-stdout sha256>`.

**Redaction is best-effort, not a guarantee.** `redact_bytes` replaces known
secret shapes (private-key blocks, `Authorization`/`Cookie`-style headers, JWTs,
`AKIA…`/`sk_…` tokens, secret-name assignments) with `[REDACTED]`, but cannot
catch every secret or PII. It is a layer on top of two other properties: raw
output is **never printed**, and evidence lives only in the git-ignored
engagement directory. Treat evidence files as sensitive. Only executed runs
produce evidence; denied and requires-approval decisions produce none. Raw output
is never stored un-redacted.

## CLI

```text
hackbot tool run ACTION_ID REQUEST.json --engagement DIR [--json]
```

Loads the context, strictly parses the request (the same parser as
`risk evaluate`: ≤ 64 KiB, UTF-8, no duplicate keys / non-finite constants /
bool-as-int; engagement identity comes from the context, never the request
file), resolves `ACTION_ID` only from `REAL_ACTIONS`, and calls `run_action`.
**Raw tool output is never printed by default** — only the decision, exit status,
sizes, a `stdout_sha256`, and the `evidence_run_id` (the redacted output is on
disk under `<engagement>/evidence/<run_id>/`).

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | executed; tool exit `0` (incl. an approved L2 run) |
| `1` | policy deny, tool non-zero / timed out, or approval drift / grant failure |
| `2` | invalid input/context/action id, or tool unavailable / missing `config` extra |
| `3` | L2 `--approve` but TTY unavailable / confirmation mismatch (pending unconsumed) |
| `4` | L2 without `--approve` (pending written, not executed) |

### Running an L2 action (`--approve`)

The first L2 action is **`net.http-post`** (`curl -X POST`, `state_changing=True`
→ L2 floor, in-scope only). L2 actions require an interactive approval
immediately before execution:

- `hackbot tool run net.http-post REQUEST.json --engagement DIR` (no `--approve`)
  → evaluates to `requires-approval`, writes a pending challenge, reports
  `challenge_id`, exit `4`. It does **not** execute.
- `hackbot tool run net.http-post REQUEST.json --engagement DIR --approve`
  → writes the pending, prompts at the **TTY** (`APPROVE-<12 hex>`), grants, then
  executes once via `run_action(grant=…)`, which **consumes the grant atomically**
  and returns `ALLOW`. Exit `0` on tool success; audit + redacted evidence are
  captured. Without a TTY (or a wrong code) → exit `3`, the pending stays
  unconsumed and nothing runs.

Each `tool run --approve` is a distinct single-use approval (one grant → one
execution); running again prompts again. Single-use protects against reusing the
**same** grant, not against separately approved executions. `--approve` on an
L0/L1 action is inert. `risk evaluate` remains the way to write a pending
challenge without executing.

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

An L2 POST against the same lab, approved at the TTY and run once:

```bash
# request.json: action_id net.http-post, argv [<curl>, -sS, -X, POST, --max-time, 10, <url>], ...
hackbot tool run net.http-post request.json --engagement engagements/local-lab --approve --json
```

## Boundary

This is the first code that runs a subprocess. It runs **only** a code-owned
executable with a code-owned argv template, **only** after an `ALLOW` from the
gate, **only** against in-scope targets, with a sanitized environment, a
mandatory timeout, and a secret-free audit trail. There is no shell path, no
argv from model/target content, and no way to execute without passing the gate.
