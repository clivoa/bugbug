# L2 execution over the CLI (approve-and-run) — design

**Status:** approved (2026-07-25)

**Goal:** Let an operator run an intrusive (L2) action once, over the CLI, after
an interactive TTY approval that is consumed atomically — completing the L2 path
end to end (`stop and request explicit approval immediately before execution`).

**Non-goals:** No non-TTY approval, no grant reuse across runs, no batching, no
new approval semantics. The reviewed `hackbot.risk` package is not modified.

## Context

The pieces exist: `risk evaluate` writes an L2 pending challenge; `approval grant`
grants it at the TTY; `RiskEngine.evaluate(request, context, grant=…, now=…)`
consumes an `ApprovalGrant` atomically and returns `ALLOW`; `run_action` executes
only on `ALLOW` and now takes an `approval_store`. **But there is no real L2
action** — `net.http-get` is L0 — so the L2 path cannot be exercised over the
CLI. This phase adds the first L2 action as the vehicle and wires the
approve-and-run flow.

## Architecture

### 1. First L2 action — `net.http-post`

Add to `hackbot.tools.actions.REAL_ACTIONS` (built only when `curl` resolves):

- `net.http-post` — `RiskLevel.L0` floor with `state_changing=True` (which raises
  the effective floor to **L2**), `network_access=True` (mandatory scope check),
  `uses_external_tool=True`, `executable=<curl>`,
  `argv_template=(curl, "-sS", "-X", "POST", "--max-time", "10", "{target}")`.

`state_changing` requires no program permission flag, so an in-scope, rate-limited
request resolves to `REQUIRES_APPROVAL`. Lab-only in practice (scope).

### 2. Shared interactive grant helper

Extract the reconstruct → TTY → reload → reconstruct → grant dance from
`risk_cmd.cmd_grant` into a reusable helper (used by `approval grant` and
`tool run`):

```python
class GrantAborted(Exception):
    def __init__(self, exit_code: int, message: str) -> None: ...


def interactive_grant(
    engagement: str,
    store: ApprovalStore,
    registry: ActionRegistry,
    challenge_id: str,
    *,
    context: PolicyContext,
) -> tuple[ApprovalGrant, PolicyContext]: ...
```

It reconstructs the pending challenge from the digest (`challenge_for_pending`,
with the supplied code-owned `registry`), prompts via
`hackbot.cli.main._read_approval_from_tty` (TTY only, exact `APPROVE-<12 hex>`
code), reloads the context, reconstructs again (deny on any drift), and grants
with `authorization.confirmed_by`. On any failure it raises `GrantAborted` with a
stable exit code (`3` TTY unavailable/mismatch, `1` deny/drift/grant failure,
`2` invalid context). It returns the grant and the **fresh** context the grant
was created under, so the caller executes against the same context.

`cmd_grant` is refactored to call this helper (behavior unchanged; its tests
still pass).

### 3. `tool run` approve-and-run

Add `--approve` to `hackbot tool run`. Flow:

- L0/L1 `ALLOW` → execute (unchanged); `--approve` is inert.
- L3 / deny → report, exit `1`.
- L2 (`REQUIRES_APPROVAL`):
  - **without `--approve`** → persist the pending challenge (like
    `risk evaluate`), report `challenge_id`, exit `4`; do not execute.
  - **with `--approve`** → persist the pending, call `interactive_grant`
    (registry = a one-item `ActionRegistry([definition])`), then
    `run_action(definition, request, fresh_context, grant=grant, now=…,
    runner=…, audit=…, evidence=…, approval_store=store)`. `evaluate` consumes the
    grant atomically and returns `ALLOW`, so the action runs once; audit and
    evidence are captured. Exit `0` on tool success.

### Data flow (L2 with --approve)

```
tool run <L2> --approve → load context → parse request → resolve action
  → evaluate(grant=None) → REQUIRES_APPROVAL
  → store.create_pending(...)                       (pending/<digest>.json)
  → interactive_grant: challenge_for_pending → _read_approval_from_tty
       → reload context → challenge_for_pending → store.grant → (grant, fresh_ctx)
  → run_action(grant=grant, approval_store=store):
       evaluate(grant) → challenge_for_grant → consume (atomic, once) → ALLOW
       → CommandRunner.run → audit → evidence
  → ActionOutcome(ALLOW, result, evidence_run_id)   exit 0
```

## Exit codes (tool run)

| Code | Meaning |
|------|---------|
| `0` | executed; tool exit `0` (incl. an approved L2 run) |
| `1` | policy deny, tool non-zero / timeout, or approval drift/grant failure |
| `2` | invalid input/context/action id, or tool unavailable |
| `3` | L2 `--approve` but TTY unavailable / confirmation mismatch (pending unconsumed) |
| `4` | L2 without `--approve` (pending written, not executed) |

## Error handling (fail-closed)

- No `ALLOW` → never executes, never captures evidence.
- The grant is consumed atomically by `evaluate`; replaying the same grant →
  `DENY_APPROVAL_CONSUMED`. Each `tool run --approve` is a distinct single-use
  approval (one grant → one execution); running again prompts again.
- Context drift between prompt and grant → deny (exit `1`), pending remains.
- `--approve` on a non-L2 action is inert (the decision is never
  `REQUIRES_APPROVAL`).
- Confirmation is TTY-only; no argv/env/stdin/model path. No TTY → exit `3`,
  pending unconsumed.

## Testing strategy (test-first)

- **`net.http-post`**: registered, L2 effective floor, `state_changing`,
  `network_access`, `uses_external_tool`, `argv_template` ends with `{target}`;
  skip the curl-backed shape assertion when curl is absent.
- **`tool run` L2 without `--approve`**: writes `pending/<id>.json`, exit `4`,
  nothing executed, no evidence.
- **`tool run` L2 `--approve` (TTY confirmed, monkeypatched)**: executes once
  against a local POST lab server, exit `0`, evidence + audit captured, the
  challenge's stored state becomes `consumed`.
- **`tool run` L2 `--approve` (no TTY, monkeypatched to raise)**: exit `3`, not
  executed, pending intact, no evidence.
- **`interactive_grant` reuse**: existing `approval grant` CLI tests stay green.
- **Regression**: full suite, Ruff, format, mypy, offline smoke (no
  target/provider request; the shared `local_server` fixture gains `do_POST`).

## Boundary

L2 execution over the CLI still requires an interactive TTY approval immediately
before the run, bound to the exact action, consumed atomically once, audited, and
evidenced (redacted). Non-executed decisions capture nothing; there is no path to
run an L2 action without a fresh, single-use, TTY-typed approval.
