# More reviewed actions: passive HTTP probes — design

**Status:** approved (2026-07-25)

**Goal:** Grow the code-owned action registry with two more L0 passive HTTP
probes, exercising the existing gate → adapter → audit → evidence path with no
new external tool.

**Non-goals:** No new external tools (DNS via `dig` and TLS via `openssl` need
their own tool resolution and lab infrastructure — a later increment); no new
CLI surface; no changes to the reviewed `hackbot.risk` package.

## Context

`hackbot.tools.actions.REAL_ACTIONS` holds `net.http-get` (L0) and `net.http-post`
(L2), both curl-backed and built only when curl resolves. The substrate
(`CommandRunner`, `run_action`, `AuditSink`, `EvidenceStore`, `hackbot tool run`)
and the loopback lab server fixture already exist.

## Design

Add to `_build_actions` (only when curl resolves):

- **`net.http-head`** — `RiskLevel.L0`, `network_access=True`,
  `uses_external_tool=True`, `executable=<curl>`,
  `argv_template=(curl, "-sS", "-I", "--max-time", "10", "{target}")`. A HEAD
  request — response headers only.
- **`net.http-options`** — `RiskLevel.L0`, `network_access=True`,
  `uses_external_tool=True`, `executable=<curl>`,
  `argv_template=(curl, "-sS", "-i", "-X", "OPTIONS", "--max-time", "10", "{target}")`.
  An OPTIONS request — allowed methods. OPTIONS is safe/idempotent, so **not**
  `state_changing` → L0.

Both are `network_access=True`, so `scope.check(target)` is mandatory (lab-only in
practice). They run through the unchanged substrate: gate → render code-owned
argv → `CommandRunner` → audit → redacted evidence.

The shared `local_server` test fixture gains `do_HEAD` and `do_OPTIONS` handlers.

## Error handling

Identical to the existing curl actions: no `ALLOW` → no execution; out-of-scope
target → `DENY_SCOPE`; sanitized env, timeout, output caps, secret-free audit,
redacted evidence.

## Testing strategy (test-first)

- **registry shape**: `net.http-head` and `net.http-options` are registered, L0,
  `network_access`, `uses_external_tool`, curl-backed, argv ends with `{target}`;
  `net.http-options` is not `state_changing`; skip curl-backed assertions when
  curl is absent.
- **end-to-end**: `net.http-head` and `net.http-options` against the loopback lab
  server return `exit_code 0` and capture evidence; an out-of-scope target →
  `DENY_SCOPE`, no execution.
- **Regression**: full suite, Ruff, format, mypy, offline smoke.

## Boundary

Both actions are L0 passive, code-owned, curl-backed, in-scope only, and run only
after an `ALLOW`. No new external tool, no shell, no argv from model/target
content.
