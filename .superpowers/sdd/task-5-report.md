# Task 5 report — action-bound L2 approval integration

## Scope and commit

Implemented Task 5 only: the policy engine now produces complete L2 challenges,
accepts only exact grants from its bound engagement-local `ApprovalStore`, and
atomically consumes a valid grant once. No CLI, subprocess, provider, token,
target-network, or attack-skill work was added.

Implementation commit: `a26f16148fe566873a599fbe06e36abc9e7b9895`
(`feat: enforce action-bound L2 approvals`).

## Architecture and security properties

- `RiskEngine` runs the complete pure policy preflight before any approval-store
  access. Engagement/authorization, L3, scope, program, argv-template, rate, and
  concurrency denials therefore cannot be overridden by a grant.
- Challenge construction and approval consumption require an explicitly
  injected aware UTC clock. L2 evaluation without a clock fails closed as
  `DENY_APPROVAL_INVALID_CLOCK`; the engine performs no hidden wall-clock read.
- `build_challenge` uses the engine's private pure preflight phase, preventing
  recursive challenge construction and ensuring that no caller-supplied
  `PolicyDecision` or challenge becomes authority.
- A no-grant L2 decision returns the full exact-action challenge. Persistence
  remains separate and trusted: `create_pending` still requires the code-owned
  definition, current request/context, injected clock, and returned nonce.
- For a grant, `ApprovalStore.challenge_for_grant` reads only a strict validated
  local artifact, reuses its original `created_at` and nonce, and rebuilds the
  challenge from the current code-owned definition, request, and policy
  context. It returns a typed challenge, never a raw approval artifact.
- Digest, definition/argv, target, rate, policy, scope, engagement, grant
  metadata, expiry, and state are rechecked. Final authorization requires
  `ApprovalStore.consume`, preserving the Task 4 per-digest lock, WAL,
  no-overwrite rename, fsync, and single-use race guarantees.
- Approval failures become stable `DENY_APPROVAL_*` decisions. Known
  pre-consumption mismatches are audited from the artifact's fixed seven-field
  safe projection without trusting or persisting the altered request.
- Template, scope, program, and L3 denials leave the grant unconsumed. Concurrent
  evaluation with one grant yields exactly one `ALLOW`; all other consumers
  receive `DENY_APPROVAL_CONSUMED`.

## RED / GREEN evidence

- Initial RED:
  `.venv/bin/python -m pytest tests/risk/test_l2_integration.py -q`
  produced 3 failures and 11 setup errors. The missing behaviors were the
  `approval_store` binding, complete L2 challenge, grant consumption, and stable
  denial paths.
- Clock RED: the new no-clock regression initially received
  `REQUIRES_APPROVAL`, proving the hidden wall-clock behavior before it was
  removed; it now receives `DENY_APPROVAL_INVALID_CLOCK`.
- Audit RED: changed target/rate and policy mismatch tests initially observed
  `GRANTED` as the last event. They now append `APPROVAL_MISMATCH` or
  `APPROVAL_POLICY_MISMATCH` using only validated safe artifact fields.
- Focused GREEN:
  `.venv/bin/python -m pytest -o addopts='' tests/risk/test_l2_integration.py
  tests/risk/test_policy.py tests/risk/test_approvals.py -q -ra`
  — `355 passed in 1.88s`.
- Full GREEN:
  `.venv/bin/python -m pytest -o addopts='' -q -ra`
  — `643 passed in 4.05s`.
- Static and formatting gates:
  `ruff check src/hackbot/risk tests/risk`,
  `ruff format --check src/hackbot/risk tests/risk`,
  `mypy src/hackbot/risk`, and `git diff --check` all passed.

## Coverage highlights

The new integration suite covers complete challenges, no-store challenge
creation, deterministic missing-clock denial, exact allow-once, replay,
concurrent consumers, otherwise-authorized target/rate changes, code-owned
definition/argv changes, malformed argv precedence, scope/program/L3
precedence, policy and engagement changes, expiry transition, missing grants,
missing approval store, and mismatch audit events.

## Review remediation — canonical payload confidentiality

Remediation commit: `012525bf2537eef5cb2a2019145bfec997e89297`
(`fix: reject secrets in canonical approval payload`).

Review reproduced a scope URL containing credential userinfo being accepted and
copied into `challenge.binding`. Root-cause tracing showed that the early
secret filter covered request fields only; `_challenge_fields` subsequently
added the code-owned definition, program/engagement metadata, and full in/out
scope snapshot before serializing them without another confidentiality check.

The fix recursively screens the complete would-be canonical `fields` mapping
immediately before `canonical_bytes`. The existing early request filter remains,
so no authority, preflight ordering, or persisted schema changed. TestingPolicy
continues to be bound only by its digest and is not copied into the artifact.

RED evidence:

- Scope userinfo in both `in_scope` and `out_of_scope`, secret-like `program_id`
  and code-owned `tool_id`, engine reason mapping, and pending-store leakage
  checks produced six expected failures.
- The engine returned `REQUIRES_APPROVAL` instead of
  `DENY_APPROVAL_SECRET`, and direct challenge construction did not raise.
- Safe ordinary scope and digest-only policy controls already passed, proving
  that the reproduction isolated canonical fields outside the request.

GREEN evidence after the one-line production fix:

- New confidentiality selection: `8 passed, 292 deselected`.
- Entire approval suite: `300 passed in 1.54s`.
- Task 5 focused suites: `363 passed in 1.83s`.
- Full suite: `651 passed in 4.39s`.
- Risk-package Ruff check/format, mypy, and `git diff --check` passed.

The regressions verify stable `APPROVAL_SECRET` /
`DENY_APPROVAL_SECRET`, value-free errors, no pending or audit file containing
the rejected secret, safe ordinary scope rules, sensitive request-header
coverage, definition/tool metadata coverage, program metadata coverage, and
that non-persisted policy text remains represented only through
`policy_digest`.
