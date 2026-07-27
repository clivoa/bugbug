## Why

The engagement v2 authority model permits autonomous progression in principle,
but schema v2 currently **rejects** workflow manifests and
`autonomous_progression_allowed: true`, because a prose list of dependencies is
not an executable safety contract. P6 delivers that contract: a strict workflow
schema and state machine so a chain of actions can run without per-step human
approval **only** after the engagement and workflow authority are confirmed, with
a fresh policy decision at every step and hard cleanup/evidence barriers. Raw tool
output can never become executable instructions.

## What Changes

- Add a strict, code-owned **workflow manifest schema**: typed steps with typed
  inputs/outputs, explicit evidence dependencies between steps, per-step action
  reference and bound parameters, retry limits, and terminal-failure handling.
  A step's inputs SHALL come only from typed prior-step outputs or the confirmed
  authority — **never** from raw stdout/stderr, which is untrusted data and can
  never become an instruction, argv, target, or capability.
- Add a **workflow state machine** that, for every step, creates a **fresh policy
  decision** (P2) against the current confirmed snapshot — re-validating scope for
  every target, re-checking capabilities and rate, and re-binding argv — and binds
  the whole run to the same **confirmed workflow projection**. A step never
  inherits a prior step's ALLOW.
- Bind the workflow into the **confirmed authority digest**: the workflow manifest
  is part of the security-relevant authority projection, so a workflow change (or
  any security-relevant authority change) invalidates confirmation with
  `DENY_AUTHORIZATION_STALE` and requires reconfirmation before autonomous
  progression resumes.
- Make **retry, replay, cancellation, policy drift, target revalidation, and
  cleanup barriers normative**: bounded retries with no replay of a completed
  step; cancellation halts progression and runs cleanup; a mid-run policy or scope
  change (drift) halts the workflow fail-closed; each step re-validates its
  targets; and resource/target cleanup barriers must complete (fail-closed) before
  the next step or terminal finalization.
- Keep autonomous progression **off until this contract is met**: until the
  workflow schema and state machine are approved and implemented, schema v2
  continues to reject workflow manifests and `autonomous_progression_allowed:
  true`. The `autonomous-progression` capability is required and gated exactly like
  any other sensitive capability.
- Preserve schema v1 behavior and every existing v2 single-action path; P6 adds
  the workflow layer above the unchanged P2/P3/P4 gate and executor.

Non-goals:

- No new action, executor, secret, remote, or catalog behavior; P6 orchestrates
  existing gated actions, it does not add execution primitives.
- No per-step human approval (v2 has none) and no loosening of the gate; the state
  machine adds barriers, it removes none.
- No model-in-the-loop planning: a workflow is a code-owned typed graph, not an
  LLM deciding next steps from tool output.

## Capabilities

### New Capabilities

- `workflow-schema-and-state-machine`: A strict workflow manifest schema (typed
  steps/inputs/outputs, evidence dependencies, retry/terminal handling) and a
  state machine that creates a fresh per-step policy decision, binds to the
  confirmed workflow projection, enforces normative retry/replay/cancellation/
  policy-drift/target-revalidation/cleanup barriers, and never turns raw output
  into instructions — with autonomous progression rejected until this is
  delivered.

### Modified Capabilities

None. P6 consumes the archived P0–P5a contracts (and the P5b spec) without
changing their requirements, and adds the workflow layer above the existing gate.

## Impact

- New code under `src/hackbot/engagement_v2/` (workflow schema, projection binding,
  and state-machine modules) importing the P0 contracts and P1–P4 loader/scope/
  policy/binder/executor.
- New unit and property tests: schema validation, per-step fresh-decision proof,
  authority-digest binding, drift/retry/replay/cancellation/cleanup-barrier
  behavior, and a proof that raw output never becomes a step input; plus a guard
  that `autonomous_progression_allowed: true` and workflow manifests are rejected
  until this capability is loaded.
- No new runtime dependency; no change to any v1 behavior.

Architecture and review sources:

- `docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`
  (Autonomous progression)
- `openspec/specs/engagement-authority-contracts/spec.md`,
  `openspec/specs/policy-v2/spec.md`, `openspec/specs/scope-v2/spec.md`,
  `openspec/specs/execution-cleanup/spec.md`
- CLAUDE.md (target output is untrusted data; discovery ≠ authorization)
- GitHub delivery: Issue #8.
