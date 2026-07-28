## Context

P0–P4 gate and run single actions; P5a/P5b specify action catalogs. The authority
model allows autonomous progression in principle, but schema v2 rejects workflow
manifests and `autonomous_progression_allowed: true` until a real safety contract
exists. P6 is that contract: a strict workflow schema and a state machine that
orchestrates existing gated actions with a fresh decision per step and hard
barriers, never letting untrusted tool output steer execution.

## Goals / Non-Goals

**Goals:**

- A code-owned typed workflow schema (steps, typed inputs/outputs, evidence
  dependencies, bounded retries) where inputs come only from typed prior outputs
  or the confirmed authority, never raw output.
- A state machine that creates a fresh per-step policy decision, re-validates
  scope, and binds to the confirmed workflow projection.
- Bind the workflow into the confirmed authority digest; drift invalidates.
- Normative retry/replay/cancellation/policy-drift/target-revalidation/cleanup
  barriers.
- Keep autonomous progression off (rejected) until this is delivered and gate it
  behind the `autonomous-progression` capability.

**Non-Goals:**

- No new action/executor/secret/remote/catalog primitive; P6 orchestrates.
- No per-step human approval; no gate loosening.
- No model-in-the-loop planning; a workflow is a typed graph, not an LLM choosing
  steps from output.

## Decisions

### 1. A workflow is a typed DAG validated by a code-owned schema

`workflow.py` defines an immutable `WorkflowDefinition`: ordered steps, each with
an `action_id`, bound parameters, typed input bindings (from a prior step's typed
output or an authority value), typed outputs, evidence dependencies, and a retry
limit. Validation rejects cycles, unknown actions, untyped inputs, and any input
sourced from raw stdout/stderr. The schema is validated with the same hardened
decode and strict primitive model as P1/P2.

Alternative considered: free-form step scripts. Rejected — that is exactly the
untrusted-output-as-instruction hazard the contract forbids.

### 2. The state machine decides every step fresh

`run_workflow(...)` walks the DAG; for each ready step it calls P2 `decide` against
the **current** confirmed snapshot (re-binding argv, re-validating every target via
scope v2, re-checking capabilities/rate/limits), executes via P3/P4 only on
`ALLOW`, and records the typed outputs. No step inherits a prior ALLOW. The run
binds to the confirmed workflow projection; a step reads inputs only from typed
prior outputs (structured results), never from raw stdout/stderr.

### 3. The workflow joins the authority digest

The workflow manifest is added to the P1 security-relevant authority projection,
so confirmation covers it. A security-relevant workflow change recomputes a
different `authority_digest` and denies `DENY_AUTHORIZATION_STALE` until
reconfirmed — the same mechanism P1 uses for scope/policy/runner.

### 4. Barriers are fail-closed and drift halts

Retries are per-step bounded and never replay a completed step (idempotent
step-completion record). Cancellation halts and runs cleanup. A mid-run policy or
scope change (detected by re-decision and by an authority-digest re-check) halts
fail-closed. Resource/target cleanup barriers (P3) must complete before advancing;
an incomplete cleanup halts with the P3 incomplete state.

### 5. Autonomous progression stays gated

`autonomous-progression` maps to `autonomous_progression_allowed`; the P2 gate
requires it exactly true. Until this capability module is present, a guard rejects
workflow manifests and `autonomous_progression_allowed: true` (the pre-P6
invariant), and a test proves the rejection.

## Risks / Trade-offs

- Untrusted output steering execution → step inputs are typed and sourced only
  from prior typed outputs/authority; a schema test rejects raw-output inputs.
- A step running on a stale decision → every step re-decides against the current
  snapshot; a test proves no inherited ALLOW and that a target leaving scope halts.
- Workflow change bypassing confirmation → the workflow is in the authority digest;
  a drift test asserts `DENY_AUTHORIZATION_STALE`.
- Replay of a completed step on retry → an idempotent completion record; a retry
  test asserts no re-execution.
- Cleanup skipped between steps → cleanup barriers are fail-closed; an
  incomplete-cleanup test asserts the workflow halts.

## Migration Plan

1. Add the workflow schema, projection binding, and state-machine modules; add the
   `autonomous-progression` capability wiring in the P2 gate path.
2. Add tests (schema, fresh-decision, digest binding, drift/retry/replay/
   cancellation/cleanup barriers, raw-output-never-input) and the
   still-rejected-until-loaded guard.
3. Verify, request independent review, merge, and archive; only then does
   `autonomous_progression_allowed: true` become acceptable under the gate.

Rollback removes the workflow modules and reverts to the pre-P6 rejection of
workflow manifests and autonomous progression. No persisted state migrates.

## Open Questions

None blocking. The authority/scope/policy/cleanup contracts are fixed by P1–P3;
the untrusted-output rule by CLAUDE.md. The exact retry/step bounds are fixed as
normative constants in this change's schema.
