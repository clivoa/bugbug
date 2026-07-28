# Engagement v2 workflow schema and autonomous state machine (P6)

**Status:** implemented on `feat/engagement-v2-workflows-impl`.

P0–P4 gate and run **single** actions; P5a/P5b specify action catalogs. The
authority model permits autonomous progression in principle, but until P6 schema
v2 rejects workflow manifests and `autonomous_progression_allowed: true` because a
prose list of dependencies is not an executable safety contract. P6 is that
contract: a strict, code-owned workflow schema and a state machine that
orchestrates existing gated actions with a **fresh decision per step** and hard
barriers. A workflow is a typed graph, not an LLM choosing steps from output;
**raw tool output can never become an instruction, argv token, target, or
capability.**

## Public interfaces

`hackbot.engagement_v2.workflow`

- `validate_workflow(document, registry, *, capability_available=True)
  -> WorkflowDefinition` — decode a workflow manifest into an immutable typed DAG.
  Each step names an `action_id` (must exist in the registry), literal bound
  `parameters`, literal scope-checked `targets`, typed `inputs`, typed `outputs`,
  explicit `depends_on` evidence dependencies, and a bounded `retry_limit`.
- `run_workflow(workflow, snapshot, registry, *, platform,
  confirmed_workflow_digest, step_executor, cancel=None) -> WorkflowResult` — the
  state machine. `step_executor` is the P3/P4 executor seam; `cancel` is an
  optional cooperative cancellation callback. `WorkflowResult` carries the run
  status (`completed` / `halted` / `cancelled`), the halt reason, the completed
  step ids, and a per-step record.
- `workflow_authority_digest(authority_digest, projection)` — bind a workflow
  projection into the confirmed authority digest (a dedicated domain tag).
- `guard_workflow_manifest` / `guard_autonomous_progression` — the pre-delivery
  guards; `workflow_capability_available()` reports whether P6 is present.

## Typed inputs and outputs (the raw-output-never-instruction rule)

- A step **input** is either a manifest literal (`{from_value: …}`, which is part
  of the workflow projection and therefore confirmed authority) or a typed prior
  step output (`{from_step: …, output: …}`). No other source shape is accepted.
- A step **output** is drawn only from a **code-owned structured-result
  whitelist** (`exit_code`, `executed`, `timed_out`, and the two cleanup statuses)
  — never `stdout`, `stderr`, or any other target-controlled bytes. An output that
  names a raw source, an untyped input/output, an unknown action, a cyclic or
  forward dependency, or a required parameter left unbound fails closed with
  `INVALID_WORKFLOW_MANIFEST`.
- Consequence: a later step can never consume an earlier step's raw output, and
  discovery output can never expand scope (targets are manifest literals,
  re-validated fresh every step).

## Fresh per-step decision and authority-digest binding

- For every step the state machine creates a **new** P2 `decide` against the
  current confirmed snapshot — re-binding argv, re-validating every target against
  scope v2, and re-checking capabilities/rate/limits — and proceeds only on
  `ALLOW`. No step inherits a prior step's decision. A step whose target has left
  scope is denied and the workflow halts without running it.
- The workflow projection joins the confirmed authority digest, so any
  security-relevant change to the workflow (or the rest of the authority)
  recomputes a different digest and halts progression with
  `DENY_AUTHORIZATION_STALE` until reconfirmed — the same mechanism P1 uses for
  scope/policy/runner. Mid-run authority drift is detected before each step.

## Fail-closed barriers

- **Retry / replay:** retries are bounded per step (`retry_limit`) and a completed
  step is never re-executed; only a step that executed-but-failed is retried.
- **Cancellation:** a cooperative cancel halts progression before the next step.
- **Drift:** a mid-run policy or scope change halts the workflow fail-closed
  (`DENY_AUTHORIZATION_STALE`, or a fresh P2 `DENY` when a target leaves scope).
- **Cleanup:** resource and target cleanup must be `complete`/`not-required`
  before the next step; an incomplete cleanup halts with
  `CLEANUP_RESOURCE_INCOMPLETE` / `CLEANUP_TARGET_INCOMPLETE`.

## Capability gate and pre-P6 rejection

- Autonomous progression requires `autonomous_progression_allowed` **exactly
  true** in the confirmed `testing_rules`; otherwise `run_workflow` halts with
  `DENY_CAPABILITY_NOT_ALLOWED`, re-checked fresh for every step.
- The workflow module's presence **is** the capability. Until it is loaded,
  `guard_workflow_manifest` rejects workflow manifests and
  `guard_autonomous_progression` rejects `autonomous_progression_allowed: true`
  (`INVALID_AUTONOMOUS_PROGRESSION`) at load time; the loader wires the guard so a
  build without P6 continues to reject autonomous progression.

## Non-goals

P6 adds no action, executor, secret, remote, or catalog primitive; it orchestrates
existing gated actions above the unchanged P2/P3/P4 path. There is no per-step
human approval and no loosening of the gate — the state machine only adds
barriers. There is no model-in-the-loop planning.
