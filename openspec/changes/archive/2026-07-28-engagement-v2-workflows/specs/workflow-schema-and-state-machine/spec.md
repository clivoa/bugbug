## ADDED Requirements

### Requirement: Strict typed workflow schema
A workflow manifest SHALL be a code-owned typed graph of steps, each naming an
action id, bound parameters, typed inputs, typed outputs, explicit evidence
dependencies on prior steps, and a bounded retry limit. A step input SHALL come
only from a typed prior-step output or the confirmed authority; it SHALL NOT come
from raw stdout, stderr, or any target-controlled bytes. A manifest with an
untyped input, a cyclic dependency, an unknown action, or a raw-output input
SHALL fail closed with a stable reason.

#### Scenario: Raw output cannot be a step input
- **WHEN** a step declares its input as another step's raw stdout/stderr
- **THEN** schema validation fails and no workflow is produced

#### Scenario: Cyclic or unknown step is rejected
- **WHEN** the step graph contains a cycle or references an unknown action id
- **THEN** schema validation fails closed

### Requirement: Fresh per-step decision bound to the confirmed workflow
For every step the state machine SHALL create a **fresh** policy v2 decision
against the current confirmed snapshot — re-binding argv, re-validating every
target against scope, and re-checking capabilities, rate, and limits — and SHALL
proceed only on `ALLOW`. A step SHALL NOT inherit a prior step's decision, and the
whole run SHALL bind to the same confirmed workflow projection.

#### Scenario: Each step is decided fresh
- **WHEN** a workflow advances from one step to the next
- **THEN** the next step is evaluated by a new policy decision against the current snapshot, not the prior step's ALLOW

#### Scenario: A step whose target left scope is denied
- **WHEN** a later step's target is no longer in scope
- **THEN** that step is denied and the workflow halts without running it

### Requirement: Workflow binds into the confirmed authority digest
The workflow manifest SHALL be part of the security-relevant authority projection,
so any security-relevant change to the workflow (or the rest of the authority)
SHALL invalidate confirmation with `DENY_AUTHORIZATION_STALE` and require
reconfirmation before autonomous progression resumes.

#### Scenario: Workflow change invalidates confirmation
- **WHEN** the workflow manifest changes in a security-relevant way after confirmation
- **THEN** the recomputed authority digest no longer matches and progression denies with `DENY_AUTHORIZATION_STALE`

### Requirement: Normative retry, replay, cancellation, drift, and cleanup barriers
Retries SHALL be bounded per step and SHALL NOT replay a completed step.
Cancellation SHALL halt progression and run cleanup. A mid-run policy or scope
change (drift) SHALL halt the workflow fail-closed. Each step SHALL re-validate its
targets before running. Resource and target cleanup barriers SHALL complete
(fail-closed) before the next step starts or the workflow finalizes; an incomplete
cleanup SHALL halt progression.

#### Scenario: Policy drift halts the workflow
- **WHEN** the confirmed policy or scope changes mid-run
- **THEN** the workflow halts fail-closed and does not start the next step

#### Scenario: Incomplete cleanup blocks the next step
- **WHEN** a step's resource or target cleanup cannot be confirmed
- **THEN** the workflow halts with an incomplete-cleanup state and does not advance

#### Scenario: A completed step is never replayed
- **WHEN** a workflow retries after a partial failure
- **THEN** an already-completed step is not re-executed

### Requirement: Autonomous progression gated and off until delivered
Autonomous progression SHALL require the `autonomous-progression` capability
enabled in the confirmed `testing_rules`, gated exactly like any other sensitive
capability. Until this workflow capability is loaded, schema v2 SHALL reject
workflow manifests and `autonomous_progression_allowed: true`.

#### Scenario: Progression denied without the capability
- **WHEN** a workflow runs but `autonomous_progression_allowed` is not exactly true
- **THEN** it denies with `DENY_CAPABILITY_NOT_ALLOWED`

#### Scenario: Workflow rejected before this capability is delivered
- **WHEN** a workflow manifest or `autonomous_progression_allowed: true` is loaded without this capability present
- **THEN** it is rejected fail-closed
