## 1. Typed workflow schema

- [ ] 1.1 Add failing tests that a valid workflow manifest produces an immutable typed DAG and that a cycle, unknown action, untyped input, or raw-stdout/stderr-sourced input fails closed with a stable reason.
- [ ] 1.2 Implement `engagement_v2.workflow` schema validation (typed steps/inputs/outputs, evidence dependencies, bounded retries; inputs only from typed prior outputs or authority) until 1.1 passes.

## 2. State machine and fresh per-step decision

- [ ] 2.1 Add failing tests that each step is decided by a fresh P2 policy decision against the current snapshot (no inherited ALLOW), that a step whose target left scope halts the workflow, and that a step reads inputs only from typed prior outputs (never raw output).
- [ ] 2.2 Implement the state machine (`run_workflow`) that re-binds/re-decides/executes per step via P3/P4 on ALLOW and records typed outputs, until 2.1 passes.

## 3. Authority-digest binding and barriers

- [ ] 3.1 Add failing tests that the workflow joins the security-relevant authority projection, so a security-relevant workflow change denies `DENY_AUTHORIZATION_STALE` until reconfirmed.
- [ ] 3.2 Add failing tests for barriers: bounded per-step retry with no replay of a completed step; cancellation halts and cleans up; mid-run policy/scope drift halts fail-closed; an incomplete resource/target cleanup halts progression.
- [ ] 3.3 Implement authority-projection binding and the fail-closed retry/replay/cancellation/drift/cleanup barriers until 3.1–3.2 pass.

## 4. Gating and pre-P6 rejection guard

- [ ] 4.1 Add failing tests that autonomous progression requires `autonomous_progression_allowed` exactly true (else `DENY_CAPABILITY_NOT_ALLOWED`), and a guard proving workflow manifests and `autonomous_progression_allowed: true` are rejected until this capability is loaded.
- [ ] 4.2 Implement the `autonomous-progression` gate wiring and the pre-delivery rejection guard until 4.1 passes.

## 5. Documentation and delivery

- [ ] 5.1 Document the P6 workflow schema and state machine: typed inputs/outputs, the raw-output-never-instruction rule, fresh per-step decision, authority-digest binding, retry/replay/cancellation/drift/cleanup barriers, and the capability gate.
- [ ] 5.2 Run focused P6 tests, the full pytest suite, Ruff check/format, mypy, fixture drift, OpenSpec strict validation, the secret-scan regex over new paths, and `git diff --check`; record fresh outputs.
- [ ] 5.3 Request independent review, resolve findings, update Issue #8/Project fields, and archive the OpenSpec change only after implementation, verification, and merge.
