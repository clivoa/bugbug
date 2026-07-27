## Why

P0 froze the action/execution contracts and P1 delivered the confirmed
engagement snapshot and typed scope, but nothing yet turns an operator action
manifest into a bound, policy-approved command. Until a strict `actions.yaml`,
a typed binder, and a direct v2 policy exist, there is no safe way to decide
whether a concrete action may run and to produce the exact argv it would run —
and P3 (the executor) has nothing to execute. P2 delivers that decision layer
while executing nothing itself.

## What Changes

- Add a strict **operator action manifest** (`actions.yaml`) loader that
  validates every action against the archived P0 `action-execution-contracts`:
  identifiers and bounds, absolute executables, platform/architecture/privilege
  enums, typed parameters, declared characteristics/capabilities, evidence
  modes, rate-control modes, and `hackbot-safe-fullmatch-v1` patterns. A manifest
  that violates any contract fails closed with the exact P0 reason.
- Add a **typed binder** that materializes an action request v2 into a concrete
  argv by binding only whole-token placeholders (`{value:id}`, `{target:id}`,
  `{targets_file:id}`, `{artifact_file:id}`, `{secret_file:id}`) to typed,
  validated parameters and scope-checked targets. `argv[0]` SHALL exactly equal
  the selected absolute executable path. The binder never accepts a
  request-supplied argv and never introduces an implicit shell; `shell_execution`
  and interpreter inline-eval forms are L3 and rejected. Secret placeholders are
  bound as references only and are **not** resolved here (P3 resolves them).
- Add a **policy v2** decision engine returning a direct `ALLOW` or a stable
  `DENY_*`, with **no per-action approval** (`REQUIRES_APPROVAL` is never
  returned for v2). It follows a deterministic, deny-wins decision order:
  validate frozen engagement/registry, require confirmed authorization, bind and
  type-check parameters, infer the effective risk level and required
  capabilities, validate **every** target against scope, apply prohibited
  tools/vulnerability-types/excluded-impacts, then apply capability, rate,
  concurrency, target-count, timeout, header, source-identity, and
  restricted-hour rules. A missing or non-`true` sensitive-capability field
  denies; an unenforceable finite rate denies with `DENY_RATE_UNENFORCEABLE`.
- Enforce **all-target** semantics: every member of a target list is checked
  before any binding output is produced, and one malformed, duplicate-conflicting,
  excluded, or out-of-scope target denies the whole action — never a silently
  filtered subset.
- Guarantee **profile-independent determinism**: identical materialized
  authority and request produce an identical decision; a profile name grants no
  capability by itself.
- Preserve schema v1 behavior and the existing v1 L2 approval model. P2 consumes
  the P1 loader/scope; it does not modify them and it executes nothing.

Non-goals:

- No subprocess execution or local executor (P3), secret resolution, private
  working directory, evidence writing, or cleanup runtime (P3).
- No SSH transport or remote helper (P4), autonomous workflows (P6), or
  effective migration (P7).
- No change to the v1 risk engine, v1 approval store, or v1 CLI behavior.

## Capabilities

### New Capabilities

- `action-manifest`: Strict `actions.yaml` loading and validation of operator
  actions against the P0 action-execution contracts, failing closed with exact
  reasons.
- `action-binder`: Typed, whole-token materialization of an action request into
  a concrete argv with `argv[0]` equal to the selected absolute executable, no
  implicit shell, and no request-supplied argv.
- `policy-v2`: Deterministic, deny-wins, profile-independent `ALLOW`/`DENY_*`
  decisions with a sensitive-capability gate, rate enforceability, and all-target
  scope checks, and no per-action approval.

### Modified Capabilities

None. P2 consumes the archived P0 contracts (`action-execution-contracts`,
`engagement-authority-contracts`) and the P1 `engagement-v2-loader`/`scope-v2`
capabilities without changing their requirements, and does not alter the v1
capabilities.

## Impact

- New code under `src/hackbot/engagement_v2/` (manifest, binder, policy modules)
  importing the P0 contract package and the P1 loader/scope.
- New unit and property tests under `tests/engagement_v2/` plus deterministic
  synthetic `actions.yaml` and request fixtures under
  `tests/fixtures/engagement_v2_loader/` (or a sibling fixture root).
- The P1 v2-consumer allowlist guard is extended to the declared P2 modules; no
  v1 module imports the v2 package and the default CLI path stays inert.
- No new runtime dependency; no change to any v1 CLI command or the v1 risk
  engine.

Architecture and review sources:

- `docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`
- `docs/reviews/2026-07-27-engagement-v2-p0-contracts-review-disposition.md`
  (forward-carry N2: the binder binds `argv[0]` to the executable path)
- `openspec/specs/action-execution-contracts/spec.md`
- `openspec/specs/engagement-authority-contracts/spec.md`
- GitHub delivery: Issue #3.
