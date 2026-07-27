## Context

P0 froze the action/execution contracts (identifiers, bounds, executable and
shell/interpreter/elevation rules, typed parameters, placeholder grammar,
evidence and rate-control modes, safe patterns). P1 delivered the confirmed,
immutable engagement snapshot and the typed default-deny scope engine. P2 is the
first phase that turns an operator's action manifest into a bound, policy-decided
command — and it is the last safety gate before P3 executes anything.

P2 must remain a pure decision layer: it loads and validates `actions.yaml`,
binds a request into a concrete argv, and returns `ALLOW`/`DENY_*`. It resolves
no secret, opens no socket, and spawns no child. The operator is trusted to
declare arbitrary-tool semantics; the manifest, request parameters, and targets
are untrusted until validated, and P2 never proves that the chosen executable
actually honors its declared behavior.

Trust boundary note (P0 review forward-carry N2): the binder is the component
that binds `argv[0]` to the selected absolute executable path. No consumer may
assume P0 already enforced it.

## Goals / Non-Goals

**Goals:**

- Load and strictly validate `actions.yaml` against the P0 contracts, failing
  closed with exact reasons.
- Bind a request into a concrete argv from a code-owned template only, with
  `argv[0]` equal to the absolute executable, no implicit shell, and no
  request-supplied argv.
- Decide `ALLOW`/`DENY_*` deterministically and deny-wins, with a
  sensitive-capability gate, rate enforceability, all-target scope checks, and
  profile-independent determinism.
- Keep the core dependency-free, consume (not modify) P0 and P1, and execute
  nothing.

**Non-Goals:**

- No subprocess execution/local executor (P3), secret resolution or private
  working directory or evidence or cleanup (P3), SSH/remote helper (P4),
  autonomous workflows (P6), or effective migration (P7).
- No per-action approval and no change to the v1 risk engine, v1 approval store,
  or v1 CLI.
- No claim that a declared capability, rate strategy, or executable semantics are
  independently proven.

## Decisions

### 1. Manifest loader reuses P0 primitives and the P1 hardened decode

`actions.yaml` is decoded through the same hardened, alias/merge/tag-free,
duplicate-rejecting path P1 uses, then validated field-by-field against the P0
constants (bounds, enums, identifier/pattern grammar, executable and
shell/interpreter/elevation tables). Every rejection surfaces an exact P0
`ReasonCode` (`INVALID_ACTION_MANIFEST` and the specific `INVALID_*`). The
registry is an immutable mapping of action id to a frozen `ActionDefinition`.

Alternative considered: a JSON-schema validator over the generated P0 schemas.
Rejected to keep the core dependency-free and because Python validation already
owns the exact constants.

### 2. The binder is the argv authority

The binder takes a frozen `ActionDefinition` and a typed, already-scope-checked
request and renders the argv purely from the action's `argv_template`. Each token
is either a literal from the template or a single whole-token placeholder bound
to one typed value. `argv[0]` is set to the action's absolute executable and can
never be templated or request-controlled. Secret placeholders become opaque
`SecretReference` tokens (resolved only by P3). A request can never inject argv,
a shell, or an interpreter inline-eval form.

Alternative considered: let the request pass extra argv for flexibility.
Rejected — it is exactly the injection surface the contract forbids.

### 3. Policy is a pure function with a fixed order

`decide(request, snapshot, registry, now) -> PolicyDecision` follows the fixed
deny-wins order (validate → confirmed authorization → parameter typing → risk and
capability inference → per-target scope → prohibited/excluded lists → numeric and
contextual limits → ALLOW/DENY). It reads only the materialized snapshot and
request, so identical materialized inputs yield identical decisions regardless of
profile name. `REQUIRES_APPROVAL` is never produced for v2. The decision reason
is a stable string: P0 `DENY_*`/`INVALID_*` codes for contract, capability, rate,
and limit denials, and the offending target's P1 `ScopeDenyReason` for a
target-scope denial.

Alternative considered: reuse the v1 `RiskEngine`. Rejected because the v1 engine
encodes the L2-approval model and different scope/authority types; v2 is a
separate, approval-free decision.

### 4. All-target semantics precede any output

Every target is validated before the binder produces argv or a targets file.
A single malformed, duplicate-conflicting, excluded, or out-of-scope target
denies the whole action; the engine never runs a filtered subset. A CIDR
authorized as one target stays one argv line (no member enumeration for argv);
tool-side expansion is a manifest characteristic that raises the inferred level.

### 5. Capability gate is exact-boolean and additive

Each required capability maps to its canonical `testing_rules` boolean, which
must be exactly `true`. Absent, `false`, or non-boolean denies
`DENY_CAPABILITY_NOT_ALLOWED`. Multiple capabilities require all corresponding
fields true. The effective risk level is `max(declared, inferred, requested)`
and a request can never lower it; levels are classification/audit only.

## Risks / Trade-offs

- Manifest breadth could recreate the whole executor in P2 → Keep P2 pure: it
  validates, binds, and decides, but never executes; a guard test asserts no
  subprocess/secret/socket call exists in the P2 modules.
- A placeholder-binding bug could enable argv injection → Enforce whole-token
  placeholders, `argv[0]` == executable, and per-token byte bounds, with negative
  tests for partial-token, request-argv, and shell/interpreter forms.
- Silent subset execution on a partly out-of-scope target list → All-target
  check before any output, asserted by a one-bad-target test.
- Non-determinism from profile-derived defaults → The decision is a pure function
  of materialized inputs; a two-profile identical-rules test asserts identical
  decisions.
- Reason-code drift with P0/P1 → P2 imports the P0 `ReasonCode` and P1
  `ScopeDenyReason`; a test maps each denial path to its exact reason.

## Migration Plan

1. Add manifest, binder, and policy modules under `src/hackbot/engagement_v2/`,
   importing only the P0 package, the P1 loader/scope, and the standard library.
2. Add synthetic `actions.yaml`/request fixtures and tests; extend the P1
   v2-consumer allowlist guard to the P2 modules.
3. Verify (full suite, ruff/format, mypy, schema/fixture drift, OpenSpec strict,
   secret scan, `git diff --check`), request independent review, merge, archive.

Rollback is deletion of the P2 modules, fixtures, and tests and reverting the
guard allowlist. P2 persists no runtime state and executes nothing, so rollback
migrates no data.

## Open Questions

None. Exact bounds, enums, grammars, and reason codes are fixed by the archived
P0 contracts; scope decisions reuse the P1 closed reason set; the capability and
decision-order rules are fixed by the delta specs in this change. Secret
resolution and execution remain P3.
