## 1. Action manifest loader

- [x] 1.1 Add failing tests for a valid `actions.yaml` producing an immutable registry, and for manifest violations (over 256 actions, bad identifier, out-of-range parameter bound, unknown capability, non-absolute executable) each mapping to their exact P0 reason code.
- [x] 1.2 Add failing tests for the executable/shell/interpreter/elevation contract (interpreter inline-eval rejected unless declared L3; elevation basename as argv[0] always rejected; case rules).
- [x] 1.3 Add failing tests for rate-control declaration (argv-placeholder requires rate+concurrency params; missing mode on a finite-rate network action rejected).
- [x] 1.4 Implement `engagement_v2.manifest` (hardened decode + P0-contract validation, frozen `ActionDefinition`/registry) until 1.1–1.3 pass.

## 2. Typed binder

- [x] 2.1 Add failing tests: a bound argv is produced from the template; `argv[0]` equals the absolute executable byte-for-byte and cannot be request-controlled.
- [x] 2.2 Add failing tests for injection resistance: request-supplied argv rejected (`INVALID_REQUEST`); partial-token placeholder rejected (`INVALID_PLACEHOLDER`); shell execution / interpreter inline-eval rejected.
- [x] 2.3 Add failing tests for typed binding: out-of-bound/enum/pattern parameter rejected (`INVALID_REQUEST`); `{secret_file:id}` bound as an unresolved reference; targets bound only after scope validation.
- [x] 2.4 Implement `engagement_v2.binder` (whole-token materialization, argv[0]=executable, secret references) until 2.1–2.3 pass.

## 3. Policy v2 decision engine

- [x] 3.1 Add failing tests for the fixed deny-wins order and outcomes: fully permitted → ALLOW (no secret/resource); unconfirmed authorization → `DENY_AUTHORIZATION_UNCONFIRMED` before target/capability work; `REQUIRES_APPROVAL` never returned.
- [x] 3.2 Add failing tests for the sensitive-capability gate: absent field, `false`, and non-boolean each deny `DENY_CAPABILITY_NOT_ALLOWED`; all-true passes the gate.
- [x] 3.3 Add failing tests for all-target scope: one out-of-scope/excluded/duplicate/malformed target denies the whole action with the offending target's scope reason and prepares no partial execution.
- [x] 3.4 Add failing tests for rate enforceability (`DENY_RATE_UNENFORCEABLE`), other numeric limits (`DENY_POLICY_LIMIT`), and effective-level max (a request cannot lower the inferred level).
- [x] 3.5 Add failing tests for profile-independent determinism: two engagements differing only by profile name with identical materialized rules yield identical decisions.
- [x] 3.6 Implement `engagement_v2.policy` (pure `decide(...)`, deny-wins order, stable reasons) until 3.1–3.5 pass.

## 4. Isolation, fixtures, and documentation

- [x] 4.1 Extend the P1 v2-consumer allowlist guard to the declared P2 modules and add a guard test asserting the P2 modules make no subprocess/secret/socket call (P2 executes nothing).
- [x] 4.2 Add deterministic synthetic `actions.yaml` and request fixtures (no real target or credential material) with a regenerate/check tool proving reproducible bytes.
- [x] 4.3 Document the P2 public manifest/binder/policy interfaces, the decision order and stable reasons, and the fact that P2 decides and binds but executes nothing.

## 5. Verification and delivery

- [x] 5.1 Run focused P2 tests, the full pytest suite, Ruff check/format, mypy, schema/fixture drift, OpenSpec strict validation, the secret-scan regex over new paths, and `git diff --check`; record fresh outputs.
- [ ] 5.2 Request independent review, resolve findings, update Issue #3/Project fields, and archive the OpenSpec change only after implementation, verification, and merge. Independent review complete; all nine findings resolved with tests and spec scenarios — disposition in `docs/reviews/2026-07-27-engagement-v2-p2-actions-policy-review-disposition.md`. Remaining: P1 merge, then rebase, PR, merge, archive.
