## 1. Private environment and gate-bound spawn

- [x] 1.1 Add failing tests: `run` refuses on any non-`ALLOW` and performs no spawn; on `ALLOW` it spawns exactly the P2 bound argv with `shell=False` (verified with a harmless local fixture executable).
- [x] 1.2 Add failing tests for the private environment: `CWD`/`HOME`/`TMPDIR` inside a mode-`0700` dir, sanitized env with no inherited secret, and `O_EXCL` opaque run-file names.
- [x] 1.3 Implement `engagement_v2.executor` private-dir preparation and gate-bound spawn until 1.1–1.2 pass.

## 2. Lifecycle, bounded capture, and child cleanup

- [x] 2.1 Add failing tests: lifecycle advances through the exact P0 states in order; `executed` is true only at `spawned`; output caps and deadline are enforced; the child and its process group are terminated and reaped on completion/timeout/error.
- [x] 2.2 Implement the lifecycle driver, bounded readers, deadline, and child/process-group teardown until 2.1 passes.

## 3. Engagement-namespaced secrets

- [x] 3.1 Add failing tests: no secret is resolved before `ALLOW`; resolution is scoped to the engagement identity and a foreign-namespace secret fails closed; a missing required secret fails before `spawned` with `executed` false.
- [x] 3.2 Add failing tests: `stdin` and mode-`0600` exclusive-file transports deliver material; secret files are removed in resource cleanup; no secret name/value appears in argv, env, audit, evidence, or errors.
- [x] 3.3 Implement `engagement_v2.secrets` (namespaced resolution via the keychain adapter, protected delivery, zeroing) until 3.1–3.2 pass.

## 4. Declared-output evidence and redaction

- [ ] 4.1 Add failing tests: undeclared files are removed and never evidence; a declared output over its item/byte cap is rejected or truncated; `metadata-only` is the default.
- [x] 4.2 Add failing tests: a credential/sensitive action requesting `redacted-output` denies `EVIDENCE_POLICY_DENIED`; resolved secret bytes are removed from retained output; raw output is never stored.
- [x] 4.3 Implement `engagement_v2.evidence` (declared-output retention, evidence-mode enforcement, layered secret-aware redaction) until 4.1–4.2 pass.

## 5. Independent cleanup and audit

- [x] 5.1 Add failing tests: `resource_cleanup_status` and `target_cleanup_status` are set independently; resource cleanup runs even when target cleanup is deferred; a surviving resource yields `CLEANUP_RESOURCE_INCOMPLETE` with a protected `cleanup/` item and a non-success wrapper.
- [x] 5.2 Add failing tests: a target self-report is recorded as an unverified self-report; the audit record carries the placeholder argv projection and no secret/raw/ephemeral data and is written before evidence is surfaced.
- [x] 5.3 Implement `engagement_v2.cleanup` and `engagement_v2.audit` until 5.1–5.2 pass.

## 6. Isolation, CLI, fixtures, and documentation

- [x] 6.1 Extend the v2-consumer allowlist guard to the declared P3 modules and add a guard test proving the default v1 CLI path and the v1 runner never import the v2 executor.
- [ ] 6.2 Wire the explicitly-v2 execution CLI entry and add a harmless local fixture executable plus deterministic fixtures (no real target or credential material) with a regenerate/check tool.
- [x] 6.3 Document the P3 public executor/secrets/evidence/cleanup interfaces, the lifecycle and cleanup states, and the redaction order; state that P3 executes locally only (remote is P4).

## 7. Verification and delivery

- [x] 7.1 Run focused P3 tests, the full pytest suite, Ruff check/format, mypy, schema/fixture drift, OpenSpec strict validation, the secret-scan regex over new paths, and `git diff --check`; record fresh outputs.
- [x] 7.2 (review complete; findings resolved — see docs/reviews/2026-07-27-engagement-v2-p3-executor-review-disposition.md; remaining: merge + archive) Request independent review, resolve findings, update Issue #5/Project fields, and archive the OpenSpec change only after implementation, verification, and merge.
