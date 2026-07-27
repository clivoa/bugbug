# Engagement v2 local executor, secrets, evidence, cleanup (P3)

**Status:** implemented on `feat/engagement-v2-executor`.

P3 is the first phase that actually spawns a child. It executes only the P2 bound
argv, only after a policy `ALLOW`, with `shell=False`, inside a private sanitized
environment, with engagement-namespaced secrets, conservative redacted evidence,
and independent fail-closed cleanup. **P3 executes locally only** — remote
execution is P4.

## Public interfaces

`hackbot.engagement_v2.executor`

- `run(bound, action, snapshot, decision, *, secret_backend, base_dir, …)
  -> ExecutionResult` — gate-bound local execution. It refuses (no spawn) on any
  non-`ALLOW` decision, prepares a private mode-0700 directory used as
  `CWD`/`HOME`/`TMPDIR` with a sanitized environment, resolves secrets, spawns the
  bound argv, captures bounded output under a deadline, finalizes evidence, and
  cleans up. `ExecutionResult` carries the lifecycle state, `executed`, exit code,
  timeout flag, evidence, both cleanup statuses, and a secret-free audit record.

`hackbot.engagement_v2.secrets`

- `resolve_secret(backend, engagement_identity, name)` /
  `namespaced_key(identity, name)` — resolve a secret only within the engagement
  namespace (`engagement-secret/<identity>/<name>`); a reference under a different
  engagement fails closed. `write_protected_file` writes a mode-0600 exclusive
  file with an opaque name.

`hackbot.engagement_v2.evidence`

- `check_evidence_mode(mode, capabilities, *, output_persistence_allowed)` —
  `metadata-only` is the default; `redacted-output` requires policy permission and
  is denied (`EVIDENCE_POLICY_DENIED`) for credential/sensitive capabilities.
- `redact(data, secret_values)` — replaces resolved secret bytes, then applies the
  structural/pattern redactor.

## Safety properties

- **Gate-bound:** the child is spawned only when the P2 decision is `ALLOW`, and
  only the exact bound argv (`shell=False`). A non-`ALLOW` decision creates no run
  resources.
- **Private, sanitized environment:** a mode-0700 directory is `CWD`/`HOME`/
  `TMPDIR`; the child environment is a minimal allowlist with no inherited operator
  or host secret; run files are `O_EXCL` with opaque numeric names.
- **Late, namespaced secrets:** secrets are resolved only after `ALLOW`, only in
  the engagement namespace, delivered only via `stdin` or a mode-0600 file, and
  never placed in argv, environment, audit, evidence, or errors; a missing secret
  fails closed before `spawned` with `executed` false.
- **Conservative evidence:** `metadata-only` stores no raw output; retained output
  is redacted (resolved secret bytes first, then structural/pattern) before
  storage; raw output is never stored.
- **Fail-closed cleanup:** resource cleanup removes the private tree; an
  unconfirmed removal is `CLEANUP_RESOURCE_INCOMPLETE` with a protected marker and
  a non-success result. Target cleanup is independent; a target's own receipt is
  recorded as an `unverified-self-report`.
- **Secret-free audit:** the audit's argv projection is the code-owned template
  (placeholders), never concrete values, secret material, or ephemeral paths.

## Integration boundary

P3's modules live inside `hackbot.engagement_v2` and import the P0 contracts, the
P1/P2 modules, the standard library, the `subprocess` primitives, and the pure v1
redaction utility. No v1 module imports the v2 executor and the default v1 CLI
path is unchanged (v2-consumer allowlist guard).

## Known follow-ups

- Declared **file** outputs (`retained_outputs`) beyond stdout/stderr are not yet
  copied into evidence; P3 currently retains redacted stdout/stderr and removes
  the whole private tree, so undeclared files never persist. Retained-file
  plumbing is a bounded follow-up.
- A dedicated v2 execution CLI entry is not yet wired; `run` is a library entry.
