## Context

P0–P2 produced a frozen contract layer, a confirmed engagement snapshot with a
typed scope, and a policy that returns `ALLOW` plus a P2 `BoundCommand`. P3 is the
first phase that actually spawns a child. It must execute only that bound argv,
only after `ALLOW`, with `shell=False`, inside a private and sanitized
environment, resolve secrets late and namespaced, retain conservative evidence,
and clean up resources and target state independently and fail-closed.

The existing v1 gate-bound runner (`src/hackbot/tools/`) already establishes the
patterns P3 reuses: no shell, sanitized env, argv arrays, bounded streaming
capture, deadline, and process-group teardown. P3 is the v2 counterpart wired to
the v2 snapshot/identity, bound command, and lifecycle. The operator is trusted to
declare arbitrary-tool semantics; target output and a target's own cleanup receipt
remain untrusted self-reports.

## Goals / Non-Goals

**Goals:**

- Spawn only the P2 bound argv on `ALLOW`, `shell=False`, in a private mode-`0700`
  `CWD`/`HOME`/`TMPDIR` with a sanitized environment and opaque run-file names.
- Drive the exact P0 lifecycle with bounded readers, a deadline, and child /
  process-group cleanup; set `executed` true only at `spawned`.
- Resolve secrets only after `ALLOW`, only within the engagement namespace, and
  deliver them only via `stdin`/protected file — never into argv/env/audit/evidence.
- Retain only declared outputs, enforce evidence modes, and redact secret-aware
  before storing; default `metadata-only`; never store raw output.
- Track resource and target cleanup independently and fail closed; write a
  secret-free audit record with a placeholder argv projection.
- Keep the core dependency-free (beyond the existing keychain extra) and leave v1
  execution unchanged.

**Non-Goals:**

- No SSH/remote helper (P4), internal-recon/L3 catalog (P5), autonomous workflow
  (P6), or effective migration (P7).
- No change to P0/P1/P2 or the v1 runner.
- No independent proof of arbitrary-executable behavior or of a target's own
  cleanup.

## Decisions

### 1. Execution is a strict pipeline over the bound command

`run(bound, action, snapshot, policy_decision, now)` refuses unless
`policy_decision` is `ALLOW`, then: prepare the private dir → resolve secrets →
materialize `{targets_file}`/`{artifact_file}`/`{secret_file}` references into the
private dir → spawn the concrete argv → capture bounded output under a deadline →
finalize evidence → resource cleanup → target cleanup → audit. Each stage maps to
one lifecycle state; a failure before `spawned` leaves `executed` false.

Alternative considered: fold execution into the policy call. Rejected — the
decision must stay a pure function (P2) with no I/O, and execution must be a
separate, auditable stage.

### 2. Private directory is the isolation unit

Create a mode-`0700` directory; set `CWD`/`HOME`/`TMPDIR` to it; build the child
environment from a minimal allowlist (no inherited secrets). All run files
(target lists, artifacts, secret files, captured output) live inside it with
`O_EXCL` opaque numeric names. Teardown removes the whole tree; failure to remove
is `CLEANUP_RESOURCE_INCOMPLETE`.

### 3. Secrets are late, namespaced, and transport-restricted

Resolution uses the engagement namespace identity as the lookup scope through the
existing keychain adapter; a reference resolving only under another engagement
fails closed. Material reaches the child only via `stdin` or a mode-`0600`
exclusive file (memory-backed `TMPDIR` when available). The resolved byte values
are held only transiently to drive redaction and delivery and are dropped after
the run; they never enter argv/env/audit/evidence/errors. Any error after the
private directory is created routes through resource cleanup and returns a
fail-closed result, so a resolved secret file never survives a spawn/finalize
failure.

### 4. Evidence is conservative and redaction is layered

Default `metadata-only`. `redacted-output` requires exact policy permission and is
denied (`EVIDENCE_POLICY_DENIED`) for credential/sensitive capabilities. Retained
output is redacted in order — exact resolved-secret bytes, then structural, then
pattern (Kerberos/NTLM/etc.) — then metadata is secret-scanned. Raw output is
never printed or stored. Redaction is never the sole control that permits a
credential capability; the capability gate (P2) already did that.

### 5. Cleanup and audit are split and fail-closed

`resource_cleanup_status` and `target_cleanup_status` are independent P0 enums.
Resource cleanup always runs; unconfirmed cleanup is an incomplete state with a
protected `cleanup/` item and a non-success wrapper status. A target self-report
is `unverified-self-report`. The audit record (written before evidence is
surfaced) carries the placeholder argv projection and no secret/raw/ephemeral
data.

### 6. Controlled v2 execution entry point

A new, explicitly v2 CLI entry reaches the executor; the P1/P2 v2-consumer
allowlist guard is extended to the declared P3 modules. Default v1 CLI paths and
the v1 runner remain unchanged and never import the v2 executor.

## Risks / Trade-offs

- A spawn path could bypass the gate → `run` refuses on any non-`ALLOW` and a test
  asserts no spawn occurs; the only argv spawned is the P2 bound argv.
- Secret leakage into output/audit → exact-byte redaction plus an audit/evidence
  secret-scan test on synthetic secrets; secrets never touch argv/env.
- Undeclared output becoming evidence → only declared paths are retained; a test
  writes an undeclared file and asserts removal.
- Cleanup silently passing → unconfirmed cleanup fails closed with a protected
  item; tests force a surviving resource and assert `CLEANUP_RESOURCE_INCOMPLETE`.
- Cross-engagement secret access → resolution scoped to the engagement identity;
  a test with a foreign-namespace secret asserts fail-closed.

## Migration Plan

1. Add executor, secrets, evidence, cleanup, and audit modules under
   `src/hackbot/engagement_v2/`, importing the P0 package, P1/P2 modules, stdlib,
   and the existing keychain adapter.
2. Add a harmless local fixture executable and tests; extend the v2-consumer
   allowlist guard to the P3 modules; wire the read-guarded v2 execution CLI.
3. Verify (full suite, ruff/format, mypy, drift, OpenSpec strict, secret scan,
   `git diff --check`), request independent review, merge, archive.

Rollback removes the P3 modules, CLI wiring, fixtures, and tests and reverts the
guard. P3 persists only per-run artifacts under the engagement directory that a
documented cleanup removes; rollback migrates no data.

## Open Questions

None. Lifecycle states, evidence modes, cleanup states, secret transports, and
reason codes are fixed by the archived P0 contracts; the bound argv and decision
come from P2; the engagement identity and scope come from P1. Remote execution
and the internal-recon catalog remain P4 and P5.
