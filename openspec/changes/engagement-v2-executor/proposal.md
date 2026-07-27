## Why

P0–P2 froze the contracts, loaded the confirmed engagement, and produced a
policy-decided, bound argv — but nothing runs it. P3 is the first phase that
actually spawns a child, and it must do so only after `ALLOW`, only for the
code-owned bound argv (never a shell), inside a private, sanitized environment,
with engagement-namespaced secrets, conservative evidence, and an independent,
fail-closed cleanup. Without it there is no v2 execution path; with it, execution
stays inside the same safety boundary the earlier phases established.

## What Changes

- Add a **local executor** that spawns the P2 `BoundCommand` **only** on a policy
  `ALLOW`, with `shell=False`, a sanitized environment (no inherited secrets), a
  private per-run resource directory (mode `0700`) used as `CWD`/`HOME`/`TMPDIR`,
  bounded output readers, deadline enforcement, and child/process-group cleanup.
  The executor drives the P0 lifecycle (`received` → `validated` → `allowed` →
  `prepared` → `spawned` → `interaction-attempted` → `child-finished` →
  `evidence-finalized` → `resource-cleanup` → `target-cleanup` → `finalized`);
  `executed` becomes true only at `spawned`.
- Add **engagement-namespaced secret resolution** that runs **only after
  `ALLOW`**, resolves each `SecretReference` for the active engagement identity
  only (**no cross-engagement lookup**), and delivers material to the child only
  via `stdin` or a protected, exclusive-create file (mode `0600`, memory-backed
  when available). Secret names and values never enter argv, environment, audit,
  or errors.
- Add **declared-output evidence** with secret-aware redaction: only outputs the
  manifest declares (relative path, type, item/byte caps) are retained; undeclared
  files in the private run directory are removed and never become evidence.
  Retained stdout/stderr are redacted before storage (exact resolved-secret bytes
  plus the structural and pattern redactors), and raw output is never printed or
  stored un-redacted. Operator actions default to `metadata-only`;
  `redacted-output` requires exact policy permission and is invalid for
  credential/sensitive-data capabilities; `structured` is closed-form only.
- Add **independent, fail-closed cleanup**: `resource_cleanup_status` (stdin,
  temporary files/directories, processes) and `target_cleanup_status` (changes to
  the tested system) are separate. If either cannot be independently confirmed,
  the status is `cleanup_incomplete`, a protected item is written under
  `cleanup/`, and the run does not report success.
- Add a **secret-free audit record** per run: engagement identity, a canonical
  argv projection that replaces temporary paths with their manifest placeholders,
  the decision, child-result metadata, the evidence reference, and cleanup
  status — never raw output, secret names, or ephemeral paths.
- Preserve schema v1 behavior and the existing v1 gate-bound runner; P3 adds a v2
  execution path and does not change v1 execution.

Non-goals:

- No SSH transport or remote helper (P4); P3 executes locally only.
- No internal-recon or L3 catalog actions (P5), autonomous workflows (P6), or
  effective migration (P7).
- No change to the P2 policy decision, the P1 loader/scope, or the P0 contracts;
  they are consumed as-is.
- No claim that a target's own cleanup receipt is independently proven; it is
  recorded as an unverified self-report.

## Capabilities

### New Capabilities

- `local-executor`: Gate-bound local subprocess execution of the P2 bound argv in
  a private, sanitized environment with the P0 lifecycle, bounded readers,
  deadline, and child cleanup — spawning only after `ALLOW`.
- `engagement-secrets`: Post-`ALLOW`, engagement-namespaced secret resolution
  delivered only via `stdin`/protected file, with no cross-engagement lookup and
  no secret leakage into argv/env/audit/evidence.
- `evidence-redaction`: Declared-output retention, evidence-mode enforcement, and
  secret-aware redaction with a `metadata-only` default and un-redacted output
  never stored.
- `execution-cleanup`: Independent, fail-closed resource and target cleanup with a
  `cleanup_incomplete` state and a secret-free audit record.

### Modified Capabilities

None. P3 consumes the archived P0 contracts and the P1/P2 capabilities without
changing their requirements, and does not alter the v1 capabilities.

## Impact

- New code under `src/hackbot/engagement_v2/` (executor, secrets, evidence,
  cleanup, audit modules) importing the P0 package and the P1/P2 modules, plus
  the standard library and the existing OS keychain adapter for secret lookup.
- New CLI surface may reach the v2 executor through a new, explicitly v2 entry
  point; the v2-consumer allowlist guard is extended to the declared P3 modules.
- New unit and property tests under `tests/engagement_v2/` with a local harmless
  fixture executable; no real target or credential material.
- No new runtime dependency beyond the existing optional keychain extra; no
  change to any v1 CLI command or the v1 runner.

Architecture and review sources:

- `docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`
- `openspec/specs/action-execution-contracts/spec.md`
- `openspec/specs/engagement-authority-contracts/spec.md`
- `docs/tool-execution.md` and the v1 runner in `src/hackbot/tools/`
- GitHub delivery: Issue #5.
