# Task 4 report — canonical L2 challenges and approval store

## Scope and commit

Implemented Task 4 only: canonical, five-minute L2 challenge construction and
engagement-local pending/granted/consumed/expired approval persistence. No CLI,
interactive confirmation, policy-engine grant integration, subprocesses,
providers, tokens, or network activity was added.

Initial implementation commit: `ac7f04cda6e643e4311995b35b65cc47a21ae963`
(`feat: add single-use L2 approval store`).

## Security properties

- Challenge hashes canonically bind the engagement ID and canonical path,
  program, action definition (including `argv_template`, classifications, and
  capabilities), full request review fields, exact argv/target, scope snapshot
  and digest, policy digest, timestamps, and bounded nonce.
- Challenge, grant, and consume clocks require aware UTC values. Expiry is
  exactly five minutes, with the expiry instant denied; grants before challenge
  creation are rejected.
- Approval files live below the matching canonical engagement directory. State
  directories are `0700`; artifacts and audit JSONL are `0600`. Artifact and
  audit opens reject symlinks, names derive only from SHA-256 digests, and all
  record reads reject oversized, malformed, duplicate-key, or unknown-key JSON.
- Pending and grant files use exclusive creation plus fsync. Consumption uses a
  per-digest advisory lock, durable transaction journal, same-filesystem rename,
  and parent-directory fsync; a competing consumer becomes a controlled
  `ApprovalError`. There is no API to unconsume, regrant, or extend a grant.
- The persisted canonical challenge payload is rehashed and cross-checked
  against presentation fields on every use, so tampering cannot reuse a stale
  digest. Audit events use a strict seven-field secret-free projection.
- Simulated write failure removes the newly-created artifact before returning
  an error.

## RED / GREEN evidence

- RED: initial `tests/risk/test_approvals.py` collection failed with
  `ModuleNotFoundError: No module named 'hackbot.risk.approvals'`.
- Subsequent red reproductions caught a pre-creation grant timestamp, malformed
  artifact status reads, challenge presentation-field tampering, and an audit
  symlink before their corresponding implementations were added.
- GREEN focused suite: `25 passed in 0.12s`.
- Full suite: `359 passed in 3.00s`.
- `ruff check .` passed; changed-file format check passed; `mypy src` passed
  for 33 source files; staged `git diff --check` passed.

## Coverage highlights

The focused suite covers deterministic hashes, argv-template enforcement,
target/request/policy/definition binding, nonce and clock validation, exclusive
creation, modes, exact expiry, replay, concurrent consumers, corrupt/oversized
and duplicate-key records, policy mismatch, engagement mismatch, symlinks,
audit projection, and partial-write cleanup.

## Concern

Audit locking deliberately uses `fcntl.flock`; it is documented in
`approvals.py` as a macOS/Linux guarantee and does not claim Windows support.
Repository-wide `ruff format --check .` still reports the pre-existing root
`conftest.py` formatting issue; Task 4's changed files are formatted and that
file was not modified.

## Review remediation — authorization and persistence hardening

Commit: `56e3c8452ed897b1231a59c4ba6be9e1145d6ad9`
(`fix: preflight and harden approval issuance`).

- `build_challenge` now recomputes the canonical policy-context digest and runs
  the pure `RiskEngine` with the exact code-owned definition, request, context,
  and injected clock. It requires `REQUIRES_APPROVAL`; scope, authorization,
  program restrictions, rate/concurrency, and malformed local L2 input deny
  with controlled `ApprovalError`s.
- `create_pending` no longer accepts a caller-supplied challenge. It requires
  the trusted definition/request/context/clock and rebuilds the challenge.
- Challenge input recursively rejects likely credential-bearing values without
  echoing them. It recognizes authorization/Bearer/Basic, common secret key
  names with values, and high-confidence provider token prefixes.
- O_EXCL ownership is tracked so a losing concurrent pending issuer never
  unlinks the winning artifact. Persisted artifacts must be regular files owned
  by the current UID and mode `0600`.
- State claims now use a per-digest `fcntl` lock and a durable transaction
  journal around no-overwrite rename plus source/destination directory fsync.

Additional RED/GREEN evidence: tests for denied preflight, secret-bearing
review text, free-standing challenge issuance, concurrent pending issuance,
and wrong artifact modes were added before the corresponding changes. Focused
approval suite completed with `30 passed`; full suite completed with `364
passed`; Ruff and mypy passed.

## Follow-up remediation — interrupted transition recovery

Commit: `b4606034b064ea974e3b11f876c098df6fb45e67`
(`fix: recover interrupted approval transitions`).

State lookup now reads a strict, mode-checked transaction journal before
reporting state. A journal with both source and destination artifacts removes
the source, a journal with just the destination confirms the completed rename,
and a journal with only source rolls back the unperformed transition. Missing
both artifacts is a controlled malformed-state failure. The new adversarial
test creates a valid dual-state crash image and verifies that `status` produces
the destination state with no remaining source file.

## Final remediation — descriptor-owned POSIX store and rejection audit

Commit: `25d98a13d1ccf0b382f93bbac032ebd314cb8adb`
(`fix: make approval storage descriptor-owned`).

- `ApprovalStore` now anchors the canonical engagement directory with an owned
  descriptor. After that bootstrap, approval root, state, lock, transaction,
  artifact, and audit access uses verified directory descriptors plus relative
  `open`, `stat`, `unlink`, and no-overwrite rename operations. Directories must
  be current-UID `0700`; regular files must be current-UID `0600`, have one
  link, and satisfy their size and strict-schema limits.
- Every descriptor open uses `O_NOFOLLOW`; per-digest locks are regular,
  single-link `0600` files. macOS uses `renameatx_np(RENAME_EXCL)` and Linux
  uses `renameat2(RENAME_NOREPLACE)` for atomic consume/expire transitions.
  Source device/inode and content checks reject read-to-rename replacement,
  while late destinations are never overwritten.
- Create, grant, consume, pending expiry, and granted expiry are all durable WAL
  transactions. The journal is fsynced before mutation; source and destination
  directories are fsynced; and recovery deterministically completes forward,
  writes the required event once, removes the journal, and leaves exactly one
  state. Both pending-origin and granted-origin expired artifacts have strict
  readable schemas.
- Lifecycle calls serialize state inspection, recovery, and mutation under the
  digest lock. Every safely projectable local rejection is appended through a
  non-recursive audit path, including invalid operator, missing state,
  challenge/grant mismatch, policy mismatch, malformed/tampered state, replay,
  and expiry. Audit events retain exactly the seven fixed secret-free fields;
  transaction recovery checks for the exact event under the audit lock before
  appending, making replayed recovery idempotent.
- Secret screening now covers every operator-reviewed request field, including
  hypothesis, expected impact, stop condition, cleanup plan, and program rule,
  in addition to target, argv, rationale, data touched, and header names.
- Adversarial coverage includes engagement-ancestor and state-directory swaps,
  source replacement after read, late destination creation, artifact/audit/lock
  hardlinks, lock symlinks, unsafe directory modes, grant/consume/expire races,
  pending expiry schema, every transaction crash phase, audit completeness, and
  the invariant that recovery/races leave no dual state. The nofollow-lock test
  was also mutation-checked: removing `O_NOFOLLOW` reproduced the unsafe grant,
  and restoring it returned the test to green.

Final verification after the remediation commit:

- Focused approval suite: `66 passed`.
- Full suite: `400 passed in 3.30s`.
- `ruff check .`: passed.
- `mypy src`: passed for 33 source files.
- Changed-file `ruff format --check`: passed.
- `git diff --check`: passed.
- Repository-wide `ruff format --check .` still reports only the pre-existing
  root `conftest.py`; 74 other files, including both Task 4 files, are formatted.
