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

## Final review remediation — crash durability and strict recovery

This remediation closes the remaining Task 4 durability, validation, and
platform-boundary findings.

- Recovery now fsyncs every transition's source and destination state
  directories before touching the audit log or removing the WAL, including
  transitions that recovery observes as already complete after an earlier
  crash. Newly created approval directories likewise fsync their parent
  descriptor immediately. Second-crash tests verify that the WAL survives a
  failed recovery fsync and that both state-directory flushes precede audit and
  journal cleanup.
- Audit recovery now fsyncs the audit descriptor even when the exact
  idempotent line already exists. A crash seam after the audit write and before
  its fsync verifies that a subsequent recovery durably flushes the existing
  line before deleting the WAL.
- WAL records carry an independent transition timestamp and enforce an exact
  operation/source/destination/artifact-kind mapping. Recovery also requires
  the exact result/reason pair, matches the event's engagement, action, digest,
  and risk to the validated artifact, and binds event time to the transition
  and artifact lifecycle. Forged or non-scalar transaction fields fail closed
  and produce the fixed seven-field rejection audit projection.
- Secret screening now recognizes Cookie and Set-Cookie material, session and
  auth-session identifiers, JWTs, all Authorization and Proxy-Authorization
  header schemes, token headers, and sensitive required-header names. Recursive
  mapping checks cover keys and values; denials never echo the rejected input.
- Challenge construction, grant, consume, recovery, and status convert
  datetime overflow, non-finite canonical JSON, malformed binding types, and
  malformed artifact/transaction values into controlled `ApprovalError`s.
  Constructor failures after engagement-descriptor acquisition close that
  descriptor.
- Atomic no-overwrite transitions fail closed when the native symbol or syscall
  is unavailable. The runtime requirement is documented in both
  `approvals.py` and the design specification: supported macOS/Linux approval
  stores require `fcntl` plus `renameatx_np`/`renameat2`; Windows remains
  unsupported.

RED evidence included missing state-directory fsyncs during observed-complete
recovery, no audit crash seam or idempotent-line fsync, eight newly enumerated
credential forms being accepted, forged WAL event fields being accepted,
uncaught timestamp/canonicalization exceptions, missing native-symbol
`AttributeError`, and leaked constructor descriptors. Each focused reproduction
was observed before its implementation change.

Final verification:

- Focused approval suite: `104 passed in 0.55s`.
- Full suite: `438 passed in 3.31s`.
- `ruff check .`: passed.
- `mypy src`: passed for 33 source files.
- Changed-file `ruff format --check`: passed.
- `git diff --check`: passed.

## Final follow-up — credential variants and directory-fsync retry

- Secret screening now normalizes spaces, underscores, hyphens, dots, and other
  separators before classifying credential key names. It rejects conservative
  generic and provider-specific names such as `client_secret`,
  `refresh_token`, `access_token`, AWS access/secret/session keys,
  `database_url`, Google/Azure/GitHub/OpenAI-style credential environment
  names, and suffix-equivalent nested names.
- Direct material screening rejects PEM/OpenSSH/PGP private-key blocks, JWTs,
  high-confidence provider token prefixes, and credential-bearing URI userinfo
  for any syntactically valid URI scheme. Mapping keys and values and sequence
  elements remain recursively screened, and the controlled rejection never
  includes the rejected value.
- A cross-product regression test places reviewer credential examples and
  underscore, hyphen, and dotted variants into every persisted request text
  field and exact argv. Sensitive required-header names receive separate
  separator-variant coverage.
- Every validated approval root/state-directory open now fsyncs its parent
  descriptor, regardless of whether that attempt created the directory. Exact
  fault/retry tests fail the first parent fsync after a successful `mkdir` for
  both `approvals/` and `pending/`, then verify the retry flushes the engagement
  or approval-root parent before opening the next child.

RED evidence: the new credential matrix exposed accepted PEM, normalized-key,
cloud-environment, and credential-URI variants; the retry spies showed no
parent fsync between the retried directory open and the next child open. Both
failures were observed before their production changes.

Final verification:

- Focused approval suite: `292 passed in 1.60s`.
- Full suite: `626 passed in 3.90s`.
- `ruff check .`: passed.
- `mypy src`: passed for 33 source files.
- Changed-file `ruff format --check`: passed.
- `git diff --check`: passed.
