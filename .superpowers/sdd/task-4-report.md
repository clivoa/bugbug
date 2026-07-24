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
