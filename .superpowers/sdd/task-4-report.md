# Task 4 report — canonical L2 challenges and approval store

## Scope and commit

Implemented Task 4 only: canonical, five-minute L2 challenge construction and
engagement-local pending/granted/consumed/expired approval persistence. No CLI,
interactive confirmation, policy-engine grant integration, subprocesses,
providers, tokens, or network activity was added.

Implementation commit: `ac7f04cda6e643e4311995b35b65cc47a21ae963`
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
  same-filesystem hard-link no-overwrite claim followed by source unlink, so a
  competing consumer cannot overwrite the consumed destination; races become
  controlled `ApprovalError`s. There is no API to unconsume, regrant, or extend
  a grant.
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
