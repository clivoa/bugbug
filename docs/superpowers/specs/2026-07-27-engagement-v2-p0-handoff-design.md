# Engagement v2 P0 durable handoff design

## Goal

Preserve enough repository-local context for Claude Code or a fresh Codex
session to resume the Engagement v2 P0 delivery without relying on conversation
history or temporary agent state.

The handoff must be useful after token or session resets, must not duplicate
large Git diffs, and must not change the implemented P0 contracts or activate
Engagement v2 execution.

## Durable outputs

The implementation will add:

1. `docs/handoffs/2026-07-27-engagement-v2-p0.md`
   - authoritative current state;
   - branch, base, reviewed HEAD, PR, Issue, and Project links;
   - frozen operator decisions and P0 boundaries;
   - task/commit timeline;
   - final gate evidence and review outcomes;
   - deferred non-blocking work;
   - exact next steps through merge and OpenSpec archive;
   - copy-paste continuation instructions for Claude Code.
2. `docs/reviews/engagement-v2-p0/README.md`
   - archive index;
   - provenance and source location;
   - explanation of which files are retained or omitted;
   - commands that reconstruct omitted diffs from Git.
3. `docs/reviews/engagement-v2-p0/sdd-ledger.md`
   - the final Subagent-Driven Development ledger.
4. Human-readable task and review reports:
   - Task 1 through Task 8 implementation reports;
   - the Task 4 recovery note;
   - Task 6 through Task 8 independent review and re-review reports;
   - final OpenSpec compliance review;
   - final security/quality review;
   - final fix-wave re-review.

## Explicit exclusions

The archive will not commit:

- `.superpowers/sdd/**/review-*.diff` packages;
- task briefs that duplicate the committed implementation plan;
- `.venv` or other local environment state;
- transient agent metadata;
- secrets, credentials, tokens, private keys, or real target data.

The omitted review packages are reproducible from the base/head SHAs recorded
in the reports with:

```bash
git diff --stat <base>..<head>
git diff -U10 <base>..<head>
git log --oneline <base>..<head>
```

The committed plan remains the authoritative task specification:
`docs/superpowers/plans/2026-07-26-engagement-v2-security-contracts.md`.

## Source and transformation rules

The readable reports will be copied byte-for-byte from the recoverable SDD
archive currently stored at:

`/Users/clivoa/.Trash/bugbug-sdd-engagement-v2-security-contracts-2026-07-27/`

Only filenames may be normalized for the durable directory. Report bodies,
findings, rulings, test evidence, and commit identifiers must not be summarized
away or silently rewritten.

The consolidated handoff is a new synthesis. It must distinguish:

- verified facts from planned future actions;
- pre-fix evidence from the final reviewed state;
- blocking work from deferred non-blocking observations;
- pre-merge work from post-merge archive work.

## Continuation contract

A fresh agent must be able to determine, from the main handoff alone:

1. the exact checkout and GitHub objects to inspect;
2. the reviewed implementation SHA;
3. which commands establish current correctness;
4. which OpenSpec task remains open and why;
5. which actions are authorized now;
6. which actions require merge or new operator approval;
7. where detailed historical evidence lives.

The handoff must explicitly instruct the next agent not to:

- archive the OpenSpec change before merge;
- mark Issue #1 or the Project item Done before archive is pushed;
- promote P1 to Ready before P0 archive completion;
- reactivate per-action approvals or add P1–P4 runtime into P0;
- stage or publish `.venv`.

## Verification

Before commit and push:

1. verify every indexed report exists;
2. prove no `review-*.diff` file is committed;
3. verify recorded base/head SHAs exist;
4. run the publication guard and repository secret-pattern scan over the new
   documentation;
5. run Ruff formatting validation, `git diff --check`, and the full test suite;
6. confirm `.venv` remains untracked;
7. update draft PR #11 and Issue #1 with the handoff paths and new HEAD.

The worktree remains available for PR feedback. OpenSpec task 8.2 remains open
until merge, remote-SHA verification, archive, Issue/Project completion, and P1
promotion are complete.
