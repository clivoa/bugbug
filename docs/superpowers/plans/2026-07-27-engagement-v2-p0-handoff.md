# Engagement v2 P0 Durable Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Commit a durable, repository-local Engagement v2 P0 continuation package and update draft PR #11 so Claude Code or a fresh Codex session can resume without conversation history.

**Architecture:** A concise authoritative handoff points to an indexed archive of byte-preserved SDD reports. Git remains the source for omitted diff packages, while the handoff records current GitHub/OpenSpec state, frozen decisions, verification, deferred work, and the exact pre-merge/post-merge sequence.

**Tech Stack:** Markdown, Git, GitHub CLI, OpenSpec CLI, Ruff, pytest, repository publication and secret guards.

## Global Constraints

- Do not change runtime code, schemas, fixtures, OpenSpec requirements, or P0 behavior.
- Preserve report bodies byte-for-byte; normalize only their durable filenames.
- Exclude every `review-*.diff` package because Git reconstructs those ranges.
- Exclude `.venv`, transient agent state, credentials, secrets, keys, and real target data.
- Keep OpenSpec task 8.2 unchecked until merge, remote-SHA verification, archive, Issue/Project completion, and P1 promotion.
- Keep the draft PR private and preserve the feature worktree for review feedback.
- The reviewed implementation before documentation is commit `4173929b550ecb60eb8d6e1fda0d0f68933cf015`.

---

## File Structure

```text
docs/
├── handoffs/
│   └── 2026-07-27-engagement-v2-p0.md
└── reviews/
    └── engagement-v2-p0/
        ├── README.md
        ├── sdd-ledger.md
        ├── task-1-report.md
        ├── task-2-report.md
        ├── task-3-report.md
        ├── task-4-recovery.md
        ├── task-4-report.md
        ├── task-5-report.md
        ├── task-6-report.md
        ├── task-6-review.md
        ├── task-6-re-review-round-1.md
        ├── task-7-report.md
        ├── task-7-review.md
        ├── task-7-re-review-round-1.md
        ├── task-8-report.md
        ├── task-8-review.md
        ├── external-claude-task4-descriptor-exporter-review.md
        ├── final-openspec-compliance-review.md
        ├── final-security-quality-review.md
        └── final-fix-wave-re-review.md
```

---

### Task 1: Materialize and index the readable evidence archive

**Files:**

- Create: `docs/reviews/engagement-v2-p0/README.md`
- Create: `docs/reviews/engagement-v2-p0/sdd-ledger.md`
- Create: `docs/reviews/engagement-v2-p0/task-1-report.md`
- Create: `docs/reviews/engagement-v2-p0/task-2-report.md`
- Create: `docs/reviews/engagement-v2-p0/task-3-report.md`
- Create: `docs/reviews/engagement-v2-p0/task-4-recovery.md`
- Create: `docs/reviews/engagement-v2-p0/task-4-report.md`
- Create: `docs/reviews/engagement-v2-p0/task-5-report.md`
- Create: `docs/reviews/engagement-v2-p0/task-6-report.md`
- Create: `docs/reviews/engagement-v2-p0/task-6-review.md`
- Create: `docs/reviews/engagement-v2-p0/task-6-re-review-round-1.md`
- Create: `docs/reviews/engagement-v2-p0/task-7-report.md`
- Create: `docs/reviews/engagement-v2-p0/task-7-review.md`
- Create: `docs/reviews/engagement-v2-p0/task-7-re-review-round-1.md`
- Create: `docs/reviews/engagement-v2-p0/task-8-report.md`
- Create: `docs/reviews/engagement-v2-p0/task-8-review.md`
- Create: `docs/reviews/engagement-v2-p0/external-claude-task4-descriptor-exporter-review.md`
- Create: `docs/reviews/engagement-v2-p0/final-openspec-compliance-review.md`
- Create: `docs/reviews/engagement-v2-p0/final-security-quality-review.md`
- Create: `docs/reviews/engagement-v2-p0/final-fix-wave-re-review.md`

**Interfaces:**

- Consumes: recoverable SDD archive at `/Users/clivoa/.Trash/bugbug-sdd-engagement-v2-security-contracts-2026-07-27/` and Claude review at `/tmp/claude-task4-descriptor-exporter-review.md`.
- Produces: byte-preserved readable evidence indexed by `docs/reviews/engagement-v2-p0/README.md`.

- [ ] **Step 1: Prove the durable archive is initially absent**

Run:

```bash
test ! -e docs/reviews/engagement-v2-p0
```

Expected: exit 0.

- [ ] **Step 2: Copy the approved readable sources**

Create `docs/reviews/engagement-v2-p0/` and copy this exact mapping:

```text
progress.md                                      -> sdd-ledger.md
task-1-report.md                                 -> task-1-report.md
task-2-report.md                                 -> task-2-report.md
task-3-report.md                                 -> task-3-report.md
task-4-recovery.md                               -> task-4-recovery.md
task-4-report.md                                 -> task-4-report.md
task-5-report.md                                 -> task-5-report.md
task-6-report.md                                 -> task-6-report.md
task-6-review.md                                 -> task-6-review.md
task-6-re-review-round-1.md                      -> task-6-re-review-round-1.md
task-7-report.md                                 -> task-7-report.md
task-7-review.md                                 -> task-7-review.md
task-7-re-review-round-1.md                      -> task-7-re-review-round-1.md
task-8-report.md                                 -> task-8-report.md
task-8-review.md                                 -> task-8-review.md
final-openspec-compliance-review.md              -> final-openspec-compliance-review.md
final-security-quality-review.md                 -> final-security-quality-review.md
final-fix-wave-re-review.md                      -> final-fix-wave-re-review.md
/tmp/claude-task4-descriptor-exporter-review.md  -> external-claude-task4-descriptor-exporter-review.md
```

- [ ] **Step 3: Verify byte preservation**

For the 18 SDD files, run `cmp -s` between each source and destination.
For the external Claude report, compare `/tmp/claude-task4-descriptor-exporter-review.md`
to its destination.

Expected: every comparison exits 0.

- [ ] **Step 4: Write the archive index**

`README.md` must contain:

- archive purpose and reviewed implementation SHA;
- a table for every retained file with type, task/range, and status;
- provenance for the SDD archive and external Claude report;
- the ruling that the Claude Task 4 review described superseded pre-hardening
  code and its findings were dispositioned;
- the explicit `review-*.diff` exclusion;
- exact reconstruction commands:

```bash
git log --oneline 30dd1e2c1bac749a1680e9770263f1cf7987c402..4173929b550ecb60eb8d6e1fda0d0f68933cf015
git diff --stat 30dd1e2c1bac749a1680e9770263f1cf7987c402..4173929b550ecb60eb8d6e1fda0d0f68933cf015
git diff -U10 30dd1e2c1bac749a1680e9770263f1cf7987c402..4173929b550ecb60eb8d6e1fda0d0f68933cf015
```

- [ ] **Step 5: Verify archive shape and exclusions**

Run:

```bash
test "$(find docs/reviews/engagement-v2-p0 -maxdepth 1 -type f | wc -l | tr -d ' ')" = 20
test -z "$(find docs/reviews/engagement-v2-p0 -name 'review-*.diff' -print -quit)"
test -z "$(git ls-files docs/reviews/engagement-v2-p0 | rg 'review-.*\\.diff$' || true)"
git diff --check
```

Expected: every command exits 0.

- [ ] **Step 6: Commit the readable archive**

```bash
git add docs/reviews/engagement-v2-p0
git diff --cached --check
git commit -m "docs: archive engagement v2 review evidence"
```

Expected: one documentation-only commit; `.venv` remains untracked.

---

### Task 2: Publish the consolidated continuation handoff

**Files:**

- Create: `docs/handoffs/2026-07-27-engagement-v2-p0.md`
- Modify: draft PR #11 body
- Modify: Issue #1 body
- External: Project #2 item metadata remains `Status=In Progress`, `Delivery Status=In Review`, `Phase=P0`, `Priority=Critical`.

**Interfaces:**

- Consumes: archive from Task 1, Git history, OpenSpec task state, PR #11, Issue #1, and Project #2.
- Produces: one authoritative continuation document and updated remote handoff links.

- [ ] **Step 1: Prove the consolidated handoff is initially absent**

Run:

```bash
test ! -e docs/handoffs/2026-07-27-engagement-v2-p0.md
```

Expected: exit 0.

- [ ] **Step 2: Write the authoritative handoff**

The document must contain these sections:

1. `Current state` — repo, worktree, branch, base, implementation SHA,
   documentation commits, PR #11, Issue #1, and Project #2.
2. `P0 boundary` — what exists and every P1–P4 runtime capability that remains
   intentionally absent.
3. `Frozen operator decisions` — execution projection, profiles, deny by
   absence, no post-engagement per-action approval, secret references and
   transports, target lists, binding grammar, and runner authority projection.
4. `Implementation map` — Tasks 1–8, commits, primary files, and review status.
5. `Final verification` — 245 focused tests, 1157 passed/1 skipped, four
   publication-guard tests, schema/fixture checks, Ruff, mypy, OpenSpec, secret
   scan, and diff check.
6. `Review history` — five final Important plus five selected Minor findings,
   fix commit `4173929`, and final 10/10 re-review verdict.
7. `Deferred work` — every non-blocking item retained in the final reviews.
8. `OpenSpec/GitHub workflow` — tasks 1.1–8.1 complete and 8.2 open.
9. `Exact next steps` — inspect PR, merge, verify remote merge SHA/checks,
   archive OpenSpec, rerun gates, push archive, close Issue/Project, then move P1
   to Ready.
10. `Claude Code continuation prompt` — a copy-paste prompt that first reads
    the handoff, archive index, active OpenSpec, and PR state; forbids archive
    before merge and requires evidence before status changes.

- [ ] **Step 3: Verify references and Git state**

Run:

```bash
git cat-file -e 30dd1e2c1bac749a1680e9770263f1cf7987c402^{commit}
git cat-file -e 4173929b550ecb60eb8d6e1fda0d0f68933cf015^{commit}
test -f docs/reviews/engagement-v2-p0/README.md
test -f openspec/changes/engagement-v2-security-contracts/tasks.md
rg -n '^## (Current state|P0 boundary|Frozen operator decisions|Implementation map|Final verification|Review history|Deferred work|OpenSpec and GitHub workflow|Exact next steps|Claude Code continuation prompt)$' docs/handoffs/2026-07-27-engagement-v2-p0.md
```

Expected: both commits and all ten sections exist.

- [ ] **Step 4: Run documentation and repository gates**

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m pytest
.venv/bin/python -m pytest tests/publication_guard -q
OPENSPEC_TELEMETRY=0 openspec validate engagement-v2-security-contracts --type change --strict --no-interactive
git diff --check
```

Run the secret scan over the new handoff/archive and require the underlying
`rg` command to return 1 with no matches:

```bash
rg -n '(gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9]{32,})' docs/handoffs/2026-07-27-engagement-v2-p0.md docs/reviews/engagement-v2-p0
```

Expected: Ruff, pytest, publication guard, OpenSpec, and diff check exit 0;
secret scan emits no match and exits 1.

- [ ] **Step 5: Commit the consolidated handoff**

```bash
git add docs/handoffs/2026-07-27-engagement-v2-p0.md
git diff --cached --check
git commit -m "docs: add engagement v2 continuation handoff"
```

- [ ] **Step 6: Push through the approved private publication flow**

```bash
HACKBOT_ALLOW_PUBLISH_RECON=1 git push origin feat/engagement-v2-security-contracts
```

Expected: publication guard acknowledges the override and remote branch advances
to the local documentation HEAD.

- [ ] **Step 7: Update and verify GitHub handoff**

Update PR #11 and Issue #1 to link:

- `docs/handoffs/2026-07-27-engagement-v2-p0.md`;
- `docs/reviews/engagement-v2-p0/README.md`;
- design `docs/superpowers/specs/2026-07-27-engagement-v2-p0-handoff-design.md`;
- this implementation plan.

Verify:

```bash
gh pr view 11 --repo clivoa/bugbug --json isDraft,headRefOid,mergeable,url
gh issue view 1 --repo clivoa/bugbug --json state,labels,projectItems,url
gh project item-list 2 --owner clivoa --format json --limit 100
git ls-remote --heads origin feat/engagement-v2-security-contracts
git status -sb
```

Expected:

- PR #11 remains draft and mergeable;
- local and remote branch SHAs match;
- Issue #1 stays open with `status:in-review`;
- Issue and PR Project items remain `In Progress` / `In Review`;
- `.venv` is the only untracked path.
