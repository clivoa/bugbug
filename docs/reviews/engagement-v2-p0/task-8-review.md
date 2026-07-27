# Task 8 independent in-repo review

Review scope: commit range `b0b8d49..5e87d51` only. This is the scoped
in-repository Task 8 review; it is not the later whole-implementation review in
the two requested axes.

Spec compliance: PASS

Task quality: APPROVED

Finding count: Critical **0**, Important **0**, Minor **1**.

## Summary

Commit `5e87d51` contains exactly six changed paths: the OpenSpec task ledger
plus the five Ruff remediation paths named in `task-8-report.md`. There is one
commit in the range, with the reported subject
`test: verify engagement v2 security contracts`. The supplied review package's
diff section is byte-identical to `git diff -U10 b0b8d49..5e87d51`.

The five non-ledger files are mechanical Ruff formatting only. Formatting the
five `b0b8d49` versions with the repository's Ruff configuration reproduced
their HEAD bytes exactly. The four Python files also have identical parsed ASTs
at the two ends of the range. The Markdown plan change is confined to Ruff
formatting of Python code fences. Therefore this range changes no runtime,
test, or plan semantics.

The ledger has 15 checked items and one open item. Accumulated reports, reviewed
fix rounds, committed artifacts, and branch diffs provide evidence for every
checked item from 1.1 through 8.1. Item 8.2 correctly remains open: independent
whole-change review, finding resolution, GitHub Issue/Project publication, and
post-merge OpenSpec archive work have not yet all occurred.

The commit/range does not contain `.venv`. The live worktree does contain the
reported pre-existing untracked `.venv -> ../../.venv` symlink; it is neither
tracked nor present in `b0b8d49..5e87d51`.

## Findings

### Critical

None.

### Important

None.

### Minor

1. `.superpowers/sdd/2026-07-26-engagement-v2-security-contracts/task-8-report.md:7`
   — The branch/worktree line says it is at `b0b8d49`, while HEAD and the
   report's own commit-scope section identify committed result `5e87d51`.

   Impact: no code, gate, or checkbox conclusion is affected, but the report's
   snapshot metadata is internally inconsistent and can confuse later handoff
   or archive auditing.

   Correction: describe `b0b8d49` as the dispatch/review base and `5e87d51` as
   the verified committed HEAD.

## Checkbox evidence audit

| Checkbox | Accumulated evidence confirmed |
| --- | --- |
| 1.1–1.2 | `task-1-report.md`, its reviewed fix rounds, the Task 1 commit sequence, `test_constants.py`, and the isolated `constants.py`/`errors.py` artifacts cover the registry tests and implementation. |
| 2.1–2.2 | `task-2-report.md`, its reviewed coverage fix, canonical fixtures, `test_canonical.py`, and `canonical.py` cover strict values, ordering, rejection boundaries, domains, and golden digest behavior. |
| 3.1–3.2 | `task-3-report.md`, its reviewed runtime/budget fix, pattern fixtures, `test_patterns.py`, and `patterns.py` cover the closed grammar and bounded non-`re` matcher. |
| 4.1–4.2 | `task-4-report.md`, two reviewed hardening rounds, eight generated schema documents plus manifest, `test_schemas.py`, `schemas.py`, and the exporter cover drift tests and code-owned Draft 2020-12 publication. |
| 5.1–5.2 | `task-5-report.md`, its reviewed binding/preflight fix, `test_protocol.py`, `protocol.py`, and protocol fixtures cover framing, caps, exact reads, digests, run binding, expiry/skew, and response echo. |
| 6.1–6.2 | `task-6-report.md`, independent review and re-review, the synthetic canonical/pattern/protocol fixture tree, `test_fixture_generation.py`, and the generator cover reproducibility, check mode, negative lengths, hashes, and safe synthetic content. |
| 7.1–7.2 | `task-7-report.md`, independent review and passing scoped re-review, `test_v1_isolation.py`, `docs/engagement-v2-contracts.md`, and roadmap/workflow updates cover v1 non-activation and the P0 documentation boundary. The already parked `FrameType` documentation omission remains a non-blocking deferred Minor for the later whole-change review. |
| 8.1 | `task-8-report.md:9-140` records focused P0, schema/fixture drift, full pytest, Ruff check/format, mypy, strict OpenSpec, publication/secret, and whitespace gates before and after Ruff remediation. |
| 8.2 | Correctly open at `openspec/changes/engagement-v2-security-contracts/tasks.md:39`; its independent whole-change review, GitHub/Project updates, merge, and archive conditions are not complete. |

## Scope and count reconciliation

- `git diff --name-status b0b8d49..5e87d51` reports only the six documented
  paths.
- Range total: **37 insertions, 90 deletions**.
- Five Ruff-only paths: **22 insertions, 75 deletions**, exactly as reported.
- Task ledger: **15 insertions, 15 deletions**, corresponding to 15 checkbox
  flips; 8.2 is unchanged and open.
- Ruff accounting is internally coherent: initial `5 files would be
  reformatted, 200 files already formatted`; final `205 files already
  formatted`.
- Focused pytest's displayed progress contains 239 test dots; the report
  consistently records exit 0 without asserting a conflicting focused count.
- Full pytest is consistently reported as **1151 passed, 1 skipped** before and
  after remediation, and publication guard as **4 passed**.
- `git diff --check b0b8d49..5e87d51` exits zero.

## Verification boundary

⚠️ Cannot verify from diff: the historical pytest, schema/fixture check, Ruff
check/whole-tree format, mypy, OpenSpec CLI, publication guard, secret scan, and
pre-commit staged-diff outputs recorded in `task-8-report.md` were not rerun in
this read-only review, per instruction not to rerun broad gates. Their command
forms, exit/count accounting, and relationship to the committed diff are
internally coherent.

The live state of GitHub Issue #1, Project #2 fields, PR publication, merge
checks, and the future post-merge archive cannot be established from this diff.
Their absence is why 8.2 must remain open.

## Final ruling

Spec compliance is **PASS** for the scoped in-repo Task 8 range. Task quality is
**APPROVED**: the diff scope, Ruff-only remediation, checkbox evidence, gate
accounting, `.venv` exclusion from the commit, and intentional 8.2 deferral are
sound. The single stale base/HEAD label is a non-blocking Minor documentation
correction.
