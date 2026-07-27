# Engagement v2 P0 review evidence archive

This directory preserves the readable Subagent-Driven Development evidence for
the Engagement v2 P0 security-contract implementation. It exists so a fresh
Claude Code or Codex session can inspect the implementation history without
conversation memory or the temporary `.superpowers/sdd/` workspace.

The reviewed implementation baseline for this archive is
`4173929b550ecb60eb8d6e1fda0d0f68933cf015`. Documentation-only continuation
commits may follow it on `feat/engagement-v2-security-contracts`.

Start with the authoritative continuation document:
[`docs/handoffs/2026-07-27-engagement-v2-p0.md`](../../handoffs/2026-07-27-engagement-v2-p0.md).

## Provenance

The SDD ledger, task reports, and Codex review reports were copied byte-for-byte
from the recoverable local archive:

`/Users/clivoa/.Trash/bugbug-sdd-engagement-v2-security-contracts-2026-07-27/`

The external Task 4 report was copied byte-for-byte from:

`/tmp/claude-task4-descriptor-exporter-review.md`

Some source reports contain historical trailing whitespace or a final blank
line. Those bytes are evidence, not current formatting style. The archive is
therefore excluded from Ruff formatting in `pyproject.toml` and marked
`-whitespace` in `.gitattributes`. This keeps both byte comparison and
range-wide `git diff --check` deterministic without silently rewriting reports.
All non-archived files remain subject to the normal formatter and whitespace
checks.

The later independent Claude review is already durable outside this directory:
[`2026-07-27-engagement-v2-p0-contracts-review-disposition.md`](../2026-07-27-engagement-v2-p0-contracts-review-disposition.md).

## Retained files

| File | Evidence | Status |
| --- | --- | --- |
| [`sdd-ledger.md`](sdd-ledger.md) | Authoritative task/fix/ruling ledger through final review | Complete |
| [`task-1-report.md`](task-1-report.md) | Typed failures and immutable contract registry | Complete |
| [`task-2-report.md`](task-2-report.md) | Canonical values and domain-separated digests | Complete |
| [`task-3-report.md`](task-3-report.md) | Safe-fullmatch parser and bounded matcher | Complete |
| [`task-4-recovery.md`](task-4-recovery.md) | Recovery handoff after the first Task 4 implementer stopped | Historical |
| [`task-4-report.md`](task-4-report.md) | Code-owned schemas and hardened exporter | Complete |
| [`task-5-report.md`](task-5-report.md) | Bounded remote framing and execution binding | Complete |
| [`task-6-report.md`](task-6-report.md) | Deterministic fixture regeneration | Complete |
| [`task-6-review.md`](task-6-review.md) | Task 6 independent review | Superseded by fix |
| [`task-6-re-review-round-1.md`](task-6-re-review-round-1.md) | Task 6 scoped re-review | Pass |
| [`task-7-report.md`](task-7-report.md) | v1 isolation and P0 documentation boundary | Complete |
| [`task-7-review.md`](task-7-review.md) | Task 7 independent review | Superseded by fix |
| [`task-7-re-review-round-1.md`](task-7-re-review-round-1.md) | Task 7 scoped re-review | Pass |
| [`task-8-report.md`](task-8-report.md) | Full gates, formatter remediation, and final fix evidence | Complete |
| [`task-8-review.md`](task-8-review.md) | Task 8 in-repository verification review | Pass |
| [`external-claude-task4-descriptor-exporter-review.md`](external-claude-task4-descriptor-exporter-review.md) | External review of the pre-hardening Task 4 exporter | Dispositioned |
| [`final-openspec-compliance-review.md`](final-openspec-compliance-review.md) | Whole-branch OpenSpec compliance review | Findings fixed |
| [`final-security-quality-review.md`](final-security-quality-review.md) | Whole-branch adversarial security/quality review | Findings fixed |
| [`final-fix-wave-re-review.md`](final-fix-wave-re-review.md) | Single scoped re-review of all final fixes | Pass; ready to merge |

## External Task 4 review ruling

The external Claude Task 4 report describes an exporter revision that predates
commits `81617c5` and `5ed72b7`. Its Critical and Important observations were
resolved by descriptor-pinned, no-follow, nonblocking, fail-closed publication
and exact-directory checking.

Two recommendations were deliberately not adopted as blockers:

- unexpected entries are reported but not deleted automatically because
  automatic deletion is destructive and outside the approved exporter
  contract;
- publication remains per-file atomic rather than a global filesystem
  transaction, with `--check` detecting and repairing partial repository state.

The disposition is recorded in [`sdd-ledger.md`](sdd-ledger.md) and the final
reviews.

## Omitted diff packages

No `.superpowers/sdd/**/review-*.diff` package is committed here. Those files
duplicate Git history and were often hundreds of kilobytes. Reconstruct the
complete implementation range with:

```bash
git log --oneline 30dd1e2c1bac749a1680e9770263f1cf7987c402..4173929b550ecb60eb8d6e1fda0d0f68933cf015
git diff --stat 30dd1e2c1bac749a1680e9770263f1cf7987c402..4173929b550ecb60eb8d6e1fda0d0f68933cf015
git diff -U10 30dd1e2c1bac749a1680e9770263f1cf7987c402..4173929b550ecb60eb8d6e1fda0d0f68933cf015
```

For a task-specific range, use the base/head SHAs recorded in
[`sdd-ledger.md`](sdd-ledger.md) or the corresponding report.

## Authority

The evidence archive is historical. Current normative authority remains:

1. `openspec/specs/` and the archived delivery record at
   `openspec/changes/archive/2026-07-27-engagement-v2-security-contracts/`;
2. `src/hackbot/engagement_v2/`;
3. generated `schemas/engagement-v2/` and deterministic fixtures;
4. `docs/engagement-v2-contracts.md`;
5. the current GitHub Issue and Project state plus merged PR #11.

If an old report conflicts with the final code or OpenSpec text, the final
review and current checked-in artifacts govern.
