# Engagement v2 P3 local executor — independent review disposition

**Date:** 2026-07-27

**Reviewer:** independent read-only subagent (security-focused code review of the
`engagement-v2-executor` change — the first phase that spawns subprocesses). The
reviewer made no repository changes.

**Scope:** `src/hackbot/engagement_v2/{executor,secrets,evidence}.py` and their
tests, checked against the four P3 delta specs, `design.md`, the archived P0
`action-execution-contracts`, and the v1 runner for comparison.

## Summary

The reviewer confirmed the gate itself is well-constructed (ALLOW-only spawn, no
shell, no request-controlled argv, namespaced secrets with no un-namespaced
fallback, sanitized minimal env, private 0700 CWD/HOME/TMPDIR, process-group
kill) but found one **HIGH fail-open** and several correctness/faithfulness gaps.
The blocking issue and the two mediums are **fixed**; the remaining items are
addressed or recorded as explicit follow-ups.

## Finding disposition

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| F1 | High | Only `SecretResolutionError` was caught, so any other exception after the private dir was created (trivially, a missing bound executable → `FileNotFoundError` in `Popen`) left the resolved secret in a mode-0600 file on disk with no cleanup and no audit, and propagated. | **Fixed.** The whole post-dir body is wrapped: an `OSError` from spawn becomes a fail-closed abort, and any other exception routes through `_resource_cleanup` before re-raising. The failure returns `executed=False` with a secret-free, path-free reason. Test `test_spawn_failure_cleans_up_secret_and_fails_closed` asserts no secret file or run dir survives and the reason leaks neither the secret nor the path. |
| F2 | Medium | `communicate()` buffered the child's entire stdout/stderr into memory; the cap was applied only afterward, so a hostile tool could OOM before the cap. | **Fixed.** Output is now read by bounded reader threads that stop appending past the cap (bytes beyond the cap are read and discarded), matching the v1 runner; a `truncated` flag is surfaced. |
| F3 | Medium | `structured` evidence mode was not gated on `output_persistence_allowed` and fell through to storing redacted raw stdout/stderr, partially circumventing the persistence policy. | **Fixed.** `check_evidence_mode` now gates both `redacted-output` and `structured` on the persistence policy, and `_finalize_evidence` stores redacted stdout/stderr only for `redacted-output`; `structured` (and `metadata-only`) store no raw output. Tests `test_structured_mode_requires_persistence`, `test_structured_mode_stores_no_raw_output`. |
| F4 | Medium/Low | The incomplete-cleanup marker was written inside the doomed private dir, not a stable location, and declared file-output (`retained_outputs`) retention is unimplemented. | **Partially fixed.** The marker is now written under a stable `base_dir/cleanup/` location. Declared file-output retention beyond stdout/stderr remains a recorded follow-up (it fails safe: the whole private tree is removed, so no undeclared file becomes evidence). |
| F5 | Low | Lifecycle only ever emitted `validated`/`prepared`/`finalized`. | **Fixed (observability).** `ExecutionResult` now carries a `states` trace of the ordered P0 lifecycle progression for each path. |
| F6 | Low | The audit `argv_projection` contained the secret **binding name** (`{secret_file:api_key}`). | **Fixed.** The projection now strips placeholder ids (`{secret_file:api_key}` → `{secret_file}`), so no binding name enters audit. |

### Nits

- `_kill_group` now calls `proc.wait()` after SIGKILL to reap the group.
- The design's "zeroed after cleanup" wording is corrected (Python `bytes` are
  immutable); values are dropped after the run.
- Redaction remains exact-byte (defense-in-depth), consistent with the v1
  redactor; the capability gate (P2), not redaction, is the control that permits
  a credential capability.
- An empty engagement identity now fails closed when secrets are required.

## Recorded follow-ups (documented, not blocking)

- Declared **file** outputs (`retained_outputs`) are not yet copied into
  persisted evidence; P3 retains redacted stdout/stderr and removes the whole
  private tree. Retained-file plumbing is a bounded follow-up.
- A dedicated v2 execution CLI entry is not yet wired; `run` is a library entry.

## What the reviewer confirmed solid

ALLOW-only spawn with no shell and no request-controlled argv; `argv[0]` is the
bound executable; `_materialize` accepts only `str`/`SecretReference`/
`targets_file` and raises otherwise; namespaced secret lookup with no
un-namespaced fallback; sanitized minimal environment; private 0700
CWD/HOME/TMPDIR; and process-group termination.

## Status

The HIGH fail-open and both mediums are fixed with tests; the lows are fixed or
recorded. Verification after the fixes: 1288 passed / 2 skipped; ruff, format,
mypy, OpenSpec strict, secret scan, and `git diff --check` clean. P3 is cleared
to open its PR (against `main`, since P1 and P2 are merged).
