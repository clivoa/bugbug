# Engagement v2 P0 security contracts — independent review disposition

**Date:** 2026-07-27

**Reviewer:** independent read-only subagent (security-focused code review of the
`engagement-v2-security-contracts` change). The reviewer made no repository
changes.

**Scope:** `src/hackbot/engagement_v2/` (constants, errors, canonical, patterns,
protocol, schemas), the generated `schemas/engagement-v2/` documents, and
`tests/engagement_v2/`, checked against the three P0 delta specs and `design.md`.

## Summary

The reviewer's verdict is **solid**: the implementation faithfully and safely
realizes the three normative specs. No exploitable defect was found — no
canonical collision, no wrongly-rejected valid input, no backtracking or
unbounded matcher path, no length field trusted before it is bounded, and the
v1 non-integration guarantee is genuinely proven. All 245 focused contract
tests pass, schema/fixture drift checks pass, and every committed schema hash
matches the manifest.

Verification (separate independent run): 1157 passed / 1 skipped / 0 failed;
`ruff check`, `ruff format --check`, and `mypy src/hackbot` clean; OpenSpec
strict validation of the change passes; fixtures and schemas reproduce their
committed bytes exactly; the secret-scan regex over the P0 paths is clean;
`git diff --check` and the working tree are clean.

## Finding disposition

Only informational notes were raised. None blocks P0.

| ID | Note | Disposition |
|---|---|---|
| N1 | Roughly half of the 26 registry reason codes are defined but not yet emitted (loader/policy/runner `INVALID_*`, `DENY_*`, replay/permit/evidence/cleanup `EXEC_*`/`CLEANUP_*`), because P0 ships contracts and primitives with no consumer. | Accepted, by design. This matches the proposal Non-goals and `design.md` §6. Those spec scenarios are contract text awaiting P1–P4 consumers; P0 actively emits `INVALID_LIMIT`, `INVALID_CANONICAL_VALUE`, `INVALID_ACTION_MANIFEST`, `EXEC_PROTOCOL_INVALID`, `EXEC_PROTOCOL_EXPIRED`, and `EXEC_TRUST_MISMATCH`. |
| N2 | The remote header carries both `argv` and `executable.path`, but the P0 protocol validator does not assert `argv[0] == executable.path`; that binding lives in the P2 action binder and its P4 consumer. | **Forward-carry.** Recorded as an explicit acceptance criterion for P2 (action binder) and P4 (remote helper): the consumer MUST bind `argv[0]` to the canonical executable path. Not a P0 defect because P0 does not open a socket or spawn a child. |
| N3 | Control-character rejection also rejects `0x7F` (DEL), slightly broader than the literal "C0/C1" spec wording. | Accepted. Stricter and safe; no change. |
| N4 | `manifest.json` encodes contract versions implicitly via the `schema_id` URN suffix (e.g. `:program:2`) rather than as explicit version fields. | Accepted. Cosmetic; the version is unambiguously present in each schema id. May be revisited if a later phase needs an explicit version field. |

## Delivery consequence

P0 was approved and subsequently merged and archived. The forward-carry item
N2 is the only finding that changes later work: it remains an explicit
binder/consumer obligation for P2 and P4 so no consumer assumes P0 already
enforces the `argv[0]`/executable binding.

## Publication note

The reviewed feature branch was pushed to the private
`github.com/clivoa/bugbug` remote under the documented recon
publication-guard override (`HACKBOT_ALLOW_PUBLISH_RECON=1`) because the
tracked, unlicensed Recon artifacts remain in the tree. The remote
already holds that material under the 2026-07-26 authorization; this push added
no new protected material and no new destination.

PR #11 merged as `7fcebb3`. The OpenSpec change and current specs were published
as `268b9fb`; Issue #1 and both P0 Project items are Done, and P1 is Ready.

## Status

All findings have a concrete disposition. P0 verification, independent review,
merge verification, archive, and OpenSpec/GitHub delivery are complete.
