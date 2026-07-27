## Why

Engagement v2 cannot be implemented safely while security-critical schemas,
canonical digests, protocol limits, lifecycle states, and trust claims remain
prose conventions. P0 turns those design targets into versioned, executable
contracts with golden vectors and negative scenarios so P1–P7 cannot make
incompatible security decisions.

## What Changes

- Add a code-owned engagement-authority contract covering exact versions,
  enums, bounds, canonical security projections, confirmation invalidation, and
  stable validation/denial reasons.
- Add a code-owned action/execution contract covering strict identifiers,
  placeholder grammar, evidence modes, rate-control modes, lifecycle states,
  cleanup states, platform/architecture names, privileges, and shell/elevation
  denial.
- Add a code-owned remote-protocol contract covering canonical encoding,
  bounded frames, total limits, request/response binding, nonce/expiry/replay,
  helper identity, and trust-claim classification.
- Publish machine-readable JSON schemas and golden fixtures generated from the
  same code-owned definitions; drift tests reject hand-maintained divergence.
- Preserve all schema v1 runtime behavior. P0 exposes contract definitions and
  validation primitives but does not route current execution through v2.

Non-goals:

- No engagement v2 loader, migration, action binder, policy decision, secret
  resolution, subprocess execution, SSH transport, internal-recon adapter, or
  autonomous workflow execution.
- No per-action approval or profile-specific capability gate.
- No claim that arbitrary executable semantics or target self-reports can be
  independently proven.

## Capabilities

### New Capabilities

- `engagement-authority-contracts`: Exact v2 authority schemas,
  canonicalization rules, digest projections, bounds, enums, and confirmation
  invalidation requirements.
- `action-execution-contracts`: Exact operator-action, evidence, lifecycle,
  cleanup, rate-control, platform, privilege, and placeholder requirements.
- `remote-runner-protocol-contracts`: Exact framed-protocol, trust-root,
  replay-resistance, executable-identity, privilege-permit, and egress-claim
  requirements.

### Modified Capabilities

None. `openspec/specs/` is empty because this is the first brownfield change.

## Impact

- New isolated Python package under `src/hackbot/engagement_v2/`.
- New machine-readable schemas under `schemas/engagement-v2/`.
- New golden and negative fixtures under `tests/fixtures/engagement_v2/`.
- New unit and drift tests under `tests/engagement_v2/`.
- No change to existing CLI commands or schema v1 execution paths.

Architecture and review sources:

- `docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`
- `docs/reviews/2026-07-26-engagement-v2-spec-reaudit-disposition.md`
- `docs/reviews/2026-07-26-claude-remote-threat-model-disposition.md`
- `docs/reviews/2026-07-26-claude-final-openspec-consistency-review.md`
