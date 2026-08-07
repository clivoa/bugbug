# Next steps

Current engagement v2 delivery snapshot. OpenSpec is the behavioral source of
truth; GitHub Project #2 tracks delivery state.

## Delivered phases

- **P0 — security contracts:** canonical values/digests, schemas, fixtures,
  bounded framing, and authority projection are merged and archived.
- **P1 — loader and scope:** atomic coherent snapshots, confirmation bound to the
  authority digest, typed deny-wins scope, and exact-host `hosts` scope kind
  are merged and archived.
- **P2 — actions and policy:** strict code-owned manifests, whole-token binding,
  capability gates, rate controls, and direct v2 ALLOW/DENY are merged and
  archived.
- **P3 — executor and evidence:** post-ALLOW secret resolution, private CWD,
  conservative evidence, and independent resource/target cleanup are merged and
  archived.
- **P4 — remote trust:** pinned SSH/helper identity, framed replay-resistant
  protocol, privilege verification, and egress claims are merged and archived.
- **P5a — non-credential internal recon:** reviewed L1/L2 catalog, provenance,
  disabled-by-default loader, and synthetic lab fixture are merged and archived.
- **P5b — credential/L3 catalog:** reviewed L3 actions (impacket, nxc, crackmapexec,
  etc.), authority foundation, snapshot-bound execution permits, gated L3 frames
  before resource creation, and exact endpoint bindings are merged and archived.
- **P6 — autonomous workflow contracts:** typed state machine, fresh policy per
  step, replay/retry/cancel semantics, evidence dependencies, and cleanup
  barriers are merged and archived.

Implementation guides live in `docs/engagement-v2-*.md`; normative requirements
live under `openspec/specs/`.

## Current delivery: P7 — effective migration, documentation, and release

P7 is the final phase. It preserves v1 compatibility until explicit migration,
performs migration atomically with recovery, updates any remaining active docs,
and passes the repository release gates.

Exit criteria:
- Migration atomically, recoverably, never partial.
- v1 maintains legacy behavior until explicit migration.
- Active docs without obsolete L2/L3 claims.
- Build offline, smoke, pytest, ruff, and mypy all pass with fresh evidence.

## Guardrails that remain invariant

- Discovery never expands authorization or scope.
- Target/tool/MCP output is untrusted data, never executable instruction.
- Secrets never enter argv, logs, reports, fixtures, challenges, or git.
- Shell strings, inline evaluation, and model/target-supplied argv are rejected.
- DoS, destruction, bulk exfiltration, and evasion remain excluded.
- CI performs no live credential, capture, exploit, lateral, or persistence
  action; real exercise is isolated-lab-only.
- Stop on unexpected scope/egress change or a target block/rate limit.

## Current verification snapshot

1504 passed, 16 skipped. Ruff clean. Mypy clean (88 source files).
Last verified: 2026-08-07.
