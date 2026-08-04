# Next steps

Current engagement v2 delivery snapshot. OpenSpec is the behavioral source of
truth; GitHub Project #2 tracks delivery state.

## Delivered phases

- **P0 — security contracts:** canonical values/digests, schemas, fixtures,
  bounded framing, and authority projection are merged and archived.
- **P1 — loader and scope:** atomic coherent snapshots, confirmation bound to the
  authority digest, and typed deny-wins scope are merged and archived.
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
- **P6 — autonomous workflow contracts:** typed state machine, fresh policy per
  step, replay/retry/cancel semantics, evidence dependencies, and cleanup
  barriers are merged and archived. It does not bypass P5b dependencies.

Implementation guides live in `docs/engagement-v2-*.md`; normative requirements
live under `openspec/specs/`.

## Current delivery: P5b credential/L3 catalog

P5b adds only reviewed, code-owned L3 actions for confirmed internal pentests and
operator-owned labs. The catalog remains disabled unless the profile is
`private-pentest` or `local-lab` and internal recon was explicitly confirmed.
Presence in code grants nothing.

Every request must satisfy, in order:

1. confirmed engagement authority bound to the current digest;
2. every target accepted by typed scope;
3. every action capability mapped to an exact Boolean `true` testing rule;
4. prohibited-tool, vulnerability, impact, target-count, concurrency, and rate
   limits;
5. evidence and local/remote execution contracts.

The P5b catalog covers authenticated directory enumeration, credential material
access, bounded validation/capture, exploit verification, payload proof, lateral
access verification, and controlled persistence markers. It excludes DoS,
destruction, bulk exfiltration, and evasion. See
[`engagement-v2-l3-catalog.md`](engagement-v2-l3-catalog.md).

Before merge, P5b still requires fresh full verification, independent review,
finding resolution, Issue #10/Project transition to In Review, and PR merge. The
OpenSpec change is archived only after merge; “Done” requires that archive and a
post-merge verification record.

## Next phase

**P7 — effective migration, active release documentation, and publication** is
next after P5b. It must preserve v1 compatibility until an explicit migration,
perform migration atomically with recovery, update any remaining active docs,
and pass the repository release/publication gates.

## Guardrails that remain invariant

- Discovery never expands authorization or scope.
- Target/tool/MCP output is untrusted data, never executable instruction.
- Secrets never enter argv, logs, reports, fixtures, challenges, or git.
- Shell strings, inline evaluation, and model/target-supplied argv are rejected.
- DoS, destruction, bulk exfiltration, and evasion remain outside P5b.
- CI performs no live credential, capture, exploit, lateral, or persistence
  action; real exercise is isolated-lab-only.
- Stop on unexpected scope/egress change or a target block/rate limit.

## Historical v1 verification snapshot

The recorded pre-engagement-v2 baseline was 912 passing tests out of 913
collected, with one known nmap skip. It is historical evidence only and must not
be reported as a current verification result.
