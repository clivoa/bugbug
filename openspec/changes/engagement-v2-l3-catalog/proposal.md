## Why

P5a delivered non-credential internal reconnaissance, but P5b still has only an
inert credential/L3 catalog prototype. Independent review found that catalog
loading is not bound to the snapshot evaluated by P3, several declared adapters
do not exist, tool destinations and rate controls are not mechanically enforced,
and synthetic fixtures cannot demonstrate executable safety. P5b therefore
needs to deliver the complete, fail-closed executable layer rather than publish
definitions that appear runnable without an enforced runtime.

## What Changes

- Deliver exactly 15 code-owned `operator.internal.*` L3 actions covering:
  authenticated directory enumeration (policies, SPNs, ADCS, AD graph),
  credential material access (AS-REP, Kerberoasting, LAPS, gMSA), validation and
  capture (bounded password spray and separate Responder analyze/capture), and
  controlled exploit, payload, lateral, and persistence proofs.
- Bind catalog activation, the P3 decision, typed inputs, targets, tool identity,
  network policy, rate policy, and evidence schema to the same immutable
  engagement snapshot through a signed, short-lived, single-use
  `ExecutionPermitV2`.
- Add a versioned Linux `hackbot-l3-runner` broker with one typed, code-owned
  adapter per action. The broker accepts no shell text, arbitrary argv, script,
  payload, command, or unreviewed exploit module.
- Execute upstream tools only from OCI images pinned by immutable digest. Record
  source revision, base image, built image, platform, and SBOM digests in a
  repository lockfile; drift fails closed and invalidates affected promotion
  receipts.
- Enforce default-deny network namespaces, exact IP/port/protocol allowlists,
  DNS revalidation, durable replay protection, persistent rate budgets, bounded
  resources, secret delivery through ephemeral files/stdin/Kerberos caches, and
  independent resource/target cleanup.
- Replace free-form sensitive output with closed, action-specific structured
  results. Raw credential material, tickets, hashes, passwords, and reusable
  authentication data are discarded and never enter permits, argv, environment,
  logs, evidence, reports, fixtures, or repository artifacts.
- Add a disposable remote lab with no route to the LAN or Internet and an
  individually addressable E2E test for every action. An action progresses from
  `implemented` to `isolated-e2e-passed` to `executable`; source presence never
  enables it.
- Preserve schema v1 behavior. Extend the existing P0/P3/P4 Ed25519 permit,
  replay, framing, and fixed-SSH primitives instead of introducing a second
  authority or transport path.

Explicit non-goals:

- denial of service, destructive testing, data exfiltration, detection evasion,
  persistence surviving the verification run, or automatic action chaining;
- generic shell/container execution or operator/model-provided commands,
  scripts, payloads, modules, or raw tool arguments;
- treating the SSH control endpoint as a test target;
- running live credential, capture, exploit, payload, lateral, or persistence
  actions in public GitHub Actions.

## Capabilities

### New Capabilities

- `l3-offensive-catalog`: A snapshot-bound executable catalog of 15 reviewed L3
  actions, implemented through typed Linux adapters and digest-pinned OCI tools,
  with durable authorization/replay/rate state, network containment, ephemeral
  secrets, closed evidence, mandatory cleanup, and per-action isolated E2E
  promotion.

### Modified Capabilities

None. P5b extends implementation of the archived P0-P5a contracts without
changing schema v1 requirements.

## Impact

- Extend `src/hackbot/engagement_v2/**` with exact L3 definitions, permit
  issuance/verification, durable replay and rate state, broker lifecycle,
  containment, typed adapters, closed results, promotion receipts, and recovery.
- Add OCI build inputs and a generated digest/SBOM lockfile for OpenLDAP,
  NetExec, Impacket, Certipy, BloodHound.py, Responder, and code-owned proof
  adapters.
- Add a disposable lab and remote opt-in E2E harness. Public CI remains
  non-offensive and verifies contracts, parsers, fixtures, lockfiles, promotion
  receipts, documentation drift, and absence of secrets.
- Update operator, security, architecture, catalog, runner, lab, recovery, and
  verification documentation; update GitHub Issue #10 and Project #2 through
  delivery.
- The Linux runner needs Docker, nftables/network namespaces, SQLite, and the
  pinned Hackbot broker. macOS remains the control plane.

Architecture and review sources:

- `docs/superpowers/specs/2026-08-01-engagement-v2-p5b-executable-layer-design.md`
- `docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`
- `docs/reviews/2026-08-01-engagement-v2-p5b-verification.md`
- `openspec/specs/action-manifest/spec.md`, `openspec/specs/policy-v2/spec.md`,
  and `openspec/specs/evidence-redaction/spec.md`
- GitHub Issue #10 and Project #2
