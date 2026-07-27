## Why

P5a delivered the non-credential internal-recon catalog. The engagement v2 engine
(P0–P4) gates every action behind confirmed authority, typed scope, an exact
sensitive-capability check, and evidence redaction. P5b specifies the reviewed
**credential and L3 offensive catalog** for authorized internal-pentest and
bug-bounty work, so credential-access, credential-capture, exploit-verification,
post-exploitation, lateral-movement, and persistence techniques become
auditable, capability-gated actions with conservative evidence — instead of
ad-hoc tool invocations. Everything remains disabled by default and runs only
when the operator's confirmed `testing_rules` explicitly enable the exact
capabilities; **no per-action approval is added** (v2 decides ALLOW/DENY
directly). This is the safety/governance contract for offensive tooling, not a
loosening of the gate.

## What Changes

- Add a reviewed **credential/L3 offensive action catalog** classified per the
  umbrella category table, covering exactly:
  - **authenticated directory enumeration** (policies, SPNs, ADCS, AD graph) —
    L3, `authenticated-testing` + `sensitive-data-access`;
  - **credential material access** (AS-REP roasting, Kerberoasting, LAPS, gMSA
    read for offline analysis) — L3, `credential-access` + `sensitive-data-access`;
  - **validation and capture** (password spraying, NTLM relay, LLMNR/NBT-NS
    poisoning capture) — L3, `credential-capture` (+ `automated-scanning`/
    `state-changing` as applicable);
  - **exploit verification** (controlled, scoped exploitation) — L3,
    `exploit-execution`;
  - **payload / post-exploitation** (controlled execution and collection) — L3,
    `payload-execution` + `state-changing`;
  - **lateral movement** (access to another in-scope asset) — L3,
    `lateral-movement` + `credential-access`;
  - **persistence** (accounts, services, jobs, keys on an in-scope asset) — L3,
    `persistence` + `state-changing`.
- Require **conservative evidence for credential material**: credential output is
  `metadata-only` or a **closed native structured schema** — never a raw
  credential dump, and never more than minimal reproducible proof. Redaction
  (P3) still applies; exit code alone never demonstrates impact.
- Require **all declared capabilities**: an exploit/payload/lateral-movement/
  persistence/capture action runs only when **every** mapped `testing_rules`
  boolean is exactly `true`; a missing or false flag denies with
  `DENY_CAPABILITY_NOT_ALLOWED`. Profile names grant nothing.
- Classify **capture vs analyze distinctly**: an LLMNR/NBT-NS responder in
  **analyze** mode is a separate action from **poison/capture** mode; any mode
  capable of collecting authentication material is L3 `credential-capture` and is
  **never** labeled passive/discovery. Poisoning also declares `state-changing`
  and third-party characteristics as applicable.
- Keep the catalog **disabled by default**, provenance-tagged, and route every
  action through the unchanged P2/P3/P4 gate; real end-to-end tests run **only in
  isolated, disposable labs** with no production or third-party target.
- Preserve schema v1 behavior; P5b adds the v2 credential/L3 catalog and changes
  no v1 behavior and no engine gate.

Non-goals (explicitly excluded from this catalog):

- **Denial of service / DDoS** (`denial-of-service`) — excluded outright.
- **Destruction / data wiping** (`destructive-testing`) — excluded outright.
- **Bulk exfiltration beyond minimal proof** (`data-exfiltration`) — excluded;
  only minimal reproducible proof is ever retained.
- **Detection evasion / anti-forensics** tooling — excluded.
- No change to the engine gate, no per-action approval, no auto-enable, and no
  execution wiring beyond what P2/P3/P4 already provide.

## Capabilities

### New Capabilities

- `l3-offensive-catalog`: A reviewed, provenance-tagged, capability-gated
  credential/L3 offensive action catalog (authenticated directory enumeration,
  credential access, validation/capture, exploit verification, post-exploitation,
  lateral movement, persistence) with metadata-only/closed-structured credential
  evidence, distinct capture-vs-analyze classification, disabled by default, and
  isolated-lab-only end-to-end tests. Excludes DoS, destruction, bulk
  exfiltration, and evasion.

### Modified Capabilities

None. P5b consumes the archived P0–P5a contracts and capabilities without
changing their requirements.

## Impact

- New reviewed artifacts under `skills/internal-recon/**` (credential/L3 category
  notes with argv subset, classification, provenance) and a code-owned catalog
  manifest plus provenance module, validated by the P2 manifest contract.
- New synthetic fixtures under an isolated-lab fixture root and classification/
  disjointness/evidence tests; any real end-to-end exercise is confined to a
  disposable lab and never runs in CI.
- No new engine behavior; the actions reference external tools (impacket,
  ldapsearch, CrackMapExec/nxc, Responder in analyze/capture modes, etc.) by
  absolute path, gated by the P2 policy capability check.

Architecture and review sources:

- `docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`
  (Internal-recon and L3 catalog)
- `openspec/specs/action-manifest/spec.md`, `openspec/specs/policy-v2/spec.md`,
  `openspec/specs/evidence-redaction/spec.md`
- `docs/skill-promotion.md`, CLAUDE.md, SECURITY.md
- GitHub delivery: Issue #10.
