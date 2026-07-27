## Why

The engagement v2 engine (P0–P4) can load, bind, decide, execute, and remotely
run operator actions, but ships no internal-recon actions. The umbrella design
turns `internal-recon` from a hard-disabled profile gate into a **category** with
explicit per-action risk and capability classification, and removes the old
invariant that internal notes can never be promoted. P5a delivers the first
reviewed, **non-credential** slice of that catalog — host discovery, service
enumeration, anonymous LDAP, and local network-state inspection — as code-owned,
provenance-tagged actions with harmless lab fixtures. Credential and L3 material
access remain out of scope (P5b).

## What Changes

- Add a code-owned, reviewed **non-credential internal-recon action catalog**
  validated by the P2 action-manifest contract, covering exactly these
  categories at their classified levels:
  - **local network state** (interfaces, routes, neighbors, listeners) — L1;
  - **host discovery** (ARP/ICMP/Nmap host discovery) — L2, `automated-scanning`;
  - **service enumeration** (port/banner, SMB/NetBIOS discovery) — L2,
    `automated-scanning`;
  - **anonymous LDAP** (naming contexts, users, groups) — L2,
    `automated-scanning`.
  Each action declares an absolute executable, platform/architecture, typed
  parameters and whole-token placeholders, rate control, risk level, capabilities,
  vulnerability types, impacts, and an evidence mode — never a shell string and
  never a copied multi-tool pipeline.
- Add **provenance** for every action: a code-owned mapping from each action to
  its reviewed source skill/category, classification, and attribution, with a
  test that every catalog action has provenance and that **no L3 / credential /
  capture category** appears in this non-credential catalog.
- Add **harmless, disposable lab fixtures** (synthetic hosts/subnets/endpoints
  and recorded tool-output samples) with no real target or credential material,
  used to test classification and adapter shape without live scanning.
- Keep `internal-recon` **disabled by default**: these actions load only under a
  `private-pentest`, `local-lab`, or explicitly-authorized internal profile with
  explicit confirmation; a category action in a manifest never self-enables, and
  discovery of an internal hostname/RFC1918/LDAP endpoint never enables it.
- Preserve schema v1 behavior and the existing recon-bundle promotion; P5a adds
  the v2 non-credential internal-recon catalog and does not change v1 actions.

Non-goals:

- No credential material access, capture, spraying, relay, or poisoning
  (`credential-access`/`credential-capture`) — that is **P5b (L3)**.
- No authenticated directory enumeration that reads sensitive data, exploit
  verification, payload/post-exploitation, lateral movement, persistence, or
  exfiltration/DoS/destruction (all L3, later).
- No execution wiring beyond what P2/P3/P4 already provide; P5a delivers reviewed
  action definitions, provenance, fixtures, and tests — it does not run scans in
  CI.
- No promotion of raw bundle pipelines; only a reviewed generic single-tool argv
  subset per action.

## Capabilities

### New Capabilities

- `internal-recon-catalog`: A reviewed, provenance-tagged, non-credential
  internal-recon action catalog (host discovery, service enumeration, anonymous
  LDAP, local network state) classified to exact risk levels and capabilities,
  validated by the P2 manifest contract, disabled by default, with harmless lab
  fixtures and classification tests.

### Modified Capabilities

None. P5a consumes the archived P0–P4 contracts and capabilities without changing
their requirements, and does not alter the v1 recon-bundle promotion.

## Impact

- New reviewed artifacts under `skills/internal-recon/**` (per-action reviewed
  skill notes with argv subset, classification, and provenance) and a code-owned
  catalog manifest plus provenance module under `src/hackbot/engagement_v2/` (or
  `src/hackbot/skills/`), validated by the P2 manifest validator.
- New deterministic synthetic fixtures under `tests/fixtures/engagement_v2_recon/`
  (example subnets/hosts/endpoints and recorded output samples) and classification
  tests under `tests/engagement_v2/`.
- No new runtime dependency; the actions reference external tools (`ip`, `ss`,
  `nmap`, `ldapsearch`) by absolute path but P5a does not execute them in tests.

Architecture and review sources:

- `docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`
  (Internal-recon and L3 catalog)
- `docs/skill-promotion.md` and `src/hackbot/skills/promotion.py`
- `openspec/specs/action-manifest/spec.md` and `openspec/specs/policy-v2/spec.md`
- CLAUDE.md and SECURITY.md internal-recon rules
- GitHub delivery: Issue #6.
