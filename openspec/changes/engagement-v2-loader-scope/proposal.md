## Why

The archived P0 change (`engagement-v2-security-contracts`) froze the v2
authority versions, canonical value model, domain-separated digests, scope
primitives, and reason codes, but nothing yet loads a real engagement through
them. Until a fail-closed loader binds a coherent on-disk snapshot to its
confirmed-authority digest and a typed scope engine decides v2 targets,
engagement v2 has contracts without an enforcement surface, and P2–P7 have no
authority snapshot to consume. P1 delivers that loader and scope decision layer
while leaving schema v1 untouched.

## What Changes

- Add a fail-closed **engagement v2 snapshot loader** that reads
  `program.yaml`, `scope.yaml`, `authorization.json`, and `runner.json` through
  bounded, symlink-refusing, inode-rechecked descriptors, validates each against
  the P0 contract layer, and either publishes one coherent immutable snapshot or
  fails closed. A mixed or mid-read set of files never becomes a usable
  snapshot.
- Add **confirmed-authority verification**: the loader recomputes the P0
  `authority_digest` over the security-relevant projection of the loaded
  snapshot and compares it to `authorization.json`'s
  `confirmed_authority_digest`. Any security-relevant mismatch denies with
  `DENY_AUTHORIZATION_STALE` before any downstream binding; an unconfirmed or
  structurally invalid authorization denies with its exact P0 reason. This
  introduces no per-action approval.
- Add a **typed scope v2 engine** over the P0 scope kinds (`domains`,
  `wildcard_domains`, `urls`, `hosts`, `cidrs`, `network_endpoints`, and
  `out_of_scope`). It stays default-deny and deny-wins, resolves CIDR
  membership by literal-IP containment, applies exclusions by overlap, and
  enforces typed cross-protocol non-authorization (a web-domain rule never
  authorizes LDAP/SMB/SSH/RDP/WinRM/arbitrary TCP-UDP, and DNS resolution never
  widens scope).
- Add a stable **engagement namespace identity** derived from the confirmed
  authority so later phases can key secrets, evidence, and audit to one
  engagement.
- Add a **dry-run migration analysis** (`hackbot engagement migrate … --to 2
  --dry-run`, or the equivalent read-only entry) that validates a v1 engagement,
  requires an explicit profile, and reports the proposed v2 files and warnings
  **without writing anything**.
- Preserve all schema v1 behavior. v1 engagements keep their loader, caller and
  approval semantics, and exit codes; no v1 engagement silently gains v2
  behavior.

Non-goals:

- No action manifest, typed binder, rate-control contract, or policy decision
  (P2).
- No secret resolution, private working directory, subprocess execution,
  evidence writing, or cleanup (P3).
- No SSH transport, remote helper, or privilege permit (P4).
- No effective migration write path, backup, or restore, and no CLI that
  mutates an engagement to v2 (P7); P1 delivers dry-run analysis only.
- No autonomous workflow schema or state machine (P6).

## Capabilities

### New Capabilities

- `engagement-v2-loader`: Atomic, fail-closed loading of a coherent v2
  engagement snapshot; input hardening; confirmed-authority digest verification
  with `DENY_AUTHORIZATION_STALE`; and stable engagement namespace identity.
- `scope-v2`: Typed default-deny, deny-wins scope decisions over v2 scope kinds,
  CIDR containment and exclusion-by-overlap, typed cross-protocol
  non-authorization, and hypothesis re-validation before reuse.
- `engagement-migration-dryrun`: Read-only v1→v2 migration analysis that
  requires an explicit profile and never writes engagement files.

### Modified Capabilities

None. P1 consumes the archived P0 contracts (`engagement-authority-contracts`,
`action-execution-contracts`, `remote-runner-protocol-contracts`) without
changing their requirements, and does not alter the existing schema v1
capabilities.

## Impact

- New code under `src/hackbot/engagement_v2/` (loader, scope, identity, and
  dry-run migration analysis modules) that imports the P0 contract package.
  P1 is the first phase in which existing CLI surface may reach the v2 package,
  and only through new, explicitly v2 entry points; the P0 non-integration
  guard is updated to allow exactly those declared consumers and no more.
- New CLI: read-only `hackbot engagement migrate … --dry-run` analysis output.
  No existing v1 command changes behavior.
- New unit and property tests under `tests/engagement_v2/` plus deterministic,
  synthetic engagement fixtures under `tests/fixtures/engagement_v2/`.
- No new runtime dependency; PyYAML remains an optional extra used only through
  the hardened, alias/merge/tag-free parsing path.

Architecture and review sources:

- `docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`
- `docs/reviews/2026-07-27-engagement-v2-p0-contracts-review-disposition.md`
- `openspec/specs/engagement-authority-contracts/spec.md`
- `openspec/specs/action-execution-contracts/spec.md`
- `openspec/specs/remote-runner-protocol-contracts/spec.md`
- GitHub delivery: Issue #2.
