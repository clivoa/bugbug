## Context

P0–P4 delivered the engagement v2 engine: contracts, loader/scope, manifest/
binder/policy, local executor, and remote helper. No internal-recon actions
exist yet. The umbrella design reclassifies `internal-recon` from a hard-disabled
profile gate into a category with per-action risk/capability classification and
removes the old "internal notes can never be promoted" invariant. P5a delivers
the first reviewed, non-credential slice.

The recon bundle (`references/recon/Recon-bundle.html`, CyberNeon Recon Bundle,
unlicensed) remains inert data: only a reviewed generic single-tool argv subset
is promoted, with attribution, never a copied pipeline. Internal recon stays disabled by
default; P5a ships definitions, provenance, fixtures, and tests, not live scans.

## Goals / Non-Goals

**Goals:**

- Ship a code-owned, reviewed non-credential internal-recon catalog (local
  network state L1; host discovery, service enumeration, anonymous LDAP L2) that
  validates against the P2 manifest contract.
- Attach provenance to every action and prove, by test, that no L3/credential/
  capture/sensitive-data action is in this catalog.
- Provide harmless, disposable-lab fixtures and classification tests that run no
  external scanner.
- Keep internal recon disabled by default and non-self-enabling.

**Non-Goals:**

- No credential/capture/spraying/relay/poisoning or any L3 category (P5b).
- No new execution wiring beyond P2/P3/P4; no live scanning in CI.
- No promotion of raw bundle pipelines; no change to v1 recon-bundle promotion.

## Decisions

### 1. The catalog is a code-owned v2 action manifest

The catalog is a code-owned `actions.yaml`-shaped structure validated by the P2
`validate_manifest`, so its identifiers, bounds, executables, placeholders, rate
control, evidence modes, and capabilities are contract-checked. Each action is an
`operator.internal.<category>.<tool>` id with an absolute executable
(`/usr/bin/ip`, `/usr/bin/ss`, `/usr/bin/nmap`, `/usr/bin/ldapsearch`), a
whole-token argv subset, and its exact classification.

Alternative considered: free-form skill YAML only. Rejected — routing the catalog
through the P2 validator guarantees it is a well-formed, gate-compatible manifest.

### 2. Classification is explicit and tested against the umbrella table

Each action's risk level and capabilities are set from the umbrella category
table: local network state → L1; host discovery/service enumeration/anonymous
LDAP → L2 with `automated-scanning`. A test asserts every action's level and
capabilities and that the non-credential capability set is disjoint from the
credential/capture/sensitive-data/L3 set. Anonymous LDAP is strictly the
unauthenticated naming-context/user/group read; anything reading sensitive
directory data or credential material is excluded (P5b).

### 3. Provenance is a code-owned mapping with attribution

`internal_recon_provenance` maps each action id to its reviewed source
skill/category, classification, and attribution. A test asserts every catalog
action has provenance and no catalog action maps to a credential/L3 source.
Reviewed skill notes under `skills/internal-recon/**` record the argv subset and
classification for auditability; the raw bundle HTML is never read.

### 4. Disabled by default is preserved

The catalog is data plus a loader that yields actions only under an authorized
internal profile with explicit confirmation. Presence in a manifest never
self-enables; discovery of internal hostnames/RFC1918/LDAP endpoints never
enables it. This matches CLAUDE.md and SECURITY.md and is covered by a guard test.

### 5. Fixtures are synthetic and scanner-free

Fixtures use example subnets (`10.20.0.0/24`), example hosts, and recorded
tool-output samples with no real target or credential material, under a disposable
`tests/fixtures/engagement_v2_recon/` root. Tests exercise classification and
adapter shape only; no test invokes `ip`/`ss`/`nmap`/`ldapsearch`.

## Risks / Trade-offs

- A credential action could slip into the non-credential catalog → a disjointness
  test asserts the catalog's capability set excludes credential/capture/
  sensitive-data/L3; adding one fails CI.
- A copied bundle pipeline could be promoted → the P2 manifest validator rejects
  shell/inline-eval and multi-tool tokens; only single-tool argv subsets validate.
- Internal recon could self-enable → a guard test proves presence-in-manifest and
  discovered-internal-data do not enable the catalog.
- Provenance drift → every action is asserted to have a provenance record with
  attribution; a new action without one fails.

## Migration Plan

1. Add the code-owned catalog manifest and provenance module, the reviewed
   `skills/internal-recon/**` notes, and synthetic fixtures.
2. Add classification, provenance, disjointness, disabled-by-default, and
   manifest-validation tests (no external scanner).
3. Verify (full suite, ruff/format, mypy, OpenSpec strict, secret scan,
   `git diff --check`), request independent review, merge, archive.

Rollback removes the catalog, provenance, skill notes, fixtures, and tests. P5a
adds no execution path and no persisted state; rollback migrates no data.

## Open Questions

None. Categories, levels, and capabilities are fixed by the umbrella table; the
manifest contract is fixed by P2; the disabled-by-default rule is fixed by
CLAUDE.md/SECURITY.md. Credential and L3 categories are P5b.
