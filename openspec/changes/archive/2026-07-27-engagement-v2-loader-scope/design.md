## Context

The archived P0 change created the isolated `hackbot.engagement_v2` contract
package: versioned authority schemas, the `hackbot-canonical-json-v1` value
model, domain-separated `authority_digest`/`execution_digest`, scope primitives,
the closed `ReasonCode` registry, and machine-readable schemas. A P0 guard test
proves no v1 module imports the package. Nothing yet loads a real engagement.

P1 is the first phase that consumes P0 at runtime. It must turn four on-disk
authority documents into one coherent, confirmed, immutable snapshot and decide
v2 targets against a typed scope, without touching schema v1 behavior and
without building the action binder (P2), executor/secrets (P3), remote helper
(P4), or effective migration write path (P7).

Trust assumptions: the operator is trusted to declare engagement authority.
Files are untrusted until validated; a file's contents, timestamps, and any
target self-report remain untrusted. P1 mechanically enforces snapshot
coherence, confirmation binding, and typed scope; it does not decide whether the
operator is legally authorized and it never proves external behavior.

## Goals / Non-Goals

**Goals:**

- Load a coherent v2 snapshot atomically or fail closed, with descriptor-bound
  reads, symlink refusal, and inode recheck.
- Enforce the P0 document limits and strict primitive model on every document,
  surfacing exact P0 reason codes.
- Bind the snapshot to its confirmed authority digest and deny
  `DENY_AUTHORIZATION_STALE`/`DENY_AUTHORIZATION_UNCONFIRMED` before any
  downstream use.
- Provide a stable, secret-free engagement namespace identity.
- Decide targets against typed scope v2 (default-deny, deny-wins) with CIDR
  containment, exclusion-by-overlap, and typed cross-protocol non-authorization.
- Provide a strictly read-only v1→v2 dry-run migration analysis.
- Keep the core dependency-free (PyYAML remains an optional, hardened extra) and
  keep schema v1 behavior identical.

**Non-Goals:**

- No action manifest/binder/policy decision (P2), secret resolution or
  subprocess execution or evidence (P3), SSH/remote helper (P4), autonomous
  workflow (P6), or effective migration write/backup/restore (P7).
- No per-action approval or profile capability gate.
- No re-specification of P0 constants; P1 imports them.

## Decisions

### 1. Snapshot loader is descriptor-first and fail-closed

Open each required document with `O_NOFOLLOW` (refusing symlinks), confirm it is
a regular file, `fstat` the open descriptor, read all bytes from that same
descriptor, then re-`fstat` and require identical `(st_dev, st_ino, st_size,
st_mtime_ns)` — a change means the file moved under us and the load fails with a
`ContractError`. All four documents are validated before any snapshot object is
constructed; a single failure yields no snapshot and no partial authority. The
snapshot object is a frozen dataclass with no setters.

Alternative considered: read-all-then-validate without inode recheck. Rejected
because a mid-write or replacement race could bind inconsistent documents.

Alternative considered: filesystem lock. Rejected as non-portable and
unnecessary given the recheck already detects mutation between reads.

### 2. Decoding goes only through P0 primitives

The loader never calls a raw `json.load`/`yaml.safe_load` into the security
model directly. It uses a hardened decode path that enforces the P0 limits and
strict model: size bound before decode, UTF-8 only, no arbitrary object
construction, and rejection of duplicate/unknown keys, YAML aliases/merge
keys/tags, non-NFC strings, floats, and excessive nesting. Each rejection maps
to its exact P0 `ReasonCode`. YAML is decoded with a custom loader that disables
aliases, merge keys, and tag construction; duplicate keys are detected at the
node level rather than after last-value-wins collapse.

Alternative considered: reuse the v1 program loader. Rejected because v1 does not
enforce the v2 strict primitive model or the canonical projection.

### 3. Confirmation binds the canonical security projection, not raw bytes

After a candidate snapshot is built, the loader computes the security-relevant
projection (scope rules, profile, policy limits, runner trust fields; excluding
notes, comments, key order, local paths, and non-security timeouts), feeds it to
P0 `canonical_bytes`, and takes `authority_digest`. It compares that to
`authorization.json.confirmed_authority_digest`. A mismatch is
`DENY_AUTHORIZATION_STALE`; a non-confirmed or field-incomplete authorization is
`DENY_AUTHORIZATION_UNCONFIRMED`. This makes semantically equivalent
reformatting non-invalidating while any security-relevant change invalidates,
satisfying Issue #2's confirmation criterion and P0 review finding C1.

### 4. Engagement namespace identity is a digest projection

Identity is `sha256:` over a fixed identity projection of the confirmed
authority (never secrets, paths, or timestamps). It is deterministic and changes
exactly when security-relevant authority changes, giving P3/P4 a stable key for
secrets, evidence, and audit without leaking sensitive material.

### 5. Typed scope engine with a closed decision-reason set

Scope v2 is a new engine (not an edit of the v1 `Scope`) keyed by the P0 scope
kinds. Each decision returns an authorized flag plus one value from a closed
`ScopeDenyReason` set (`authorized`, `out-of-scope-no-match`, `excluded-by-rule`,
`cross-protocol-not-authorized`, `unparsable-target`,
`dns-resolution-not-authoritative`). Kinds authorize only compatible target
protocols; `hosts` never suffix-matches; `network_endpoints` require exact
scheme/host/port. CIDR uses `ipaddress` containment on the literal target IP,
exclusions deny on network overlap and win over in-scope matches, and families
never cross. The engine performs no DNS: an undeclared hostname that would
resolve into a CIDR is denied `dns-resolution-not-authoritative`.

Alternative considered: extend v1 `ScopeDecision` free-text reasons. Rejected
because P1 requires stable machine-readable reasons for every sensitive path.

### 6. Dry-run migration is analysis-only

The dry-run transformer validates the v1 engagement, requires an explicit
profile, and builds the proposed v2 tree entirely in memory, emitting proposed
files and warnings. It performs no filesystem write, no temporary sibling tree,
no backup, and no atomic publication. It flags any proposed feature the
installed runtime cannot yet enforce and never presents it as ready to apply.
Effective migration, backup, and restore remain P7.

### 7. Controlled v1→v2 integration boundary

P1 is the first phase where CLI may reach `hackbot.engagement_v2`, and only
through new, explicitly v2 entry points (the v2 loader and the `--dry-run`
analysis). The P0 non-integration guard test is tightened into an allowlist:
exactly the declared v2 entry modules may import `hackbot.engagement_v2`; every
other v1 module (v1 program/risk/scope/tools) still must not, and default v1 CLI
paths must not import it.

## Risks / Trade-offs

- Inode recheck can false-positive on legitimately concurrent edits → Treated as
  fail-closed by design; the operator re-runs against a stable tree.
- Custom hardened YAML decoding could diverge from the P0 model → All decode
  rejections are asserted against P0 `ReasonCode` values and golden fixtures;
  drift fails tests.
- A closed scope-reason set could omit a needed case → The set is small and
  covers match/no-match/exclusion/protocol/parse/DNS; any later kind must extend
  it through an explicit spec change, not ad-hoc strings.
- Namespace identity could accidentally include mutable data → The identity
  projection is an explicit allowlist of security-relevant fields with a golden
  vector; secrets/paths/timestamps are excluded and tested.
- Dry-run could leave a stray temp file → A test asserts the engagement
  directory is byte-for-byte unchanged (snapshot of names, sizes, and hashes
  before and after).

## Migration Plan

1. Add the loader, scope engine, identity, and dry-run analysis modules under
   `src/hackbot/engagement_v2/`, importing only the P0 package and standard
   library.
2. Add synthetic engagement fixtures and tests; tighten the P0 integration guard
   into the v2-consumer allowlist.
3. Wire the read-only `hackbot engagement migrate --dry-run` CLI; leave all v1
   commands unchanged.
4. Verify (full suite, ruff/format, mypy, schema drift, OpenSpec strict, secret
   scan, `git diff --check`), request independent review, merge, and archive.

Rollback is deletion of the P1 modules, CLI wiring, fixtures, and tests, and
reverting the guard to the P0 allowlist. Because P1 writes no engagement data
(dry-run is read-only) and adds no persisted runtime state, rollback migrates no
data.

## Open Questions

None. Exact bounds, enums, digests, and reason codes are fixed by the archived
P0 contracts; the scope decision-reason set and identity projection are fixed by
the delta specs in this change. The forward-carried P0 review note N2
(`argv[0]` == executable path binding) is a P2/P4 obligation and is out of scope
for P1.
