# engagement-v2-loader Specification

## Purpose
TBD - created by archiving change engagement-v2-loader-scope. Update Purpose after archive.
## Requirements
### Requirement: Atomic coherent engagement snapshot
The loader SHALL read the v2 authority documents (`program.yaml`, `scope.yaml`,
`authorization.json`, and, when present, `runner.json`) and either publish one
immutable in-memory snapshot in which every document validated against the P0
contract layer, or fail closed and publish nothing. A partially read, mixed, or
mid-write set of files MUST NOT become a usable snapshot.

Each security-critical file SHALL be opened without following symlinks, SHALL be
required to be a regular file, and SHALL have its file identity (device and
inode) rechecked after opening so that a file replaced between discovery and
read is rejected rather than trusted. All bytes for one document SHALL be read
from a single stable descriptor.

#### Scenario: Coherent set produces one snapshot
- **WHEN** all required v2 documents are present, individually valid, and unchanged during the read
- **THEN** the loader returns exactly one immutable snapshot and performs no downstream binding on failure paths

#### Scenario: Mid-read replacement fails closed
- **WHEN** any authority file is replaced, truncated, or its inode changes between discovery and completion of the read
- **THEN** the loader raises a `ContractError` and returns no snapshot

#### Scenario: Symlinked authority file is refused
- **WHEN** a required authority path is a symlink or a non-regular file
- **THEN** the loader fails closed with `INVALID_DOCUMENT_STRUCTURE` and returns no snapshot

#### Scenario: One invalid document denies the whole snapshot
- **WHEN** exactly one of the required documents fails P0 contract validation
- **THEN** the loader returns no snapshot and no partial authority is exposed to any consumer

### Requirement: Hardened document decoding
The loader SHALL enforce the P0 document limits and strict primitive model on
every authority document: bounded encoded size checked before decoding, UTF-8
only, no arbitrary object construction, and rejection of duplicate keys, unknown
keys, YAML aliases, merge keys, explicit tags, invalid Unicode, non-NFC strings,
floats, excessive nesting, and unsupported versions. Each failure SHALL surface
its exact P0 reason code.

#### Scenario: Oversized document rejected before decode
- **WHEN** an encoded authority document exceeds its P0 byte limit
- **THEN** decoding fails with `INVALID_DOCUMENT_SIZE` before a parser allocates from its content

#### Scenario: Duplicate key rejected
- **WHEN** any authority mapping repeats a key at any depth
- **THEN** decoding fails with `INVALID_DUPLICATE_KEY` and produces no snapshot

#### Scenario: Unsupported version rejected
- **WHEN** a document declares a version other than its P0-listed value
- **THEN** decoding fails with `INVALID_SCHEMA_VERSION`

#### Scenario: YAML alias or merge key rejected
- **WHEN** `scope.yaml` contains a YAML alias, merge key, or explicit tag
- **THEN** decoding fails with `INVALID_DOCUMENT_STRUCTURE` and no snapshot is produced

#### Scenario: Unknown nested field rejected
- **WHEN** a scope section contains an unrecognized scope kind, or `testing_rules` contains an unrecognized field
- **THEN** validation fails with `INVALID_UNKNOWN_FIELD` and no snapshot is produced

#### Scenario: Structurally malformed value stays inside the reason-code contract
- **WHEN** a scope kind holds a scalar instead of a list, or a scope section is not a mapping
- **THEN** validation fails with `INVALID_DOCUMENT_STRUCTURE` (never an uncaught error) and no snapshot is produced

### Requirement: Confirmed-authority verification
After building a candidate snapshot the loader SHALL recompute the P0
`authority_digest` over the canonical security-relevant projection of that
snapshot and compare it byte-for-byte with the `confirmed_authority_digest` in
`authorization.json`. Any security-relevant mismatch SHALL deny with
`DENY_AUTHORIZATION_STALE` before any downstream binding, secret resolution, or
spawn. An authorization document with `confirmed` not true, or missing required
confirmation fields, SHALL deny with `DENY_AUTHORIZATION_UNCONFIRMED`.
Verification SHALL perform no network or subprocess I/O.

#### Scenario: Matching digest confirms the engagement
- **WHEN** the recomputed authority digest equals the stored `confirmed_authority_digest`
- **THEN** the snapshot is marked confirmed and made available to consumers

#### Scenario: Material change invalidates confirmation
- **WHEN** any security-relevant authority field (scope rule, profile, runner trust field, or policy limit) differs from what the stored digest covers
- **THEN** verification denies with `DENY_AUTHORIZATION_STALE` and exposes no confirmed snapshot

#### Scenario: Unconfirmed authorization denies
- **WHEN** `authorization.json` has `confirmed` false or omits a required confirmation field
- **THEN** verification denies with `DENY_AUTHORIZATION_UNCONFIRMED`

#### Scenario: Non-security formatting change does not invalidate
- **WHEN** only non-security content changes (a `note`, comment, or key ordering) while every security-relevant value is unchanged
- **THEN** the recomputed digest still matches and the engagement remains confirmed

### Requirement: Stable engagement namespace identity
A confirmed snapshot SHALL expose one stable, deterministic engagement namespace
identity derived only from confirmed security-relevant authority, such that two
loads of the same confirmed authority yield the same identity and any
security-relevant change yields a different identity. The identity SHALL contain
no secret material, no local filesystem path, and no mutable timestamp.

#### Scenario: Identity is stable across identical loads
- **WHEN** the same confirmed engagement is loaded twice
- **THEN** both loads produce the same namespace identity

#### Scenario: Identity changes on security-relevant change
- **WHEN** a security-relevant authority value changes and the engagement is reconfirmed
- **THEN** the namespace identity differs from the previous identity

### Requirement: Schema v1 remains unchanged
Loading a schema v1 engagement SHALL keep its existing v1 semantics, caller and
approval behavior, and exit codes. No v1 engagement SHALL silently acquire v2
loader behavior, and the v2 loader SHALL be reachable only through explicit v2
entry points.

#### Scenario: v1 engagement keeps v1 behavior
- **WHEN** an engagement declares schema v1
- **THEN** it is handled by the existing v1 path and the v2 loader is not invoked

#### Scenario: v2 entry point required for v2 loading
- **WHEN** no explicit v2 entry point is used
- **THEN** the v2 loader does not run and no v2 snapshot is produced

