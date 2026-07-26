## ADDED Requirements

### Requirement: Versioned authority artifacts
Hackbot SHALL expose immutable contract constants for these artifact versions:
`program=2`, `scope=2`, `authorization=2`, `actions=1`, `action_request=2`,
`runner=2`, `authority_projection=1`, and `execution_projection=1`. A document
with any other version MUST fail with `INVALID_SCHEMA_VERSION`.

The maximum encoded UTF-8 size SHALL be 1,048,576 bytes for each program,
scope, authorization, and runner document, and 4,194,304 bytes for the action
manifest. Nesting depth SHALL be at most 32.

#### Scenario: Supported versions are accepted by the contract layer
- **WHEN** every artifact declares the exact version listed above
- **THEN** contract-version validation succeeds without activating a v2 runtime path

#### Scenario: Unknown version fails closed
- **WHEN** any authority artifact declares an unlisted version or a boolean version
- **THEN** contract-version validation fails with `INVALID_SCHEMA_VERSION`

#### Scenario: Oversized document is rejected before decoding
- **WHEN** an encoded authority document exceeds its byte limit
- **THEN** validation fails with `INVALID_DOCUMENT_SIZE` before a parser allocates from its content

### Requirement: Strict authority primitive model
Authority values SHALL contain only mappings, lists, NFC-normalized Unicode
strings, signed 64-bit integers, exact booleans, and null. Floats, byte strings,
surrogates, non-NFC strings, and C0/C1 control characters MUST fail with
`INVALID_CANONICAL_VALUE`.

Mapping keys SHALL be ASCII snake case matching
`[a-z][a-z0-9_]{0,63}`. YAML aliases, merge keys, explicit tags, duplicate
keys, unknown fields, and arbitrary object construction MUST be rejected.

#### Scenario: Equivalent normalized primitives are stable
- **WHEN** two decoded documents contain the same valid normalized primitive values
- **THEN** both produce byte-identical canonical values

#### Scenario: Float cannot enter a security projection
- **WHEN** a decoded authority value contains `1.0`
- **THEN** canonical validation fails with `INVALID_CANONICAL_VALUE`

#### Scenario: Duplicate key cannot use last-value-wins behavior
- **WHEN** a JSON or YAML mapping repeats a key at any depth
- **THEN** decoding fails with `INVALID_DUPLICATE_KEY` and produces no authority snapshot

### Requirement: Exact profiles and policy limits
The profile enum SHALL contain only `bug-bounty`, `local-lab`, and
`private-pentest`. Profile names SHALL NOT grant runtime capabilities.

The numeric policy bounds SHALL be:

| Field | Minimum | Maximum |
|---|---:|---:|
| `max_requests_per_second` | 1 | 1,000 |
| `concurrency` | 1 | 100 |
| `timeout_seconds` | 1 | 86,400 |
| `output_cap_bytes` | 4,096 | 16,777,216 |
| `max_targets_per_action` | 1 | 65,536 |

The sensitive policy fields SHALL be exact booleans:
`automated_scanning_allowed`, `authenticated_testing_allowed`,
`exploit_execution_allowed`, `payload_execution_allowed`,
`credential_access_allowed`, `credential_capture_allowed`,
`state_changing_allowed`, `privileged_execution_allowed`,
`lateral_movement_allowed`, `persistence_allowed`,
`sensitive_data_access_allowed`, `data_exfiltration_allowed`,
`account_creation_allowed`, `multiple_accounts_allowed`,
`out_of_band_testing_allowed`, `autonomous_progression_allowed`,
`operator_output_persistence_allowed`, `social_engineering_allowed`,
`denial_of_service_allowed`, and `destructive_testing_allowed`.
Absence SHALL normalize to false; any non-boolean value MUST fail with
`INVALID_SCHEMA`.

#### Scenario: Profiles do not alter a materialized decision input
- **WHEN** two contract values differ only by profile and have identical materialized policy fields
- **THEN** their capability projections are identical

#### Scenario: Missing sensitive permission is false
- **WHEN** a sensitive policy field is absent
- **THEN** its normalized contract value is exactly false

#### Scenario: Numeric policy boundary is closed
- **WHEN** a numeric limit is below its minimum or above its maximum
- **THEN** validation fails with `INVALID_LIMIT`

### Requirement: Canonical JSON bytes
Hackbot SHALL implement `hackbot-canonical-json-v1` over the strict primitive
model. Before serialization, set-like collections SHALL be deduplicated and
sorted by their own canonical UTF-8 bytes; ordered collections such as argv
SHALL preserve order.

Serialization SHALL:

- sort ASCII mapping keys by byte value;
- encode UTF-8 without a byte-order mark;
- use JSON `true`, `false`, and `null`;
- render integers in base 10 with no leading zero or plus sign;
- use `,` and `:` with no surrounding whitespace;
- escape only quotation mark and reverse solidus because controls are invalid;
- append no newline.

#### Scenario: Formatting does not change canonical bytes
- **WHEN** two authority files differ only in YAML/JSON formatting, comments, mapping order, or set-like list order
- **THEN** their normalized authority projections serialize to identical canonical bytes

#### Scenario: Ordered argv remains order-sensitive
- **WHEN** two action projections contain the same argv tokens in different orders
- **THEN** their canonical bytes and resulting digests differ

### Requirement: Confirmed authority projection
The `hackbot-authority-v1` projection SHALL include normalized security fields
from program, scope, actions, the P6 workflow slot, and the runner security
view. Before P6, the workflow slot SHALL be exactly null.

The runner security view SHALL include role, canonical node identity, SSH host,
port and user, pinned host-key SHA-256 fingerprint, helper absolute path,
helper protocol version and digest, operating system, architecture, permitted
privileges, source-identity mode, and egress-attestation identity. It SHALL
exclude private-key content/path and connection timeout.

The projection SHALL exclude `authorization.json` itself, confirmation
timestamp, confirmer, note, secret references/values, evidence, and runtime
results. The authority digest SHALL be lowercase
`sha256:` followed by 64 hexadecimal characters calculated over canonical
projection bytes.

#### Scenario: Security-relevant change invalidates confirmation
- **WHEN** any included authority field changes
- **THEN** the recomputed digest differs and authorization fails with `DENY_AUTHORIZATION_STALE`

#### Scenario: Operational timeout does not invalidate confirmation
- **WHEN** only the runner connection timeout or local private-key path changes
- **THEN** the confirmed authority digest remains unchanged

#### Scenario: Authorization cannot hash itself
- **WHEN** confirmation metadata changes without an authority change
- **THEN** the authority digest remains unchanged and no circular projection exists

### Requirement: Confirmation contract
Authorization schema v2 SHALL require `confirmed`, `confirmation_timestamp`,
`confirmed_by`, `confirmed_authority_digest`, and `note`. A false confirmation
MUST return `DENY_AUTHORIZATION_UNCONFIRMED`. A malformed digest MUST return
`INVALID_SCHEMA`. A well-formed digest unequal to the frozen authority snapshot
MUST return `DENY_AUTHORIZATION_STALE`.

Confirmation SHALL bind the engagement as a whole and SHALL NOT create a
per-action approval or L3 grant.

#### Scenario: Confirmed matching authority is eligible for later policy checks
- **WHEN** confirmation is true and its digest equals the frozen authority digest
- **THEN** authorization validation succeeds without returning an action approval state

#### Scenario: Stale confirmation prevents preparation
- **WHEN** confirmation is true but its digest does not match
- **THEN** processing stops with `DENY_AUTHORIZATION_STALE` before secret resolution or resource creation

### Requirement: Stable reason code registry
P0 SHALL publish one immutable string enum containing:
`INVALID_SCHEMA_VERSION`, `INVALID_DOCUMENT_SIZE`,
`INVALID_DOCUMENT_ENCODING`, `INVALID_DOCUMENT_STRUCTURE`,
`INVALID_UNKNOWN_FIELD`, `INVALID_DUPLICATE_KEY`, `INVALID_IDENTIFIER`,
`INVALID_LIMIT`, `INVALID_CANONICAL_VALUE`, `INVALID_ACTION_MANIFEST`,
`INVALID_PLACEHOLDER`, `INVALID_REQUEST`, `INVALID_RUNNER`,
`DENY_AUTHORIZATION_UNCONFIRMED`, `DENY_AUTHORIZATION_STALE`,
`DENY_CAPABILITY_NOT_ALLOWED`, `DENY_POLICY_LIMIT`,
`DENY_RATE_UNENFORCEABLE`, `EXEC_PROTOCOL_INVALID`,
`EXEC_PROTOCOL_EXPIRED`, `EXEC_PROTOCOL_REPLAY`, `EXEC_TRUST_MISMATCH`,
`EXEC_PRIVILEGE_MISMATCH`, `EVIDENCE_POLICY_DENIED`,
`CLEANUP_RESOURCE_INCOMPLETE`, and `CLEANUP_TARGET_INCOMPLETE`.
The public contract error SHALL accept only an exact enum member and derive its
message from that member. It MUST NOT accept decoded input, target output,
secret references, or arbitrary metadata as a public message.

#### Scenario: Unknown reason code cannot be emitted
- **WHEN** code attempts to construct a contract failure with an unregistered reason
- **THEN** construction fails before the failure is exposed through JSON, audit, or CLI output

#### Scenario: Untrusted detail cannot enter public error
- **WHEN** a lower layer encounters malformed content containing sensitive text
- **THEN** it may chain a private cause but the public error contains only its registered reason and code-owned message
