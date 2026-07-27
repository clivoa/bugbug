## ADDED Requirements

### Requirement: Fixed binary framing
Remote protocol v1 SHALL begin with the eight-byte magic
`b"HBV2RUN\x00"`. It SHALL then encode, in network byte order: unsigned 16-bit
protocol version `1`, unsigned 32-bit canonical JSON header length, unsigned
16-bit frame count, and the header bytes. Each frame SHALL encode unsigned
16-bit frame type, unsigned 64-bit byte length, 32 raw SHA-256 digest bytes, and
opaque payload.

Header size SHALL be at most 1,048,576 bytes, frame count at most 256, each
frame at most 67,108,864 bytes, complete request at most 75,497,472 bytes, and
complete response at most 41,943,040 bytes. Lengths MUST be validated before
allocation. Trailing bytes, missing frames, duplicate frame indexes, unknown
frame types, or digest mismatch MUST fail with `EXEC_PROTOCOL_INVALID`.
Immediately after canonical header and descriptor validation, the complete
declared wire size SHALL be computed from the fixed prefix, header length, all
frame-prefix widths, and all descriptor lengths; aggregate overflow MUST be
rejected before reading any frame prefix or payload.

Frame types SHALL be exactly `1=target-list`, `2=artifact`, `3=secret`,
`4=stdout`, `5=stderr`, `6=structured-result`, and `7=cleanup-receipt`.
Requests SHALL contain only frame types 1 through 3; responses SHALL contain
only frame types 4 through 7.

#### Scenario: Empty metadata-only run is framed deterministically
- **WHEN** a valid request has no opaque input frames
- **THEN** frame count is zero and the header still binds the complete execution request

#### Scenario: Declared length is checked before allocation
- **WHEN** a frame declares a size above 67,108,864 bytes
- **THEN** the helper returns `EXEC_PROTOCOL_INVALID` without allocating the declared payload

#### Scenario: Extra bytes fail closed
- **WHEN** bytes remain after the declared final frame
- **THEN** the complete message is rejected with `EXEC_PROTOCOL_INVALID`

### Requirement: Canonical request binding
The request header SHALL use `hackbot-canonical-json-v1` and contain:
`protocol_version`, `run_id`, `nonce`, `issued_at`, `expires_at`,
`authority_digest`, `execution_digest`, `action_id`, canonical secret-free argv
projection, executable path/digest, runner identity, OS, architecture,
required privileges, frame descriptors, timeout, stdout cap, and stderr cap.

`run_id` SHALL be a lowercase canonical UUIDv4. `nonce` SHALL be 32 random bytes
encoded as 43-character unpadded base64url. Times SHALL use UTC RFC3339 seconds
ending in `Z`. Expiry SHALL be 1 through 300 seconds after issue time. A helper
MUST allow at most 30 seconds of clock skew.

The execution digest SHALL be lowercase `sha256:` plus 64 hex characters over
the canonical execution projection, including the authority digest, action,
argv projection, all input frame digests, executable identity, runner security
identity, run ID, and nonce.

Execution projection v1 SHALL be exactly
`{"schema_version":1,"request":<request>}`, where `<request>` is the complete
canonical request-header mapping with only its top-level `execution_digest`
field removed. Every other approved request-header field and nested value SHALL
remain unchanged, including protocol version, run ID, nonce, issue and expiry
times, authority digest, action, argv, executable identity, runner identity,
operating system, architecture, required privileges, ordered frame
descriptors, timeout, stdout cap, and stderr cap. A request SHALL be rejected
with `EXEC_PROTOCOL_INVALID` when recomputing `execution_digest` over that exact
projection does not equal the request header's `execution_digest`.

#### Scenario: Frame substitution changes execution identity
- **WHEN** one input payload or descriptor changes
- **THEN** its frame digest and the execution digest no longer match the request

#### Scenario: Expired request never spawns
- **WHEN** current trusted time exceeds expiry plus 30 seconds
- **THEN** the helper returns `EXEC_PROTOCOL_EXPIRED` before resource preparation

### Requirement: Replay resistance
The helper SHALL atomically reserve `(authority_digest, run_id, nonce)` before
creating resources. It SHALL retain the reservation for 600 seconds after
expiry or until a longer in-progress run finalizes. A repeated tuple MUST fail
with `EXEC_PROTOCOL_REPLAY`, including after an SSH reconnect.

The response SHALL echo run ID, nonce, authority digest, and execution digest.
Response frame descriptors SHALL be ordered by frame index and hash-chained
from the request execution digest. Let `chain[0]` be the raw 32-byte digest
portion of `execution_digest`. For response frame `i`, the next value SHALL be
`SHA256(chain[i] || uint16_be(frame_type) || uint64_be(length) ||
payload_sha256)`. The structured result SHALL contain the final lowercase
64-hex chain value.

#### Scenario: Concurrent duplicate is rejected
- **WHEN** two connections present the same valid tuple concurrently
- **THEN** exactly one reservation succeeds and the other returns `EXEC_PROTOCOL_REPLAY`

#### Scenario: Response from another run is rejected locally
- **WHEN** a response has a different nonce, run ID, authority digest, or execution digest
- **THEN** the local runner rejects it with `EXEC_TRUST_MISMATCH`

### Requirement: Pinned SSH and helper trust root
Runner schema v2 SHALL require a dedicated SSH identity, exact host, port, user,
SHA-256 host-key fingerprint, absolute helper path, protocol version, and
helper SHA-256 digest or code-signing identity. SSH configuration SHALL enforce
batch mode, identities-only, strict pinned host-key checking, a dedicated
known-hosts file, no agent/X11/port forwarding, no TTY, and a forced fixed
helper command.

`accept-new`, PATH lookup, inherited SSH configuration, arbitrary remote
commands, and action-controlled remote command text MUST be absent.
Helper self-report SHALL NOT satisfy helper identity.

#### Scenario: Host key mismatch stops before protocol
- **WHEN** the server host key differs from the confirmed fingerprint
- **THEN** SSH fails with `EXEC_TRUST_MISMATCH` and sends no secret frame

#### Scenario: Helper digest mismatch stops before action spawn
- **WHEN** the pinned verifier observes a different helper binary identity
- **THEN** the helper path is not trusted and action execution does not begin

### Requirement: Executable identity and privilege permit
For an exact executable-digest action, the helper SHALL open a regular
non-symlink executable without following links, hash that descriptor, and
execute the same descriptor where the platform supports descriptor execution.
A platform unable to close the identity-to-exec race MUST return
`EXEC_TRUST_MISMATCH` for such an action.

A privileged broker permit SHALL be machine-signed and bind engagement ID,
authority digest, execution digest, action ID, runner identity, executable
digest, exact privilege set, nonce, issue time, and expiry. It SHALL use the
same 300-second maximum lifetime and replay tuple. Permit issuance SHALL occur
automatically only after policy `ALLOW`; it is not a human action approval.
The signed envelope SHALL use Ed25519 with a 32-byte public key and 64-byte
signature over `hackbot-canonical-json-v1` permit bytes. The confirmed runner
projection SHALL store the signer public-key SHA-256 fingerprint.

#### Scenario: Executable replacement is detected
- **WHEN** the path inode is replaced between configuration and execution
- **THEN** descriptor identity or digest verification fails closed

#### Scenario: Permit cannot authorize broader privilege
- **WHEN** the requested runtime privilege set is not a subset of the signed permit and confirmed runner set
- **THEN** the broker returns `EXEC_PRIVILEGE_MISMATCH`

### Requirement: Runtime platform and privilege claims
Static runner OS, architecture, and permitted privileges SHALL be upper bounds.
Trusted preflight SHALL compare the actual execution identity and held
capabilities with the action requirements immediately before spawn.

An `execution-node` SHALL be a confirmed trust principal but not an action
target. An `in-scope-target` SHALL independently pass scope validation. Claims
made solely by an in-scope target about its OS, privileges, egress, interaction,
state, or cleanup SHALL be labeled `unverified-self-report`.

#### Scenario: Configured privilege is not actually held
- **WHEN** runner configuration permits packet capture but trusted preflight does not observe it
- **THEN** execution fails with `EXEC_PRIVILEGE_MISMATCH`

#### Scenario: Target claim is not promoted to attestation
- **WHEN** an in-scope target reports successful cleanup without a pinned independent verifier
- **THEN** the result remains `unverified-self-report`

### Requirement: Source identity and egress claims
Source identity modes SHALL be exactly `none`, `direct-interface`, and
`attested-egress`. `direct-interface` SHALL prove only an address directly
assigned to the execution node. `attested-egress` SHALL require a confirmed,
pinned adapter identity and a signed observation bound to run ID, nonce,
execution digest, observed address, and observation time.

The egress observation SHALL use the same Ed25519 signed-envelope format as a
privilege permit and SHALL be valid for at most 60 seconds from observation.

An interface address SHALL NOT satisfy a required NAT/public egress claim.
Missing, stale, mismatched, or self-reported egress evidence MUST fail with
`EXEC_TRUST_MISMATCH`.

#### Scenario: Direct address satisfies direct requirement
- **WHEN** trusted preflight observes the required address on a local interface and policy requires `direct-interface`
- **THEN** source identity validation succeeds

#### Scenario: Interface address cannot prove public egress
- **WHEN** policy requires `attested-egress` but only a local interface address exists
- **THEN** validation fails with `EXEC_TRUST_MISMATCH`

### Requirement: Crash and cleanup reporting
The helper SHALL create private run state with directory mode `0700` and file
mode `0600`, prefer memory-backed storage for secrets, and reconcile stale run
directories at startup. It SHALL never claim physical erasure.

Connection loss, host loss, process crash, `SIGKILL`, missing receipt, malformed
receipt, or failed removal MUST produce resource cleanup `failed`. A cleanup
receipt from the tested target alone SHALL remain an unverified target-state
self-report.

#### Scenario: SSH disconnect after secret delivery is incomplete
- **WHEN** SSH disconnects after protected input preparation and before a verified cleanup receipt
- **THEN** execution is incomplete and resource cleanup is `failed`

#### Scenario: Startup reconciliation is auditable
- **WHEN** a later helper start finds stale private run state
- **THEN** it attempts bounded cleanup and emits a result bound to the original run identifier without exposing secret names or values
