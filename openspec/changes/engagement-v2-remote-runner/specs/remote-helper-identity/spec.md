## ADDED Requirements

### Requirement: Pinned helper identity
The remote helper SHALL be identified only by a pre-provisioned, pinned identity
from the confirmed runner projection — a SHA-256 binary digest or a code-signing
identity — together with an expected protocol version. A helper self-report of
its own path, version, or digest SHALL NOT satisfy helper identity.

#### Scenario: Helper self-report does not satisfy identity
- **WHEN** the helper reports its own digest or version but the transport has no pinned match
- **THEN** identity verification fails closed with `EXEC_TRUST_MISMATCH`

#### Scenario: Wrong protocol version is rejected
- **WHEN** the helper speaks a protocol version other than the pinned expected version
- **THEN** the run fails closed with `EXEC_PROTOCOL_INVALID`

### Requirement: Remote executable-digest verification
For an action that declares an exact executable digest, the helper SHALL open the
remote executable as a regular file, verify its SHA-256 digest against the
declared value before spawn, and bind `argv[0]` to that verified absolute
executable. A digest mismatch or a non-regular file SHALL fail closed before any
spawn.

#### Scenario: Executable digest mismatch fails closed
- **WHEN** the remote executable's digest does not match the action's declared digest
- **THEN** the helper does not spawn and fails closed with `EXEC_TRUST_MISMATCH`

#### Scenario: argv[0] is the verified executable
- **WHEN** an exact-digest action spawns remotely
- **THEN** `argv[0]` equals the verified absolute executable path
