# remote-runner-transport Specification

## Purpose
TBD - created by archiving change engagement-v2-remote-runner. Update Purpose after archive.
## Requirements
### Requirement: Fixed exec-only pinned SSH transport
The remote transport SHALL connect only with a dedicated exec-only SSH identity
to the pinned host, port, and user, with the pinned host key enforced and agent
forwarding, X11 forwarding, port forwarding, and TTY allocation disabled. The SSH
argv SHALL invoke only the fixed absolute `hackbot-remote-runner` helper path and
SHALL NOT interpolate any action executable, target, parameter, artifact, or
secret into a remote shell string.

#### Scenario: Host-key mismatch fails closed
- **WHEN** the remote host key does not match the pinned host key
- **THEN** the transport refuses to connect and no request is sent, denying with `EXEC_TRUST_MISMATCH`

#### Scenario: Only the fixed helper is invoked
- **WHEN** a remote run is dispatched
- **THEN** the SSH argv invokes only the fixed helper path and carries no interpolated action content

### Requirement: Canonical request binding and framed send
The client SHALL build a `hackbot-canonical-json-v1` request header bound to a
canonical UUIDv4 run ID, a 32-byte base64url nonce, a UTC RFC3339-seconds issue
time, a 1–300 second expiry, and the execution digest over the execution
projection, and SHALL send only request frame types (target-list, artifact,
secret) within the P0 header/frame/count/total caps.

#### Scenario: Over-cap request is rejected before send
- **WHEN** a request would exceed a P0 header, frame, count, or total byte cap
- **THEN** the client fails closed with `EXEC_PROTOCOL_INVALID` and sends nothing

#### Scenario: Expired request window is rejected
- **WHEN** a request expiry is outside 1–300 seconds after issue time
- **THEN** the client fails closed with `EXEC_PROTOCOL_EXPIRED`

### Requirement: Response verification and equivalent semantics
The client SHALL verify that the response echoes the run ID, nonce, authority
digest, and execution digest and that response frame descriptors are ordered and
hash-chained per the P0 contract; any mismatch SHALL fail closed with the exact
P0 `EXEC_*` reason. A verified remote run SHALL apply the same gate, bound argv,
secret handling, evidence redaction, lifecycle, and independent fail-closed
resource/target cleanup as the local executor, and SHALL reconcile a partially
completed remote run.

#### Scenario: Broken response hash chain fails closed
- **WHEN** a response frame descriptor breaks the ordered hash chain or echoes a wrong binding value
- **THEN** the client rejects the response with `EXEC_PROTOCOL_INVALID` and surfaces no evidence

#### Scenario: Remote result matches local semantics
- **WHEN** the same action runs locally and remotely with identical inputs
- **THEN** both apply the same gate, redaction, lifecycle, and cleanup semantics

