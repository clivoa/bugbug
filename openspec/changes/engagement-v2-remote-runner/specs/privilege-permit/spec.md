## ADDED Requirements

### Requirement: Static privileges are upper bounds
Static runner operating system, architecture, and permitted privileges SHALL be
treated as upper bounds only. A trusted preflight SHALL compare the actual remote
execution identity and held privileges against the confirmed permitted set; an
action requiring a privilege outside the confirmed set SHALL fail closed with
`EXEC_PRIVILEGE_MISMATCH`.

#### Scenario: Privilege outside the confirmed set is denied
- **WHEN** an action requires a privilege not in the confirmed permitted set
- **THEN** the run fails closed with `EXEC_PRIVILEGE_MISMATCH`

#### Scenario: Held privileges below the static upper bound are used
- **WHEN** the actual held privileges are a subset of the static permitted set
- **THEN** the preflight uses the actual held privileges, not the static upper bound

### Requirement: Machine-signed privilege permit
A privileged action SHALL require an Ed25519 machine-signed permit bound to the
engagement ID, authority digest, action ID, runner, executable digest, exact
privilege set, nonce, issue time, and a 1–300 second expiry, verified against the
runner projection's pinned signer public-key SHA-256 fingerprint and the same
replay tuple as the request. A missing, mis-signed, expired, replayed, or
mismatched permit SHALL fail closed.

#### Scenario: Mis-signed permit is rejected
- **WHEN** a permit's Ed25519 signature does not verify against the pinned signer fingerprint
- **THEN** the run fails closed with `EXEC_PRIVILEGE_MISMATCH`

#### Scenario: Permit privilege set must match exactly
- **WHEN** a permit's privilege set differs from the action's required privileges
- **THEN** the run fails closed with `EXEC_PRIVILEGE_MISMATCH`

#### Scenario: Expired or replayed permit is rejected
- **WHEN** a permit is expired or reuses a reserved `(authority_digest, run_id, nonce)` tuple
- **THEN** the run fails closed with `EXEC_PROTOCOL_EXPIRED` or `EXEC_PROTOCOL_REPLAY`
