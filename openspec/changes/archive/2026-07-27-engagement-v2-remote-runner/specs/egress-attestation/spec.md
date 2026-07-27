## ADDED Requirements

### Requirement: Distinct egress claims
`direct-interface` and `attested-egress` SHALL be distinct source-identity claims
in the runner projection. A local interface address SHALL NOT by itself be
evidence of NAT or public egress. An observed-egress claim SHALL require a
configured, pinned attestation adapter; a claim that cannot be mechanically
verified SHALL fail closed.

#### Scenario: Local address is not public-egress evidence
- **WHEN** a runner declares `direct-interface` with a local interface address and no attestation adapter
- **THEN** it is recorded only as a direct-interface claim and grants no public-egress assertion

#### Scenario: Unverifiable observed egress fails closed
- **WHEN** an `attested-egress` claim has no configured, pinned attestation adapter
- **THEN** the egress claim fails closed and the run does not proceed under that claim

### Requirement: Bounded, pinned egress attestation
An `attested-egress` claim SHALL be produced by the pinned adapter (identified by
its SHA-256 and signer fingerprint in the runner projection) and SHALL carry an
observation age within the P0 maximum. A stale or mis-signed attestation SHALL
fail closed.

#### Scenario: Stale attestation is rejected
- **WHEN** an egress attestation's observation age exceeds the P0 maximum
- **THEN** the attestation is rejected and the run fails closed

#### Scenario: Signed, fresh attestation is accepted
- **WHEN** an egress attestation is signed by the pinned adapter and within the maximum age
- **THEN** the observed-egress claim is accepted as an attested claim
