## ADDED Requirements

### Requirement: Scoped L3 category set
The credential/L3 offensive catalog SHALL contain only actions in the authorized
categories: authenticated directory enumeration, credential material access,
validation and capture, exploit verification, payload/post-exploitation, lateral
movement, and persistence. It SHALL NOT contain any action declaring
`denial-of-service`, `destructive-testing`, or `data-exfiltration`, and SHALL NOT
contain detection-evasion tooling. Every catalog action SHALL be classified `L3`.

#### Scenario: Excluded impact categories are rejected
- **WHEN** an action declaring `denial-of-service`, `destructive-testing`, or `data-exfiltration` is added to the catalog
- **THEN** the catalog classification test fails

#### Scenario: Every catalog action is L3
- **WHEN** the catalog is loaded
- **THEN** every action's risk level is `L3` and declares at least one credential/exploit/movement/persistence capability

### Requirement: All declared capabilities required
An action SHALL run only when every `testing_rules` boolean mapped from its
declared capabilities is exactly `true`; a missing, `false`, or non-boolean flag
SHALL deny with `DENY_CAPABILITY_NOT_ALLOWED`. A profile name SHALL grant no
capability, and no per-action approval SHALL be introduced (`REQUIRES_APPROVAL`
is never returned for v2).

#### Scenario: A single missing capability denies
- **WHEN** an exploit action requires `exploit-execution` and `state-changing` but only `exploit-execution` is enabled
- **THEN** the decision denies with `DENY_CAPABILITY_NOT_ALLOWED`

#### Scenario: All capabilities enabled allows the gate
- **WHEN** every mapped `testing_rules` flag for an action is exactly `true` and all other checks pass
- **THEN** the capability gate does not deny

### Requirement: Conservative credential evidence
Credential material SHALL be retained only as `metadata-only` or a closed native
structured schema — never a raw credential dump and never more than minimal
reproducible proof. A credential-access or credential-capture action requesting
`redacted-output` SHALL deny with `EVIDENCE_POLICY_DENIED`. Exit code alone SHALL
never demonstrate impact.

#### Scenario: Credential action cannot persist raw output
- **WHEN** a `credential-access`/`credential-capture` action requests `redacted-output`
- **THEN** the run denies with `EVIDENCE_POLICY_DENIED` and stores no raw credential material

#### Scenario: Structured credential evidence is closed-form
- **WHEN** a credential action uses `structured` evidence
- **THEN** only a closed native structured result (e.g. counts, principal names, ticket metadata) is stored, never raw secret material

### Requirement: Capture is never labeled passive
An LLMNR/NBT-NS/mDNS responder or any tool run in a mode capable of collecting
authentication material SHALL be an `L3` `credential-capture` action, distinct
from an analyze/observe-only action of the same tool. A capture-capable action
SHALL NOT be labeled passive or discovery, and a poisoning mode SHALL also declare
`state-changing` and third-party characteristics as applicable.

#### Scenario: Analyze and capture are distinct actions
- **WHEN** the catalog offers a responder analyze mode and a poison/capture mode
- **THEN** they are separate actions and only the capture mode declares `credential-capture` at `L3`

#### Scenario: A capture mode is not labeled passive
- **WHEN** an action can collect authentication material
- **THEN** its classification is `L3` `credential-capture` and it carries no passive/discovery label

### Requirement: Provenance, disabled by default, and isolated-lab tests
Every catalog action SHALL map to a provenance record (source skill/category,
classification, attribution), SHALL load only under an authorized internal
profile with explicit confirmation (presence in code never self-enables), and any
real end-to-end exercise SHALL run only in an isolated, disposable lab with no
production or third-party target. Fixtures SHALL be synthetic with no real target
or credential material.

#### Scenario: Catalog disabled without authorized profile and confirmation
- **WHEN** no authorized internal profile is active or internal recon is not confirmed
- **THEN** the catalog does not load

#### Scenario: End-to-end tests are lab-only
- **WHEN** the test suite runs in CI
- **THEN** it performs no live credential/exploit action and exercises only synthetic fixtures and classification
