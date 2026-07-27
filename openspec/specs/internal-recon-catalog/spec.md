# internal-recon-catalog Specification

## Purpose
TBD - created by archiving change engagement-v2-recon-catalog. Update Purpose after archive.
## Requirements
### Requirement: Non-credential category scope
The non-credential internal-recon catalog SHALL contain only actions in the
local-network-state (L1), host-discovery (L2), service-enumeration (L2), and
anonymous-LDAP (L2) categories. It SHALL NOT contain any action classified `L3`
or declaring `credential-access`, `credential-capture`, `sensitive-data-access`,
`exploit-execution`, `payload-execution`, `lateral-movement`, `persistence`, or
`data-exfiltration`. Host-discovery, service-enumeration, and anonymous-LDAP
actions SHALL declare `automated-scanning`.

#### Scenario: Every catalog action is non-credential
- **WHEN** the catalog is loaded
- **THEN** every action's risk level is `L1` or `L2` and none declares a credential/capture/sensitive-data or L3 capability

#### Scenario: A credential category is rejected from this catalog
- **WHEN** an action declaring `credential-access` (or any L3 capability) is added to the non-credential catalog
- **THEN** the catalog classification test fails

### Requirement: Contract-valid reviewed actions
Every catalog action SHALL validate against the P2 action-manifest contract: an
absolute executable, declared platform/architecture, typed parameters, whole-token
argv placeholders (never a shell string), a declared rate-control mode, an
evidence mode, and its exact risk/capability classification. No action SHALL
encode a copied multi-tool bundle pipeline; only a reviewed generic single-tool
argv subset is permitted.

#### Scenario: Catalog validates as a manifest
- **WHEN** the catalog is validated by the P2 manifest validator
- **THEN** it produces an immutable registry with no `INVALID_ACTION_MANIFEST` error

#### Scenario: Shell or pipeline action is rejected
- **WHEN** an action uses a shell executable, an inline-eval flag, or a multi-token pipeline
- **THEN** manifest validation fails

### Requirement: Provenance for every action
Every catalog action SHALL map to a code-owned provenance record naming its
reviewed source skill/category, its risk/capability classification, and its
attribution. A catalog action without a provenance record SHALL fail the
provenance test.

#### Scenario: Missing provenance fails
- **WHEN** a catalog action has no provenance record
- **THEN** the provenance test fails

### Requirement: Disabled by default
Catalog actions SHALL load only under a `private-pentest`, `local-lab`, or
explicitly-authorized internal profile with explicit confirmation. A catalog
action present in a manifest SHALL NOT self-enable internal recon, and the
discovery of an internal hostname, an RFC1918 address, or an LDAP endpoint SHALL
NOT enable it.

#### Scenario: No profile does not enable the catalog
- **WHEN** the active profile is not an authorized internal profile
- **THEN** the catalog actions are not enabled for execution

#### Scenario: Discovered internal data does not enable the catalog
- **WHEN** an internal hostname, RFC1918 address, or LDAP endpoint appears in collected data
- **THEN** the catalog remains disabled

### Requirement: Harmless lab fixtures and tested classification
Fixtures SHALL be deterministic, synthetic, and contain no real target or
credential material, and SHALL live under a disposable-lab fixture root. Tests
SHALL assert each action's platform/architecture, risk level, and capabilities,
and SHALL NOT perform any live scan.

#### Scenario: Fixtures contain no real or credential material
- **WHEN** the fixtures are scanned
- **THEN** they contain only synthetic example subnets/hosts/endpoints and no secret

#### Scenario: Classification is tested without scanning
- **WHEN** the catalog classification tests run
- **THEN** they assert every action's level and capabilities and execute no external scanner

