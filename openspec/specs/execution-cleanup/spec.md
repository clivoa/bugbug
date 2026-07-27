# execution-cleanup Specification

## Purpose
TBD - created by archiving change engagement-v2-executor. Update Purpose after archive.
## Requirements
### Requirement: Independent resource and target cleanup
`resource_cleanup_status` (stdin, temporary files and directories, and processes)
and `target_cleanup_status` (changes made to the tested system) SHALL be tracked
and reported independently, each drawn from the exact P0 cleanup-state enums.
Neither status SHALL be inferred from the other, and resource cleanup SHALL run
regardless of the target outcome.

#### Scenario: Statuses are reported separately
- **WHEN** a run finishes
- **THEN** the record carries a `resource_cleanup_status` and a `target_cleanup_status` that are set independently

#### Scenario: Resource cleanup runs even when target cleanup is deferred
- **WHEN** target cleanup is deferred or manual
- **THEN** resource cleanup still removes stdin, temporary files/directories, and processes

### Requirement: Cleanup fails closed
If resource or target cleanup cannot be independently confirmed, the run SHALL
NOT report success: the affected status SHALL be a failure/incomplete state
(`CLEANUP_RESOURCE_INCOMPLETE` / `CLEANUP_TARGET_INCOMPLETE`), a protected item
SHALL be written under `cleanup/`, and the wrapper SHALL return a non-success
status. A target's own cleanup receipt SHALL be recorded as an unverified
self-report, never as independent proof.

#### Scenario: Unconfirmed resource cleanup is incomplete
- **WHEN** resource cleanup cannot be confirmed (for example a surviving temporary directory)
- **THEN** the status is `CLEANUP_RESOURCE_INCOMPLETE`, a protected item is written under `cleanup/`, and the run does not report success

#### Scenario: Target self-report is unverified
- **WHEN** the tested system returns its own cleanup receipt
- **THEN** it is recorded as an unverified self-report and does not by itself set the target status to complete

### Requirement: Secret-free audit record
Each run SHALL write one audit record containing the engagement identity, a
canonical argv projection in which temporary paths are replaced by their manifest
placeholders, the decision, child-result metadata, the evidence reference, and
both cleanup statuses. The audit SHALL contain no raw output, no secret name or
value, and no ephemeral filesystem path.

#### Scenario: Audit omits secrets and ephemeral paths
- **WHEN** an audit record is written
- **THEN** it contains the placeholder argv projection and no secret name/value, no raw output, and no ephemeral path

#### Scenario: Audit is written before output is exposed
- **WHEN** a run finalizes
- **THEN** the audit record is written before any evidence is surfaced to the operator

