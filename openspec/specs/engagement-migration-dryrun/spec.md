# engagement-migration-dryrun Specification

## Purpose
TBD - created by archiving change engagement-v2-loader-scope. Update Purpose after archive.
## Requirements
### Requirement: Read-only migration analysis
`hackbot engagement migrate --engagement DIR --to 2 --profile PROFILE
--dry-run` SHALL validate the complete v1 engagement, require an explicit
profile from the P0 profile enum (`bug-bounty`, `local-lab`, `private-pentest`),
compute the proposed v2 files and warnings, and **write nothing**: no engagement
file, backup, temporary sibling tree, or in-place edit. The command SHALL leave
the engagement directory byte-for-byte unchanged.

#### Scenario: Dry-run writes nothing
- **WHEN** dry-run analysis runs against a valid v1 engagement
- **THEN** it prints the proposed v2 files and warnings and the engagement directory is unchanged (no new, modified, or deleted files)

#### Scenario: Missing profile is rejected
- **WHEN** `--to 2` is requested without an explicit `--profile`
- **THEN** the command fails with a clear error and writes nothing

#### Scenario: Invalid v1 engagement blocks analysis
- **WHEN** the source v1 engagement fails validation
- **THEN** the command reports the validation failure and writes nothing

### Requirement: Faithful proposed transformation
The analysis SHALL report a proposed v2 tree that preserves the exact
authoritative scope and authorization, carries compatible testing values
forward, uses the selected profile's scaffold defaults, defaults every new
sensitive capability to false, and proposes an empty `actions.yaml` unless the
operator separately supplies one. The analysis SHALL record existing approval
artifacts as historical and ineffective in v2.

#### Scenario: New sensitive capabilities default to false
- **WHEN** the proposed v2 tree introduces a sensitive capability absent from v1
- **THEN** the analysis shows that capability defaulted to false

#### Scenario: Scope and authorization are preserved exactly
- **WHEN** the analysis proposes the v2 scope and authorization
- **THEN** they preserve the exact authoritative v1 scope and authorization content, with no silent widening

### Requirement: No unenforceable migration is proposed
The analysis SHALL warn and refuse to propose an effective migration whenever a
proposed engagement would declare a feature the installed runtime cannot yet
enforce. Effective migration, backup creation, atomic publication, and restore
are out of scope for this capability and SHALL NOT be performed by the dry-run
path.

#### Scenario: Unenforceable feature is flagged
- **WHEN** the proposed v2 engagement would require a subsystem not yet delivered
- **THEN** the analysis emits a warning and does not present that migration as ready to apply

#### Scenario: Dry-run never performs effective migration
- **WHEN** any `--dry-run` analysis completes
- **THEN** no backup, temporary tree, or atomic publication occurs

