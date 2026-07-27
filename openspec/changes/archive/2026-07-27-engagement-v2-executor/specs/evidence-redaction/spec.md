## ADDED Requirements

### Requirement: Only declared outputs are retained
The executor SHALL retain only outputs the action manifest declares (relative
path, file/directory type, item and byte caps). Undeclared files created in the
private run directory SHALL be removed and SHALL NOT become evidence. A declared
output exceeding its item or byte cap SHALL be rejected or truncated per the
declaration, never silently kept whole.

#### Scenario: Undeclared output is discarded
- **WHEN** a child writes a file the manifest did not declare
- **THEN** the file is removed and never referenced as evidence

#### Scenario: Declared output over its cap is not kept whole
- **WHEN** a declared output exceeds its item or byte cap
- **THEN** it is rejected or truncated per the declaration and never stored beyond the cap

### Requirement: Evidence-mode enforcement
Operator actions SHALL default to `metadata-only`. `redacted-output` SHALL
require exact policy permission and SHALL be invalid for an action with declared
or inferred credential or sensitive-data capability, denying with
`EVIDENCE_POLICY_DENIED`. `structured` SHALL persist only closed-form structured
results. Exit code alone SHALL never demonstrate impact.

#### Scenario: Metadata-only is the default
- **WHEN** an action declares no evidence mode
- **THEN** only secret-free metadata is retained and no raw output is stored

#### Scenario: Credential action cannot use redacted-output
- **WHEN** an action with a credential/sensitive-data capability requests `redacted-output`
- **THEN** the run denies with `EVIDENCE_POLICY_DENIED` and stores no raw output

### Requirement: Secret-aware redaction before storage
Retained stdout and stderr SHALL be treated as untrusted and redacted before
storage: every resolved secret byte value SHALL be replaced, then the structural
and pattern redactors SHALL apply, then metadata SHALL be secret-scanned. Raw,
un-redacted output SHALL never be printed or stored, and redaction SHALL never be
the sole control that permits a credential capability.

#### Scenario: Resolved secret bytes are removed from output
- **WHEN** retained output contains a resolved secret's byte value
- **THEN** those bytes are replaced before the output is stored

#### Scenario: Raw output is never stored
- **WHEN** any output is retained
- **THEN** it is stored only after redaction and never in raw form
