## ADDED Requirements

### Requirement: Whole-token placeholder binding to a code-owned argv
The binder SHALL materialize a concrete argv only from the action's code-owned
`argv_template`, binding each placeholder to a typed value. The only placeholders
SHALL be `{value:<id>}`, `{target:<id>}`, `{targets_file:<id>}`,
`{artifact_file:<id>}`, and `{secret_file:<id>}`, each occupying an entire argv
token. A placeholder that shares a token with any other bytes SHALL fail with
`INVALID_PLACEHOLDER`. The binder SHALL NOT accept a request-supplied argv.

#### Scenario: Bound argv is produced from the template
- **WHEN** a request binds every template placeholder to a valid typed value
- **THEN** the binder returns a concrete argv and performs no execution

#### Scenario: Request-supplied argv is refused
- **WHEN** a request attempts to supply argv tokens directly
- **THEN** the binder fails with `INVALID_REQUEST` and produces no argv

#### Scenario: Partial-token placeholder is refused
- **WHEN** a placeholder occupies only part of an argv token (for example `--flag={value:id}`)
- **THEN** the binder fails with `INVALID_PLACEHOLDER`

### Requirement: argv[0] equals the selected absolute executable
The rendered `argv[0]` SHALL be exactly the action's selected absolute executable
path — never a placeholder, a shell, or a request-controlled value. This binding
is enforced by the binder (P0 review forward-carry N2).

#### Scenario: argv[0] is the executable
- **WHEN** an action binds successfully
- **THEN** `argv[0]` equals the selected absolute executable path byte-for-byte

#### Scenario: Executable cannot be overridden by the request
- **WHEN** a request attempts to set or template `argv[0]`
- **THEN** the binder fails with `INVALID_REQUEST`

### Requirement: No implicit shell or interpreter evaluation
The binder SHALL never introduce an implicit shell and SHALL never produce a
shell string. `shell_execution` and interpreter inline-evaluation are `L3` forms
and SHALL be rejected at bind time.

#### Scenario: Shell execution is rejected
- **WHEN** an action or request would require shell execution or a shell string
- **THEN** the binder fails closed and produces no argv

### Requirement: Typed parameter and target binding
The binder SHALL bind each `{value:id}` to a parameter validated against its
declared type and bounds (string length, integer range, enum membership, port
range, safe pattern) and each `{target:id}`/`{targets_file:id}` only to targets
that have passed scope validation. A value violating its type or bound SHALL fail
with `INVALID_REQUEST`. `{secret_file:id}` SHALL be bound as a secret reference
only and SHALL NOT be resolved by the binder.

#### Scenario: Out-of-bound parameter rejected
- **WHEN** a `{value:id}` bound to an integer parameter is outside its manifest bounds
- **THEN** the binder fails with `INVALID_REQUEST`

#### Scenario: Secret placeholder stays a reference
- **WHEN** an action declares a `{secret_file:id}` placeholder
- **THEN** the binder records a secret reference and never reads or embeds secret material (P3 resolves it)
