## ADDED Requirements

### Requirement: Strict manifest validation against the P0 contracts
The manifest loader SHALL validate `actions.yaml` (schema version 1) against the
archived P0 action-execution contracts and fail closed on any violation with the
exact P0 reason. It SHALL enforce at most 256 actions; lowercase snake/dotted
identifiers within their byte bounds; operator action IDs prefixed `operator.`
that do not collide with native IDs; typed parameter definitions and bounds;
declared evidence and rate-control modes; and `hackbot-safe-fullmatch-v1`
patterns. It SHALL be decoded through the same hardened, alias/merge/tag-free,
duplicate-rejecting path the P1 loader uses.

#### Scenario: Valid manifest loads
- **WHEN** an `actions.yaml` satisfies every P0 action-execution contract
- **THEN** the loader returns an immutable action registry and no execution occurs

#### Scenario: Manifest violating a bound fails closed
- **WHEN** a manifest declares more than 256 actions, an out-of-range parameter bound, or a malformed identifier
- **THEN** loading fails with `INVALID_ACTION_MANIFEST` (or the exact P0 reason) and produces no registry

#### Scenario: Unknown capability invalidates the manifest
- **WHEN** an action declares a capability outside the canonical capability set
- **THEN** loading fails with `INVALID_ACTION_MANIFEST` and produces no registry

### Requirement: Absolute executable and shell/interpreter/elevation contract
Every action SHALL select an absolute executable path. A shell or interpreter
basename SHALL be accepted only for an action whose declared minimum level is
`L3`, and inline-evaluation flag forms for shells and interpreters SHALL be
rejected. An elevation basename (`sudo`, `su`, `doas`, `pkexec`, `runas`,
`runas.exe`) SHALL NOT appear as `argv[0]`. Comparison SHALL be case-insensitive
on Windows and case-sensitive otherwise.

#### Scenario: Non-absolute executable rejected
- **WHEN** an action's executable is not an absolute path
- **THEN** loading fails with `INVALID_ACTION_MANIFEST`

#### Scenario: Interpreter inline-eval rejected even at L3
- **WHEN** an action names a shell/interpreter executable and any argv token is an inline-eval flag for that basename (for example `bash -c`, `python -c`)
- **THEN** loading fails with `INVALID_ACTION_MANIFEST` even when the action declares `L3`; the only safe L3 form is an interpreter with an immutable `{artifact_file:id}` script

#### Scenario: Elevation basename as an argv token rejected
- **WHEN** any argv token's basename is an elevation basename (`sudo`, `su`, `doas`, `pkexec`, `runas`, `runas.exe`)
- **THEN** loading fails with `INVALID_ACTION_MANIFEST`

#### Scenario: Target-shaped value parameter rejected
- **WHEN** a `{value:id}` placeholder references a parameter of a target-shaped type (`domain`, `host`, `ip`, `cidr`, `url`, `network-endpoint`, `target-list`)
- **THEN** loading fails with `INVALID_ACTION_MANIFEST`; target-shaped inputs MUST use scope-checked `{target:id}`/`{targets_file:id}` bindings

#### Scenario: Unknown action field rejected
- **WHEN** an action object contains a field outside the allowed action schema
- **THEN** loading fails with `INVALID_ACTION_MANIFEST`

### Requirement: Rate-control declaration
A network action SHALL declare exactly one rate-control mode. `not-applicable`
SHALL be valid only for an action that cannot make finite-rate network requests.
`argv-placeholder` SHALL bind both request rate and tool-internal concurrency
through typed whole-token parameters. `native-adapter` SHALL name a code-owned
adapter. A declaration that cannot enforce a finite rate SHALL be recorded so
that policy denies it with `DENY_RATE_UNENFORCEABLE`.

#### Scenario: argv-placeholder requires rate and concurrency parameters
- **WHEN** an action declares `argv-placeholder` rate control but omits a rate or concurrency parameter
- **THEN** loading fails with `INVALID_ACTION_MANIFEST`

#### Scenario: Missing rate control on a network action
- **WHEN** a finite-rate network action declares no rate-control mode
- **THEN** loading fails with `INVALID_ACTION_MANIFEST`
