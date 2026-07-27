## ADDED Requirements

### Requirement: Execution only after ALLOW
The executor SHALL spawn a child only when policy v2 returned `ALLOW` for the
request, and SHALL spawn exactly the P2 bound argv with `shell=False` and no
interpretation. It SHALL never build or run a shell string and SHALL never accept
a request-supplied argv. On any non-`ALLOW` decision it performs no spawn.

#### Scenario: Allowed request spawns the bound argv
- **WHEN** policy returns `ALLOW` with a bound command
- **THEN** the executor spawns exactly that argv with `shell=False`

#### Scenario: Denied request never spawns
- **WHEN** policy returns any `DENY_*`
- **THEN** the executor performs no spawn and creates no run resources

### Requirement: Private, sanitized execution environment
Each run SHALL execute inside a private resource directory created with mode
`0700`, used as the child's `CWD`, `HOME`, and `TMPDIR`. The child environment
SHALL be sanitized so no operator or host secret is inherited. Run files SHALL be
created exclusively (`O_EXCL`) with opaque numeric identifiers that never contain
parameter or secret names.

#### Scenario: Child runs in an isolated directory
- **WHEN** a run is prepared
- **THEN** `CWD`, `HOME`, and `TMPDIR` all point inside the private mode-`0700` run directory and no inherited secret is present in the environment

#### Scenario: Run files carry no sensitive names
- **WHEN** the executor creates temporary files
- **THEN** their names are opaque identifiers containing no parameter or secret name

### Requirement: Bounded lifecycle and child cleanup
The executor SHALL advance the run through the exact P0 lifecycle states in order
(`received`, `validated`, `allowed`, `prepared`, `spawned`,
`interaction-attempted`, `child-finished`, `evidence-finalized`,
`resource-cleanup`, `target-cleanup`, `finalized`), SHALL mark `executed` true
only at `spawned`, SHALL enforce output caps and a deadline during capture, and
SHALL terminate the child and its process group and reap it on completion,
timeout, or error.

#### Scenario: Deadline terminates the child
- **WHEN** a child exceeds the run deadline
- **THEN** the executor terminates the child and its process group and records a terminal failure without leaving a live process

#### Scenario: executed reflects spawn only
- **WHEN** a run fails before `spawned` (for example a missing secret)
- **THEN** `executed` is false and no impact entry is required
