# action-execution-contracts Specification

## Purpose
Define the versioned, bounded, secret-safe action and execution-request
contracts that later binder, policy, and executor phases must consume without
activating an Engagement v2 runtime path in P0.

## Requirements
### Requirement: Exact action manifest bounds
Action manifest v1 SHALL contain at most 256 actions. Each action SHALL contain
at most 128 parameters, 32 secrets, 32 target bindings, 64 capabilities, 64
vulnerability types, 64 impacts, and 128 argv tokens.

General value identifiers, including action and node IDs, SHALL be lowercase
ASCII, at most 128 bytes, and match
`[a-z0-9]+(?:[._-][a-z0-9]+)*`. Operator action IDs SHALL start with `operator.`
and SHALL NOT collide with native IDs. Secret reference values SHALL match
`secret:[a-z0-9]+(?:[._-][a-z0-9]+)*` and SHALL be resolved only inside the
canonical engagement namespace.

Parameter names, action-request parameter keys, secret binding names, target
binding names, and placeholder IDs SHALL be lowercase ASCII snake case, at
most 64 bytes, and match `[a-z][a-z0-9_]{0,63}`.

#### Scenario: Manifest at every closed maximum is valid
- **WHEN** a manifest uses each maximum without duplicate identifiers
- **THEN** contract validation accepts its collection sizes

#### Scenario: One excess action rejects the whole manifest
- **WHEN** a manifest contains 257 actions
- **THEN** validation fails with `INVALID_ACTION_MANIFEST` and registers no partial action set

#### Scenario: Secret reference is engagement-scoped
- **WHEN** two engagements use the same canonical secret name
- **THEN** their contract lookup keys remain distinct because canonical engagement identity is part of the lookup key

### Requirement: Exact parameter and prepared-input bounds
Parameter types SHALL be exactly `string`, `integer`, `boolean`, `enum`, `port`,
`domain`, `host`, `ip`, `cidr`, `url`, `network-endpoint`, `repository`,
`contract`, `target-list`, and `artifact-ref`.

Scalar/target encoded values SHALL be at most 2,048 UTF-8 bytes except a
manifest-bounded string, whose declared maximum SHALL be 1 through 8,192 bytes.
An enum SHALL contain 1 through 256 unique values. An integer SHALL use
inclusive signed 64-bit bounds further narrowed by its manifest. A port SHALL
be 1 through 65,535. Target-list length SHALL be bounded by the lower of 65,536
and `max_targets_per_action`.

An individual resolved secret SHALL be at most 1,048,576 bytes, total secret
bytes SHALL be at most 4,194,304, and total prepared input bytes across target
lists, immutable artifacts, and secrets SHALL be at most 67,108,864.

#### Scenario: Boolean cannot satisfy integer
- **WHEN** a boolean is supplied for an integer or port parameter
- **THEN** request binding fails with `INVALID_REQUEST`

#### Scenario: Prepared input total is bounded
- **WHEN** individually valid inputs exceed 67,108,864 aggregate bytes
- **THEN** preparation fails before spawn with `INVALID_LIMIT`

### Requirement: Deterministic safe full-match pattern
Optional string patterns SHALL use `hackbot-safe-fullmatch-v1`, an implicitly
anchored ASCII grammar no longer than 256 bytes. It SHALL support only:

- unescaped ASCII letters, digits, space, `_`, `.`, `:`, `/`, and `@`;
- escaped literal `-`, `[`, `]`, `{`, `}`, and reverse solidus;
- character classes containing 1 through 64 ASCII literals or ascending
  `A-Z`, `a-z`, or `0-9` ranges, with optional leading `^`;
- bounded quantifiers `{m}` or `{m,n}` where `0 <= m <= n <= 1024`.

Grouping, alternation, dot wildcard, anchors, lookaround, backreferences,
Unicode classes, unbounded `*`/`+`/`?`, nested quantifiers, and empty matches
without an explicit `{0,n}` MUST fail with `INVALID_ACTION_MANIFEST`.
Evaluation SHALL be full-match and linear in input length times pattern length.
Match input SHALL be printable ASCII and at most 8,192 bytes; the first byte
beyond that limit MUST fail before matching with `INVALID_LIMIT`.

#### Scenario: Bounded identifier pattern matches
- **WHEN** pattern `[A-Za-z0-9._\-]{1,64}` is compiled and input is `dc01.corp`
- **THEN** full-match succeeds

#### Scenario: Backtracking construct is rejected
- **WHEN** a pattern contains `(a+)+`, alternation, lookaround, or a backreference
- **THEN** pattern compilation fails with `INVALID_ACTION_MANIFEST`

### Requirement: Whole-token placeholder grammar
The only placeholders SHALL be `{value:<id>}`, `{target:<id>}`,
`{targets_file:<id>}`, `{artifact_file:<id>}`, and `{secret_file:<id>}`, where
`<id>` satisfies the binding-name contract
`[a-z][a-z0-9_]{0,63}`. A placeholder SHALL occupy the entire argv token and be
used only with a matching declared binding.

Each argv token SHALL be 1 through 4,096 UTF-8 bytes. The rendered argv SHALL
contain 1 through 128 tokens and at most 65,536 UTF-8 bytes including one NUL
terminator per token. `argv[0]` SHALL exactly equal the selected absolute
executable.

#### Scenario: Reordering named bindings is deterministic
- **WHEN** whole-token placeholders are reordered in a manifest
- **THEN** each value binds by canonical name and no positional inference occurs

#### Scenario: Concatenated placeholder is rejected
- **WHEN** a token is `--target={target:host}` or contains unmatched braces
- **THEN** manifest validation fails with `INVALID_PLACEHOLDER`

#### Scenario: General identifiers do not widen binding names
- **WHEN** a binding key or placeholder ID is `1-target`, `target-name`, or `target.name`
- **THEN** manifest validation fails while those forms remain representable in general value-identifier fields

### Requirement: Exact platform, architecture, privilege, and execution enums
Platforms SHALL be exactly `linux`, `darwin`, and `windows`. Architectures
SHALL be exactly `x86_64` and `arm64`. Privileges SHALL be exactly
`network-raw`, `network-admin`, `packet-capture`,
`filesystem-protected-read`, and `superuser`.

Risk levels SHALL remain `L0`, `L1`, `L2`, and `L3`. Evidence modes SHALL be
`metadata-only`, `redacted-output`, and `structured`. Rate-control modes SHALL
be `argv-placeholder`, `native-adapter`, and `not-applicable`. Secret
transports SHALL be `stdin` and `file`.

#### Scenario: Unknown enum fails before policy
- **WHEN** an action declares an unregistered platform, privilege, evidence mode, rate mode, or secret transport
- **THEN** manifest validation fails with `INVALID_ACTION_MANIFEST`

#### Scenario: Superuser implies L3 contract floor
- **WHEN** an action declares `superuser`
- **THEN** its contract-derived minimum risk is `L3` and privileged execution is required

### Requirement: Shell, interpreter, and elevation contract
Executable basenames recognized as shells SHALL be `sh`, `bash`, `dash`, `zsh`,
`ksh`, `csh`, `tcsh`, `fish`, `cmd`, `cmd.exe`, `powershell`,
`powershell.exe`, `pwsh`, and `pwsh.exe`. Elevation basenames SHALL be `sudo`,
`su`, `doas`, `pkexec`, `runas`, and `runas.exe`; they MUST NOT appear as an
action executable or argv token.

Shells and interpreters SHALL be accepted only for an L3
`payload-execution` action with an immutable script artifact. Inline command
modes SHALL be rejected:

- Interpreter basenames SHALL be `python`, `python3`, `python.exe`, `perl`,
  `perl.exe`, `ruby`, `ruby.exe`, `php`, `php.exe`, `node`, and `node.exe`,
  in addition to the shell basenames above.
- POSIX shells: `-c`, `--command`;
- Python: `-c`;
- Perl/Ruby/PHP: `-e`, `-r`;
- Node: `-e`, `--eval`, `-p`, `--print`;
- PowerShell: `-command`, `-c`, `-encodedcommand`, `-enc`;
- cmd: `/c`, `/k`.

Comparison SHALL be case-insensitive on Windows and case-sensitive otherwise.

#### Scenario: Immutable script mode is representable
- **WHEN** an L3 payload action uses an allowed interpreter plus one immutable `{artifact_file:<id>}` script token and no inline mode
- **THEN** the contract layer can represent it for later policy evaluation

#### Scenario: Elevation inside argv is rejected
- **WHEN** any argv token resolves to a listed elevation basename
- **THEN** manifest validation fails with `INVALID_ACTION_MANIFEST`

### Requirement: Rate-control contract
A network action SHALL declare one rate-control mode. `not-applicable` SHALL be
valid only when there is one target, `high_volume=false`,
`recursive_discovery=false`, and the action cannot fan out.
`argv-placeholder` SHALL bind both rate and tool-internal concurrency through
typed whole-token parameters. `native-adapter` SHALL identify a code-owned
adapter contract.

#### Scenario: Multi-target scanner without enforceable rate is denied
- **WHEN** a network action accepts a target list but declares `not-applicable`
- **THEN** later policy evaluation MUST return `DENY_RATE_UNENFORCEABLE`

#### Scenario: Process concurrency is not tool concurrency
- **WHEN** only runner process concurrency is bounded for a high-volume tool
- **THEN** the action does not satisfy the rate-control contract

### Requirement: Evidence and output contract
Operator actions SHALL default to `metadata-only`. `redacted-output` SHALL
require exact policy true and SHALL be invalid for declared or inferred
credential/sensitive-data capabilities. `structured` SHALL be available only
to a native code-owned parser with a closed schema containing no free-text,
unknown-field, pass-through, or raw-output member.

Each retained output SHALL declare a relative path, file/directory type,
maximum item count 1 through 64, maximum individual size 1 through 33,554,432
bytes, and evidence mode. Total retained outputs SHALL not exceed 67,108,864
bytes. Absolute paths, empty segments, `.`, `..`, symlinks, and undeclared
outputs MUST be rejected or removed.

#### Scenario: Credential-capable operator output is metadata only
- **WHEN** an operator action declares or infers credential or sensitive-data access
- **THEN** any evidence mode other than `metadata-only` fails with `EVIDENCE_POLICY_DENIED`

#### Scenario: Structured schema cannot pass raw text
- **WHEN** a native structured schema contains a free-text or unknown-field member
- **THEN** contract validation rejects the schema

### Requirement: Execution and cleanup lifecycle
Lifecycle states SHALL be exactly `received`, `validated`, `allowed`,
`prepared`, `spawned`, `interaction-attempted`, `child-finished`,
`evidence-finalized`, `resource-cleanup`, `target-cleanup`, and `finalized`.
Transitions SHALL move forward in that order; terminal failure metadata SHALL
record the last reached state.

`executed` SHALL become true only at `spawned`. Impact entries SHALL become
mandatory at `interaction-attempted`. Resource cleanup states SHALL be
`not-required`, `complete`, and `failed`. Target cleanup states SHALL be
`not-required`, `complete`, `deferred`, `failed`, and
`unverified-self-report`.

#### Scenario: Spawn failure has no fabricated impact
- **WHEN** preparation succeeds but process spawn fails
- **THEN** `executed=false`, the last lifecycle state is `prepared`, and no impact entry is required

#### Scenario: Disconnect after spawn is incomplete execution
- **WHEN** a remote disconnect occurs after `spawned`
- **THEN** `executed=true`, completion is non-success, and cleanup states cannot be inferred as complete

#### Scenario: Self-reported target cleanup is not complete
- **WHEN** only the tested target reports its own post-state
- **THEN** target cleanup state is `unverified-self-report` and autonomous dependents remain blocked
