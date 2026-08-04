## ADDED Requirements

### Requirement: Exact reviewed L3 action set
The catalog SHALL contain exactly the following 15 `L3` action IDs and no other
action:

- `operator.internal.directory.policies`
- `operator.internal.directory.spns`
- `operator.internal.directory.adcs`
- `operator.internal.directory.graph`
- `operator.internal.credential.asrep`
- `operator.internal.credential.kerberoast`
- `operator.internal.credential.laps`
- `operator.internal.credential.gmsa`
- `operator.internal.validation.password-spray`
- `operator.internal.responder.analyze`
- `operator.internal.responder.capture`
- `operator.internal.exploit.verify`
- `operator.internal.payload.verify`
- `operator.internal.lateral.verify`
- `operator.internal.persistence.verify`

The catalog SHALL reject `denial-of-service`, `destructive-testing`,
`data-exfiltration`, detection-evasion behavior, shell/interpreter execution,
and operator/model-supplied commands, argv, scripts, payloads, or modules. It
SHALL validate every complete definition, including typed inputs, targets,
capabilities, characteristics, adapter/image identity, network/rate/evidence
policy, cleanup, and provenance.

#### Scenario: Exact IDs and definitions load
- **WHEN** the reviewed catalog is validated
- **THEN** it contains exactly the 15 IDs above and every complete definition matches its code-owned golden definition

#### Scenario: Excluded or generic execution is rejected
- **WHEN** a definition adds an excluded capability, shell/interpreter, raw argv field, arbitrary module, script, command, or payload input
- **THEN** catalog validation fails with `INVALID_ACTION_MANIFEST`

### Requirement: Exact capability sets
Every catalog action SHALL require every capability in its exact set below, and
no profile name SHALL grant a capability:

- directory policies/SPNs/ADCS/graph: `authenticated-testing` and
  `sensitive-data-access`;
- AS-REP/Kerberoast/LAPS/gMSA: `credential-access` and
  `sensitive-data-access`;
- password spray: `credential-capture`, `automated-scanning`,
  `multiple-accounts`, and `state-changing`;
- Responder analyze: `sensitive-data-access`;
- Responder capture: `credential-capture` and `state-changing`;
- exploit verify: `exploit-execution`;
- payload verify: `payload-execution` and `state-changing`;
- lateral verify: `lateral-movement` and `credential-access`;
- persistence verify: `persistence` and `state-changing`.

A missing, `false`, or non-boolean mapped `testing_rules` flag SHALL deny with
`DENY_CAPABILITY_NOT_ALLOWED`. Engagement v2 SHALL NOT return
`REQUIRES_APPROVAL`.

#### Scenario: One missing capability denies
- **WHEN** any one capability required by an action is absent, false, or non-boolean
- **THEN** P3 denies with `DENY_CAPABILITY_NOT_ALLOWED` and no permit is issued

#### Scenario: Profile does not grant capability
- **WHEN** `private-pentest` or `local-lab` is active but one required capability is not exactly true
- **THEN** P3 denies with `DENY_CAPABILITY_NOT_ALLOWED`

### Requirement: Snapshot-bound activation and decision
The catalog SHALL load only for profile `private-pentest` or `local-lab` with
explicit internal-recon confirmation. Catalog activation, P3 evaluation, input
binding, and permit issuance SHALL use the same immutable snapshot identity,
profile, and `authority_digest`. Presence in source code SHALL NOT enable an
action.

#### Scenario: Same snapshot permits evaluation
- **WHEN** activation, P3 evaluation, binding, and permit issuance use the same confirmed authorized snapshot
- **THEN** snapshot binding does not deny the action

#### Scenario: Profile or authority changes after activation
- **WHEN** the P3 snapshot profile, identity, or authority digest differs from the snapshot that activated the catalog
- **THEN** execution denies with `DENY_AUTHORIZATION_STALE` before permit issuance

#### Scenario: Catalog is disabled by default
- **WHEN** the profile is unauthorized or internal recon is not explicitly confirmed
- **THEN** the loader returns no L3 action and denies with `DENY_AUTHORIZATION_UNCONFIRMED`

### Requirement: Signed single-use execution permit
Every L3 run SHALL require a canonical, domain-separated Ed25519
`ExecutionPermitV2` containing exactly the fields defined in the approved P5b
design. It SHALL bind engagement, authority/snapshot/profile, action-definition,
runner/helper, image, typed input, resolved endpoints, network/rate/evidence
policy, privileges, run ID, nonce, issue time, and expiry. Permit lifetime SHALL
be between 1 and 300 seconds inclusive.

The broker SHALL atomically reserve `(authority_digest, run_id, nonce)` in a
durable SQLite ledger before creating any namespace, mount, or container. The
reservation SHALL survive broker restart for the protocol replay window.

#### Scenario: Exact permit runs once
- **WHEN** a valid unexpired permit matches every broker and request binding
- **THEN** the broker reserves its replay tuple before resource creation and continues validation

#### Scenario: Permit is replayed after restart
- **WHEN** a previously reserved authority/run/nonce tuple is submitted after the broker restarts
- **THEN** the broker denies with `EXEC_PROTOCOL_REPLAY` and creates no resource

#### Scenario: Permit binding or field set differs
- **WHEN** a permit contains an unknown/missing field or differs in snapshot, action, runner, image, input, endpoint, policy, or privilege binding
- **THEN** the broker denies with `EXEC_PROTOCOL_INVALID` or `EXEC_PRIVILEGE_MISMATCH` before resource creation

#### Scenario: Permit time is invalid
- **WHEN** a permit is expired, not yet valid, or has a lifetime outside 1-300 seconds
- **THEN** the broker denies with `EXEC_PROTOCOL_EXPIRED`

### Requirement: Fixed broker and typed adapters
The Linux runner SHALL execute an L3 action only through the fixed, root-owned,
digest-pinned `hackbot-l3-runner`. The SSH transport SHALL invoke only that
forced stdin/stdout command with host key and identity pinned and forwarding,
agent, X11, TTY, and interactive shell disabled.

Each action SHALL map to one code-owned typed adapter. Adapter inputs SHALL
reject unknown fields. An adapter SHALL construct its immutable invocation,
mounts, secrets, network policy, parser, and cleanup from code-owned values and
SHALL NOT invoke a shell or accept raw argv, commands, scripts, payload bytes, or
unreviewed modules.

#### Scenario: Typed request reaches its exact adapter
- **WHEN** a valid bound request and permit name one reviewed action
- **THEN** the broker selects only that action's digest-matched adapter and code-owned invocation

#### Scenario: Request attempts to alter execution
- **WHEN** an input adds an unknown field, executable, argv token, environment override, shell text, script, payload bytes, or module outside the closed enum
- **THEN** the broker denies with `INVALID_REQUEST` and spawns nothing

### Requirement: Immutable OCI supply chain
Every upstream tool SHALL execute from `repository@sha256:<64 lowercase hex>`.
A committed lockfile SHALL bind adapter ID, upstream release/commit, source
digest, base-image digest, package snapshot, built image digest, `linux/amd64`,
and SBOM digest. Tags and host-installed tool versions SHALL NOT satisfy runtime
identity.

A promotion receipt SHALL bind the exact action-definition, adapter, image, and
lab-scenario digests. Changing any bound value SHALL make the action unavailable
until its E2E test passes again.

#### Scenario: Locked image and receipt match
- **WHEN** adapter, image, platform, SBOM, definition, and promotion receipt digests all match
- **THEN** supply-chain validation permits the run to continue

#### Scenario: Tag, host tool, or digest drift is presented
- **WHEN** runtime receives a tag-only image, a host-installed tool, a missing SBOM, or any digest differing from the lockfile/receipt
- **THEN** the broker denies with `EXEC_TRUST_MISMATCH` before container creation

### Requirement: Default-deny network containment
Every complete networked action definition SHALL declare a closed ordered
endpoint-binding schema containing each code-owned role, its allowed URI
scheme/protocol set, and cardinality. The confirmed engagement/request SHALL
supply the full URI or network endpoint, including an explicit port, for every
primary and auxiliary destination. An adapter SHALL NOT apply an omitted-port
default, use an implicit system resolver, discover an undeclared endpoint,
follow a redirect or proxy, or widen authority from tool output.

A hostname binding SHALL require an explicit DNS resolver endpoint bound to the
same snapshot, request, and permit; an IP-literal binding SHALL NOT require a
resolver. The control plane and broker SHALL use that same resolver. The permit
SHALL contain the complete normalized role, original hostname, resolved IP,
port, and protocol set for the action. The broker SHALL resolve names
immediately before execution; every complete answer set SHALL exactly equal the
permitted resolved set and remain in confirmed scope. Mixed-scope answers, DNS
changes, redirects, proxies, and discovery of undeclared peers SHALL deny.

Before attaching a tool container, the broker SHALL create an ephemeral network
namespace and install default-deny nftables rules. The tool SHALL NOT modify
those rules. A subnet target SHALL be parsed as a first-class CIDR and SHALL be
wholly contained by confirmed scope.

#### Scenario: Exact endpoint is contained
- **WHEN** every resolved address and requested port/protocol matches the permit and confirmed scope
- **THEN** the namespace allows only those flows and blocks all other egress and ingress

#### Scenario: Required endpoint binding is absent
- **WHEN** a required primary or auxiliary endpoint, explicit port, or required DNS resolver binding is absent
- **THEN** validation denies with `INVALID_REQUEST` or `DENY_POLICY_LIMIT` before permit issuance

#### Scenario: Adapter attempts implicit or discovered authority
- **WHEN** an adapter attempts a default port, system-resolver fallback, undeclared peer, discovered endpoint, redirect, or proxy
- **THEN** execution fails closed before forbidden traffic leaves the namespace

#### Scenario: DNS answer or destination changes
- **WHEN** re-resolution adds, removes, or changes an address or the tool attempts an undeclared IP, port, protocol, redirect, proxy, or peer
- **THEN** execution fails closed with `EXEC_TRUST_MISMATCH` or `DENY_POLICY_LIMIT` and the forbidden traffic does not leave the namespace

#### Scenario: Lab tries to reach the LAN
- **WHEN** any lab container attempts to reach the SSH management address, LAN default gateway, or Internet
- **THEN** the internal lab network blocks the traffic and the isolation test fails if any packet escapes

### Requirement: Durable bounded password validation
Password spray SHALL accept exactly one password candidate and between 1 and 25
explicit account identifiers for one scoped host. It SHALL run with concurrency
one and at least 30 seconds between attempts. It SHALL require a confirmed,
current lockout threshold greater than one and SHALL allow at most
`lockout_threshold - 1` cumulative attempts per account across runs. The broker
SHALL persist the budget by authority, action, target, and account-set digest.

#### Scenario: Safe spray budget is enforced
- **WHEN** one candidate, at most 25 accounts, a known threshold, and sufficient durable budget are present
- **THEN** the broker serializes attempts, waits at least 30 seconds between them, and updates durable budget before each attempt

#### Scenario: Budget or policy is unsafe
- **WHEN** the candidate/account bounds are exceeded, the threshold is missing/stale/not greater than one, or any account lacks remaining safety margin
- **THEN** the broker denies with `DENY_RATE_UNENFORCEABLE` before the first unsafe attempt

#### Scenario: Container restart cannot reset attempts
- **WHEN** a spray container or broker restarts after recorded attempts
- **THEN** the next run uses the persisted cumulative budget rather than a new budget

### Requirement: Ephemeral secrets and closed evidence
Secret references SHALL resolve on the runner only after permit and containment
validation. Secret values SHALL be delivered only through read-only tmpfs files,
stdin, or an ephemeral Kerberos cache and SHALL NOT enter permits, environment
variables, argv, OCI labels, logs, audit, errors, receipts, findings, reports, or
fixtures.

Credential/sensitive actions SHALL use `metadata-only` or a closed native
`structured` schema and SHALL NOT retain raw/redacted stdout, stderr, passwords,
hashes, tickets, managed-password blobs, private keys, or reusable authentication
material. A final secret detector SHALL validate every serialized result. Exit
code alone SHALL NOT demonstrate impact.

#### Scenario: Closed structured credential result is valid
- **WHEN** a sensitive adapter returns only its allowed counts, booleans, bounded masked identifiers, enums, timestamps, and correlation digests
- **THEN** the structured result may be retained after the final secret scan passes

#### Scenario: Raw or secret-like value reaches evidence
- **WHEN** result material contains free-form tool output, a resolved secret, credential line, password/hash/ticket/key/token pattern, or a field outside the closed schema
- **THEN** evidence denies with `EVIDENCE_POLICY_DENIED`, stores no raw material, and does not report demonstrated impact

### Requirement: Responder modes are mechanically distinct
`operator.internal.responder.analyze` SHALL invoke only Responder analyze mode,
SHALL NOT poison or capture authentication material, and SHALL retain only
protocol/request counters. `operator.internal.responder.capture` SHALL be a
separate L3 `credential-capture` and `state-changing` adapter, SHALL NOT carry a
passive/discovery label, and SHALL retain only protocol, source, masked
principal, and capture count.

Both modes SHALL use a dedicated authorized interface and CIDR, never the SSH
management interface. Capture SHALL destroy collected material after parsing.
Each invocation SHALL have a maximum duration of 120 seconds.

#### Scenario: Analyze mode cannot poison
- **WHEN** the analyze action runs in the lab
- **THEN** packets demonstrate observation without poisoning/capture and the result contains counters only

#### Scenario: Capture is not passive
- **WHEN** the capture action is validated or run
- **THEN** it requires its exact capture/state-changing capabilities, dedicated interface, and non-passive classification

#### Scenario: Management interface is selected
- **WHEN** either Responder action requests the SSH management interface or a CIDR not wholly in scope
- **THEN** it denies before interface attachment

### Requirement: Controlled proof actions accept no arbitrary behavior
Exploit verify SHALL select only a code-owned reviewed profile from a closed enum,
verify the target fingerprint, and return one random proof token without an
interactive session. The initial enum SHALL contain only `lab-proof-v1`, which
SHALL be valid only for `local-lab`.

Payload verify SHALL create, read, and remove one code-owned benign marker.
Lateral verify SHALL use batch SSH to one additional scoped host and invoke only
`/usr/bin/true`. Persistence verify SHALL install, verify, and remove one inert
user-level marker in the same run. None SHALL accept operator/model commands,
scripts, payload bytes, persistence mechanisms, or cleanup commands.

#### Scenario: Lab proof completes and cleans up
- **WHEN** a controlled proof action runs against its matching disposable target
- **THEN** it returns only its closed proof receipt and leaves no marker/session/persistence after cleanup

#### Scenario: Arbitrary behavior is requested
- **WHEN** a request supplies a non-reviewed exploit profile, command, script, payload, marker path, persistence mechanism, or cleanup command
- **THEN** it denies with `INVALID_REQUEST` before target interaction

#### Scenario: Lab exploit profile is requested for private pentest
- **WHEN** `lab-proof-v1` is requested under `private-pentest`
- **THEN** it denies with `DENY_POLICY_LIMIT`

### Requirement: Cleanup and crash recovery are enforced
Resource cleanup and target cleanup SHALL execute independently after every
interaction attempt. Runtime timeout SHALL terminate the complete
container/cgroup before cleanup. A mutable action whose target cleanup is not
verified SHALL return `CLEANUP_TARGET_INCOMPLETE` and SHALL create a durable block
on later mutable actions for that authority and target.

On startup the broker SHALL reconcile unfinished ledger entries with labeled
containers, namespaces, nftables rules, tmpfs mounts, and target cleanup receipts
before accepting new work.

#### Scenario: Target cleanup fails
- **WHEN** a payload or persistence marker cannot be verified as removed
- **THEN** the result is `CLEANUP_TARGET_INCOMPLETE` and later mutable actions for the authority/target remain blocked

#### Scenario: Broker crashes during a run
- **WHEN** the broker restarts with an unfinished durable run
- **THEN** it reconciles and cleans all labeled resources before accepting another action

### Requirement: Promotion requires faithful isolated E2E
An action SHALL be `executable` only when a committed receipt proves its real
typed adapter and digest-pinned upstream tool passed an individually addressable
E2E scenario in the disposable lab. The scenario SHALL prove permit and replay,
image identity, expected and forbidden traffic, real target interaction, closed
evidence, secret absence, resource cleanup, and target cleanup.

The lab SHALL use synthetic credentials and internal networks with no route to
the LAN or Internet. Parser mocks and synthetic output fixtures SHALL NOT create
a promotion receipt. If a protocol-faithful scenario cannot run, the action SHALL
remain `implemented` and unavailable.

#### Scenario: Complete receipt promotes one action
- **WHEN** one action passes every required E2E assertion with definition, adapter, image, and scenario digests matching
- **THEN** only that action progresses from `isolated-e2e-passed` to `executable`

#### Scenario: Tool is mocked or scenario is incomplete
- **WHEN** a test replaces the upstream tool/target protocol with a mock or omits containment, evidence, secret, or cleanup assertions
- **THEN** no promotion receipt is generated and the action remains unavailable

#### Scenario: Public CI runs
- **WHEN** the public GitHub Actions suite executes
- **THEN** it runs only contract, golden, property, negative, parser-fixture, lockfile/SBOM, receipt, documentation, publication, and secret-scan tests and performs no live L3 action

### Requirement: Provenance and compatibility remain auditable
Every action SHALL identify its local code-owned adapter, exact upstream
repository/revision where applicable, category, classification, risk,
capabilities, labels, and review attribution. Provenance SHALL NOT claim a
nonexistent skill file or attribute locally invented behavior to an upstream
project. Schema v1 behavior SHALL remain byte-for-byte unaffected by loading,
executing, disabling, or rolling back P5b.

#### Scenario: Provenance is complete and real
- **WHEN** the 15 definitions are validated
- **THEN** every referenced local path exists and every upstream revision matches the OCI lockfile

#### Scenario: P5b is disabled or rolled back
- **WHEN** all L3 promotion receipts are disabled or the P5b broker/catalog is removed
- **THEN** schema v1 fixtures and behavior remain unchanged
