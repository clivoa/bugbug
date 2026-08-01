# Engagement v2 P5b Executable Layer Design

**Status:** approved  
**Date:** 2026-08-01  
**Change:** `engagement-v2-l3-catalog`  
**Issue:** GitHub #10

## Purpose

P5b will deliver the complete executable layer for the reviewed credential and
L3 internal-pentest catalog. The result is not a generic command runner. It is a
closed set of 15 code-owned actions whose authorization, network reachability,
tool version, arguments, rate, secret handling, evidence, and cleanup are
enforced by code.

An action is executable only after its own end-to-end test passes against a
disposable lab. Presence in source code, an internal profile name, or a policy
decision alone never enables execution.

## Goals

- Bind every execution to the exact confirmed engagement snapshot and policy
  decision.
- Execute on a Linux runner through typed, code-owned adapters without accepting
  arbitrary commands, scripts, modules, payloads, or tool arguments.
- Run tools from OCI images pinned by immutable digest and fail closed on drift.
- Enforce targets, ports, protocols, rate limits, concurrency, and cleanup at
  runtime.
- Keep credentials, hashes, tickets, and reusable authentication material out of
  permits, arguments, logs, evidence, and repository artifacts.
- Validate every action with the real adapter and real upstream tool in an
  isolated, disposable lab before promoting it to the executable catalog.
- Support authorized offensive tests against explicitly scoped LAN assets from
  a Linux runner; macOS remains a control plane.

## Non-goals

- Generic shell or arbitrary container execution.
- User- or model-supplied exploit modules, scripts, payloads, commands, or raw
  argument arrays.
- Denial of service, destructive testing, data exfiltration, detection evasion,
  persistence that survives the verification run, or automatic action chaining.
- Treating the SSH control endpoint as a test target.
- Running live offensive actions in public GitHub Actions.
- Persisting raw stdout or stderr from credential-sensitive tools.

## Selected architecture

The selected design is one versioned `hackbot-l3-runner` broker with a typed
adapter for each action. A broker keeps authorization, containment, evidence,
and cleanup consistent while adapters remain small and independently testable.
A service per upstream tool was rejected because it duplicates security policy.
Direct container invocation from a manifest was rejected because it cannot
reliably enforce scope, rate, evidence, or cleanup.

The flow is:

```text
confirmed P3 snapshot and ALLOW decision
  -> signed, single-use ExecutionPermit
  -> fixed P4 SSH transport
  -> hackbot-l3-runner on Linux
  -> typed action adapter
  -> digest-pinned OCI tool image in an ephemeral network namespace
  -> closed structured evidence and cleanup receipt
```

The existing P0/P3/P4 primitives are extended rather than replaced:

- `EngagementSnapshot.authority_digest` remains the authority identity.
- The existing Ed25519 permit verifier becomes the basis of the L3 permit
  envelope.
- The P4 framed protocol and fixed SSH helper remain the transport boundary.
- Replay protection becomes durable and cross-process before resource creation.
- The current generic remote helper does not execute an L3 action directly; it
  delegates only to the fixed broker after all L3 claims validate.

## Trust boundaries

### Control plane

The control plane loads one immutable `EngagementSnapshot`, evaluates the exact
catalog definition through P3, binds typed inputs, and signs the permit. It owns
the Ed25519 private key. A successful policy decision that is not bound to the
same snapshot used to load the catalog is invalid.

### SSH transport

SSH is control transport only. Host key, identity, user, port, and helper path
remain pinned by the confirmed runner document. Forwarding, agent forwarding,
X11, and TTY stay disabled. `192.168.1.45` may host the test runner but is never
implicitly in scope and is never a test target.

### Linux broker

The broker owns the permit public key, durable replay ledger, OCI lockfile,
adapter registry, rate state, execution lifecycle, and sanitized result schema.
It accepts one framed request on stdin and returns one framed result. It exposes
no listening network service.

### Tool container

Each invocation gets a read-only container filesystem, private writable tmpfs,
dropped capabilities by default, explicit resource limits, and an ephemeral
network namespace. Only Responder receives the minimum network capabilities its
mode requires. The image cannot choose its own network policy.

### Target network

The runner may reach only addresses, ports, and protocols copied into the permit
from the confirmed snapshot. The disposable lab uses internal Docker networks
with no route to the LAN or Internet. Production execution uses a dedicated
namespace with fail-closed egress rules.

## Execution permit v2

`ExecutionPermitV2` is canonical JSON, domain-separated and signed with
Ed25519. It contains exactly:

- `schema_version`
- `engagement_id`
- `authority_digest`
- `snapshot_identity`
- `profile`
- `action_id`
- `action_definition_digest`
- `runner_identity`
- `runner_helper_digest`
- `image_reference`
- `image_digest`
- `input_digest`
- `resolved_endpoints`
- `network_rules`
- `rate_policy`
- `required_privileges`
- `evidence_schema`
- `run_id`
- `nonce`
- `issued_at`
- `expires_at`

The maximum validity remains 300 seconds. The broker verifies the pinned signer,
signature, exact field set, timestamps, runner identity, helper digest, image
digest, action definition digest, and every run binding before creating a
container or network namespace.

The replay key is `(authority_digest, run_id, nonce)`. It is reserved atomically
in a broker-owned SQLite database before resource creation and retained for at
least the protocol replay window. A duplicate is rejected even after broker
restart.

## Catalog lifecycle

Actions have three explicit states:

```text
implemented -> isolated-e2e-passed -> executable
```

The reviewed definition and implementation may exist while the action remains
unavailable. Promotion requires a matching, committed verification receipt for
the action definition digest, adapter digest, image digest, and lab scenario
digest. Changing any of those values returns the action to `implemented`.

The catalog loader requires all of the following:

1. profile `private-pentest` or `local-lab`;
2. explicit internal-recon confirmation;
3. the same profile and authority digest in the snapshot used by P3;
4. every capability required by the action set to boolean `true`;
5. a valid executable promotion receipt;
6. a runner compatible with the pinned broker and image digests.

Catalog validation compares complete definitions, not only IDs and selected
invariants. Executable path, image identity, adapter identity, typed inputs,
capabilities, characteristics, rate policy, evidence schema, cleanup contract,
and provenance are all exact code-owned values.

## Action contracts

All actions remain L3. Credentials used for authenticated actions are secret
references resolved only on the runner. Kerberos-capable tools receive an
ephemeral credential-cache file where possible. Password candidates and account
lists are bounded files in tmpfs. Secret values never appear in a permit or
audit projection.

### Authenticated directory enumeration

| Action | Adapter behavior | Closed result |
|---|---|---|
| `operator.internal.directory.policies` | Authenticated LDAP query against one explicit DC and base DN for password and lockout policy attributes. | Attribute presence and normalized numeric policy fields. |
| `operator.internal.directory.spns` | Authenticated LDAP query against one explicit DC and base DN; no recursive host action follows. | Count and masked principals/SPN service classes. |
| `operator.internal.directory.adcs` | Certipy `find` against one explicit DC/domain using Kerberos material and JSON parsing. | Counts and identifiers of enabled CAs/templates; no private material. |
| `operator.internal.directory.graph` | BloodHound.py with the code-owned `DCOnly` collection set and explicit DC/domain. | Object and relationship counts plus output digest; no ZIP is retained by Hackbot. |

`DCOnly` is selected because BloodHound.py documents it as a collection set that
queries the domain controller rather than automatically contacting member hosts.

### Credential-material access

| Action | Adapter behavior | Closed result |
|---|---|---|
| `operator.internal.credential.asrep` | Impacket `GetNPUsers` requests material only for a bounded, explicit principal list and DC. | Attempt count, eligible-principal count, masked principals, encryption-type metadata. |
| `operator.internal.credential.kerberoast` | Impacket `GetUserSPNs` requests tickets only for a bounded, explicit principal/SPN set and DC. | Request count, ticket count, masked principals, encryption-type metadata. |
| `operator.internal.credential.laps` | NetExec LDAP adapter reads authorized LAPS attributes for one bounded computer set. | Presence, schema/version, rotation metadata, and count; never the password. |
| `operator.internal.credential.gmsa` | NetExec LDAP adapter reads authorized gMSA metadata for one bounded account set. | Presence, account count, and rotation metadata; never key material. |

Raw AS-REP blobs, TGS tickets, LAPS passwords, gMSA managed-password blobs, and
derived hashes are discarded after parsing and secret scanning.

### Validation and capture

| Action | Adapter behavior | Closed result |
|---|---|---|
| `operator.internal.validation.password-spray` | NetExec validates an explicit account list against one host with a bounded candidate set, mandatory delay, concurrency one, and a budget derived from the confirmed lockout policy. | Attempt/success/locked-out counts and masked successful principals. |
| `operator.internal.responder.analyze` | Responder analyze-only mode on a dedicated interface. It observes but does not poison. | Protocol and request counters only. |
| `operator.internal.responder.capture` | Responder poisoning/capture mode on a dedicated authorized interface and subnet. | Protocol, source, masked principal, and capture count; captured material is destroyed. |

Password spray declares `multiple-accounts`, `credential-capture`,
`automated-scanning`, and `state-changing`. It refuses to run without a verified
lockout threshold and stops below the configured safety margin. The rate bucket
is broker-owned and keyed by authority, action, target, and account set, so
restarting a container cannot reset it.

Responder capture is never labeled passive or discovery. Analyze and capture use
separate adapter entry points and privilege sets.

### Controlled proofs

| Action | Adapter behavior | Closed result and cleanup |
|---|---|---|
| `operator.internal.exploit.verify` | Runs one code-owned exploit profile selected from a closed enum against a matching, fingerprinted service. The first profile targets only the synthetic lab service. | Random proof token observed once; no interactive session. |
| `operator.internal.payload.verify` | Sends a code-owned benign marker operation through a verified execution channel. | Marker create/read/delete receipt. |
| `operator.internal.lateral.verify` | Performs fixed batch SSH authentication to one additional scoped host and invokes only `/usr/bin/true`. | Authentication and fixed-command status. |
| `operator.internal.persistence.verify` | Installs one code-owned, inert user-level persistence marker, verifies it, and removes it in the same run. | Install/verify/remove receipt; cleanup failure is critical. |

These actions never accept a module name outside the closed registry, a script,
shell text, payload bytes, or a command supplied by the operator or model.
Exploit profiles are separately reviewed code artifacts. The initial profile is
lab-only; production exploit profiles require their own future review and E2E
receipt before promotion.

## OCI supply chain

The repository contains a generated lockfile mapping every adapter to an exact
source revision, base-image digest, built image digest, platform, and SBOM
digest. Runtime accepts only `repository@sha256:...`; tags are provenance labels,
not execution identities.

The initial upstream pins are:

- [NetExec v1.5.1](https://github.com/Pennyw0rth/NetExec/releases/tag/v1.5.1)
- [Impacket 0.13.1](https://github.com/fortra/impacket/releases/tag/impacket_0_13_1)
- [Certipy 5.1.0](https://github.com/ly4k/Certipy/releases/tag/5.1.0)
- [BloodHound.py commit `fd3f322e066d66314bfb31d4ae6f497df5872177`](https://github.com/dirkjanm/BloodHound.py/commit/fd3f322e066d66314bfb31d4ae6f497df5872177)
- [Responder commit `424fbe53d6a61824e3c7685fe5f69668721b821e`](https://github.com/lgandx/Responder/commit/424fbe53d6a61824e3c7685fe5f69668721b821e)

OpenLDAP client and operating-system packages are pinned through the package
snapshot and image digest recorded in the same lockfile. A lock update invalidates
the affected action receipts and requires their E2E tests again.

## Typed adapters

The broker registry maps each action ID to one adapter class. Every adapter
implements the same lifecycle:

```text
validate_input
resolve_secrets
build_invocation
declare_network_policy
parse_result
sanitize_evidence
cleanup_target
```

Input models reject unknown fields. Enumerations, strings, collections, target
counts, and byte sizes have explicit limits. `build_invocation` returns an
immutable argv projection and mount plan assembled solely by adapter code. No
adapter invokes a shell or interpreter inline.

Adapters may parse tool output, but sensitive actions cannot emit free-text
evidence. Parsers return typed values from an allowlist and delete their raw
input immediately. Parser failure returns `evidence` failure, never successful
impact.

## Network containment

The control plane normalizes target hostnames and endpoints against the confirmed
snapshot. The permit includes the complete allowed IP, port, and protocol set,
including explicit auxiliary DC/DNS endpoints where required.

Immediately before execution, the broker resolves names again. Every returned
address must match the permitted resolved set and remain in scope. Mixed-scope
answers, new answers, missing addresses, redirects, proxy configuration, and
discovery of undeclared peers are rejected.

The broker creates an ephemeral network namespace and installs default-deny
`nftables` rules before attaching the tool container. Only permit rules are
allowed. A separate namespace/Docker network is used per concurrent run.

Responder uses a dedicated interface bound to the explicit authorized CIDR. In
the lab this is an internal Docker network with no default route. In production
the operator must configure a dedicated test interface; the SSH management
interface is rejected. The subnet is parsed as a first-class target type and
must be wholly contained by the confirmed scope.

## Secrets and evidence

Secrets are stored by reference in the engagement namespace and resolved only
after permit verification. They are delivered as read-only files in tmpfs,
stdin, or a Kerberos cache. The broker does not place secret values in OCI
environment variables, command arguments, Docker labels, logs, permits, or
receipts. Files are unlinked during independent resource cleanup.

`L3ExecutionResult` is a closed schema with:

- run binding and action definition digest;
- lifecycle and reason code;
- start/end timestamps and duration;
- normalized target and image digest;
- typed action-specific result object;
- resource and target cleanup status;
- rate-budget state;
- response-chain and evidence digests.

Credential-sensitive result objects permit only counts, booleans, bounded masked
identifiers, protocol/encryption enums, timestamps, and correlation digests.
Before serialization, a final detector rejects values resembling passwords,
NTLM/Kerberos material, private keys, bearer tokens, or raw credential lines.

## Failure model

Failures are classified as `authorization`, `containment`, `runtime`, `parsing`,
`cleanup`, or `evidence`. All failures are secret-free and path-free.

- Authorization or containment failure creates no tool container.
- Runtime timeout terminates the whole container/cgroup and proceeds to cleanup.
- Parsing or evidence failure never reports a successful proof.
- Resource cleanup and target cleanup run independently.
- Target cleanup failure on a state-changing action is critical and blocks new
  mutable actions for the same engagement and target until operator resolution.
- Broker crash recovery reconciles the durable run ledger with labeled OCI and
  network resources before accepting new work.

## Disposable lab

The lab runs on the authorized Linux host through an explicit SSH command. It is
composed of disposable OCI resources and synthetic credentials:

- Samba AD DC for realm `LAB.HACKBOT.INVALID`;
- LDAP objects for policy, SPN, ADCS, LAPS, and gMSA scenarios;
- SMB member and bounded account/candidate sets;
- authentication client for Responder analyze and capture flows;
- SSH source and destination containers for lateral verification;
- code-owned vulnerable proof service;
- payload and persistence proof target;
- isolated DNS where required.

Every lab network is marked internal and has no route to the LAN or Internet.
The harness first proves this negative property, then runs one action at a time.
It tears down containers, volumes, namespaces, and rules even after failure.

If a protocol cannot be represented faithfully in this lab, its action remains
non-executable. In particular, the ADCS action must demonstrate the real Certipy
adapter against protocol-faithful directory objects; a mocked Certipy result does
not satisfy promotion.

## Verification strategy

### Local CI-safe verification

- Unit tests for every input and result schema.
- Golden tests for every complete catalog definition.
- Property and mutation tests for permit bindings and canonicalization.
- Negative tests for stale/replayed permits, authority/profile mismatch, digest
  drift, unknown fields, arbitrary argv, and unscoped targets.
- Parser fixtures containing representative tool output and secret canaries.
- Secret scans over logs, receipts, fixtures, and generated docs.
- OCI lockfile consistency, SBOM presence, and documentation drift checks.

Public CI executes no live credential, capture, exploit, payload, lateral, or
persistence action.

### Remote isolated E2E

Each of the 15 actions has an individually addressable E2E test proving:

1. permit acceptance and replay rejection;
2. digest-pinned image selection;
3. containment of expected and forbidden traffic;
4. real adapter/tool interaction with the disposable target;
5. expected closed evidence and absence of secret material;
6. resource and target cleanup.

Promotion receipts are generated only after success and contain no credentials
or raw output. The complete remote run also exercises concurrent rate limits,
broker restart/replay behavior, timeout cleanup, and recovery after an injected
cleanup failure.

## Delivery and repository updates

Implementation is split into four reviewable milestones within P5b:

1. snapshot-bound permit and exact catalog contracts;
2. Linux broker, OCI lock, network containment, rate state, and evidence schemas;
3. tool adapters plus disposable lab, promoted one action at a time;
4. full verification, operator docs, security docs, GitHub issue/project update,
   and pull request.

The branch remains in progress and the pull request remains draft until all
required local checks and remote E2E tests pass. GitHub Issue #10 and Project #2
move to completed only after independent review and required GitHub checks.

## Acceptance criteria

- No L3 execution path accepts shell text, arbitrary argv, scripts, payloads, or
  unreviewed modules.
- A catalog/snapshot/profile mismatch denies before resource creation.
- Every image and adapter is selected by immutable digest.
- Network tests demonstrate default-deny behavior and no lab route to the LAN.
- Rate limits survive container restart and prevent unsafe spray budgets.
- Raw credential material is absent from all persisted artifacts.
- Each executable action has a matching successful isolated E2E receipt.
- All repository tests, lint, format, type checks, OpenSpec validation, fixture
  drift checks, publication guards, and secret scans pass.
- Documentation and GitHub tracking reflect the delivered implementation.
