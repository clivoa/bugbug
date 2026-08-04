## Context

P0-P4 already provide strict engagement loading, scope and capability decisions,
canonical framing, Ed25519 privilege-permit verification, fixed SSH transport,
executable digest checks, and in-process replay protection. P5a supplies a
non-credential catalog. The first P5b implementation added 15 inert L3 manifest
entries and synthetic fixtures but independent review found that it could load a
catalog for one profile and decide against another snapshot, advertised adapters
that did not exist, did not bind all tools to actual destinations, and did not
mechanically enforce rate, evidence, or E2E promotion.

P5b now includes the complete executable boundary defined by
`docs/superpowers/specs/2026-08-01-engagement-v2-p5b-executable-layer-design.md`.
The exact normative fields, action semantics, upstream pins, lifecycle, and
acceptance criteria in that document are part of this design.

The macOS workstation is the control plane. L3 tools execute on a Linux runner.
The authorized test host may be reached through SSH, but its management address
is not a test target. Public CI remains incapable of live offensive execution.

## Goals / Non-Goals

**Goals:**

- Deliver 15 exact L3 actions through real, typed, code-owned adapters.
- Bind catalog activation, P3 decision, request, snapshot, runner, image,
  containment, rate, evidence, and cleanup to one signed permit.
- Fail closed on profile, authority, target, DNS, adapter, helper, image, version,
  or receipt drift before creating an execution resource.
- Keep reusable credential material out of persistent artifacts.
- Promote each action only after a faithful E2E test in a disposable lab.
- Allow explicitly authorized local-network testing from the Linux runner while
  keeping the lab isolated from that network.

**Non-Goals:**

- Generic commands, arbitrary argv, shell text, scripts, payload bytes, or
  unreviewed modules supplied by an operator or model.
- DoS, destruction, exfiltration, evasion, persistent changes surviving the run,
  or automatic action chaining.
- Treating a profile name, catalog presence, exit code, or target self-report as
  authorization or proof.
- Live offensive execution in public CI or on macOS.

## Decisions

### 1. Extend the existing P0/P3/P4 trust path

P5b extends the current Ed25519 permit and framed P4 transport instead of adding
a parallel executor. The control plane loads one immutable
`EngagementSnapshot`, evaluates the exact action through P3, binds typed inputs,
and issues `ExecutionPermitV2`. The same `profile`, `authority_digest`, and
snapshot identity must be present at catalog load, policy decision, permit
issuance, and broker verification.

The permit uses the exact closed field set in the approved design and has a
maximum lifetime of 300 seconds. The broker verifies signature, timestamps,
action definition digest, runner/helper identity, image digest, input digest,
resolved endpoints, network/rate/evidence claims, privileges, and replay tuple
before resource creation.

Alternative: trust the existing ALLOW object at the runner. Rejected because it
does not cryptographically bind the catalog definition or execution environment.

### 2. Make replay and rate state durable

The broker reserves `(authority_digest, run_id, nonce)` atomically in SQLite
before creating a namespace or container. The reservation survives process
restart for at least the existing replay window.

Rate budgets use the same durable store and are keyed by authority, action,
target, and account-set digest. Password spray runs with concurrency one,
mandatory inter-attempt delay, a bounded candidate set, and a budget below the
confirmed directory lockout threshold. Missing or stale lockout policy denies.

Alternative: keep replay and rate state in memory. Rejected because restarting a
broker or container would bypass both controls.

### 3. Use one root-owned broker with typed adapters

`hackbot-l3-runner` is a root-owned, digest-pinned, stdin/stdout broker installed
at a fixed path. Production deployment uses a dedicated SSH identity with a
forced command and no interactive shell, forwarding, agent, X11, or TTY. The
broker exposes no listening socket.

One adapter class per action owns input validation, secret requirements,
invocation rendering, image identity, network rules, result parsing, evidence
sanitization, and target cleanup. Inputs reject unknown fields and all
collections, strings, counts, timeouts, and byte sizes are explicitly bounded by
the approved action definitions. No adapter invokes a shell or accepts raw argv.

Alternative: one daemon per upstream tool. Rejected because it duplicates
authorization and cleanup policy. Alternative: render Docker commands directly
from the manifest. Rejected because a declarative argv cannot safely enforce
network, rate, evidence, or state recovery.

### 4. Validate complete definitions and promote by receipt

The catalog contains exact code-owned definitions for the 15 reviewed IDs.
Validation compares the complete definition: inputs, targets, capabilities,
characteristics, adapter/image identity, rate, network, evidence, cleanup, and
provenance. Fictional executable paths or partially validated manifests are
invalid.

Every action moves through:

```text
implemented -> isolated-e2e-passed -> executable
```

A committed promotion receipt binds action-definition, adapter, image, and lab
scenario digests. Drift resets the action to `implemented`. The loader returns
only executable actions and also requires an authorized internal profile,
explicit confirmation, exact snapshot binding, all capability booleans, and a
compatible runner.

Alternative: load all implemented definitions and document missing tools.
Rejected because source presence would appear to enable unproved behavior.

### 5. Pin the complete OCI supply chain

Tool execution uses only `repository@sha256:...`. A generated lockfile records
the upstream release/commit, source digest, base-image digest, package snapshot,
built image digest, platform, and SBOM digest. Tags are metadata only. A lock
update invalidates E2E receipts for affected actions.

Initial pins are NetExec v1.5.1, Impacket 0.13.1, Certipy 5.1.0,
BloodHound.py commit `fd3f322e066d66314bfb31d4ae6f497df5872177`, and
Responder commit `424fbe53d6a61824e3c7685fe5f69668721b821e`. OpenLDAP
and OS packages are pinned through the image/package snapshot and final digest.

Alternative: use host-installed tools or tags. Rejected because tool behavior
could change without a catalog or receipt change.

### 6. Keep the 15 action semantics closed

The catalog contains four authenticated directory actions, four
credential-material actions, password spray, separate Responder analyze/capture,
and four controlled proofs. Detailed behavior and closed results are normative in
the approved design.

- LDAP policies/SPNs contact one explicit DC/base DN.
- Certipy `find` and BloodHound.py `DCOnly` contact explicit directory endpoints.
- Impacket AS-REP/Kerberoast use bounded principal sets and discard ticket/hash
  material after parsing.
- NetExec LAPS/gMSA returns presence and rotation metadata, never values.
- Spray has durable rate/lockout enforcement and declares `multiple-accounts`.
- Responder analyze cannot poison; capture is separate L3 state-changing
  credential capture on a dedicated authorized interface.
- Exploit uses only a reviewed closed profile and returns a one-time proof token.
- Payload creates, verifies, and removes a benign marker.
- Lateral movement uses batch SSH and only `/usr/bin/true`.
- Persistence installs, verifies, and removes one inert user-level marker.

The initial exploit profile is lab-only. A future production exploit profile
requires separate reviewed code and a matching E2E receipt; the operator or
model cannot select an arbitrary module.

### 7. Apply default-deny network containment

The control plane resolves and normalizes targets against the confirmed scope and
places exact IP/port/protocol rules in the permit. The broker resolves names again
immediately before execution. Every answer must equal the permitted set and
remain in scope; mixed, new, redirected, proxied, or discovered endpoints deny.

Before attaching a container, the broker creates an ephemeral namespace and
installs default-deny nftables rules. The tool image cannot modify its own policy.
Containers use a read-only root filesystem, private tmpfs, resource bounds, and
dropped capabilities. Responder alone receives its mode's minimum network
capabilities and a dedicated interface. Its CIDR is a first-class target wholly
contained by scope, and the SSH management interface is rejected.

The lab uses Docker internal networks without a LAN/Internet route. Production
uses a dedicated test interface or namespace that can reach only permit rules.

Alternative: rely on scope validation before spawn. Rejected because tools may
discover or follow undeclared endpoints after validation.

### 8. Resolve secrets after authorization and retain closed evidence

The runner resolves engagement-scoped secret references only after permit and
containment validation. It delivers secrets through read-only tmpfs files,
stdin, or an ephemeral Kerberos cache. Secret values never enter permits,
environment variables, argv, labels, audit, logs, errors, receipts, or reports.

Sensitive adapters parse raw output in memory and return only their closed
action-specific result. P3's archived evidence requirement already permits
closed `structured` results while denying `redacted-output` for credential and
sensitive-data capabilities; implementation is corrected to match that
requirement. A final detector rejects password, NTLM/Kerberos, private-key,
bearer-token, and credential-line patterns before serialization.

Exit code alone never proves impact. Results include the run/action/image
binding, lifecycle/reason, timing, normalized target, typed result, durable rate
state, cleanup status, and response/evidence digests.

### 9. Treat cleanup and recovery as security controls

Failures are classified as authorization, containment, runtime, parsing,
cleanup, or evidence. Authorization/containment failures spawn nothing. Timeout
terminates the complete container/cgroup. Resource and target cleanup run
independently.

A target-cleanup failure for a mutable action is critical. The durable ledger
blocks further mutable actions for that engagement/target until an operator
resolves it. On broker start, recovery reconciles unfinished ledger records with
labeled containers, namespaces, nftables rules, tmpfs mounts, and target cleanup
receipts before accepting work.

### 10. Require faithful per-action remote E2E

The remote lab contains a synthetic Samba AD domain, directory objects for the
reviewed LDAP scenarios, SMB member, Responder client, SSH source/destination,
isolated DNS, vulnerable proof service, and payload/persistence proof target.
Every network is internal and the harness proves lack of LAN/Internet routing
before executing an action.

Each action test proves permit/replay, pinned image, expected traffic, blocked
traffic, real adapter/tool interaction, closed evidence, secret absence, and
cleanup. Protocol mocks may test parsers but cannot create a promotion receipt.
If Certipy or another tool cannot be exercised faithfully, that action remains
implemented and unavailable.

Public CI runs unit, golden, property, negative, parser-fixture, secret-scan,
lockfile/SBOM, receipt, documentation-drift, and publication-guard tests only.

## Risks / Trade-offs

- **The scope is substantially larger than the original catalog-only P5b** ->
  deliver four reviewable milestones: authority; broker; adapters/lab; final
  verification and delivery.
- **Docker and nftables require privilege** -> install one root-owned fixed broker
  behind a forced SSH command; never expose the Docker socket or generic sudo
  through the Hackbot protocol.
- **ADCS/LAPS/gMSA behavior may not be faithful in Samba** -> require the real
  tool and protocol-faithful objects; leave the action unavailable rather than
  promote from a mock.
- **Responder requires L2 behavior and extra capabilities** -> use a dedicated
  interface/network, distinct analyze/capture adapters, minimum capabilities,
  and explicit containment escape tests.
- **Upstream CLI changes can invalidate parsers** -> pin source and image digests;
  golden parser tests and E2E receipts are version-bound.
- **Raw secrets exist transiently inside tool memory/output** -> use synthetic or
  engagement-scoped secrets, in-memory parsing, tmpfs, immediate destruction,
  closed schemas, and a final secret detector.
- **Cleanup cannot undo a completed network interaction** -> report interaction
  separately from proof, make cleanup status explicit, and block subsequent
  mutable actions after target-cleanup failure.
- **A compromised Linux root can bypass broker controls** -> the Linux execution
  node is a trusted computing base; pin its identity/helper and document host
  hardening and recovery. P5b does not claim safety against compromised root.

## Migration Plan

1. Keep the current L3 prototype non-executable while adding exact golden tests
   and snapshot-bound catalog loading.
2. Extend permit/framing and deploy the root-owned broker with durable replay,
   rate, containment, evidence, cleanup, and recovery tests.
3. Build and lock OCI images, create the lab, implement adapters, and generate a
   receipt only after each action's E2E passes.
4. Publish the executable catalog, operator/security docs, and verification
   report only after the full local and remote suites pass.
5. Merge and archive P5b after independent review and required GitHub checks.

Rollback first disables all promotion receipts, which makes every L3 action
unavailable without changing v1 or P5a. The broker and lab can then be removed.
Durable ledgers and receipts contain no raw credentials; rollback preserves them
for audit unless the operator explicitly performs the documented cleanup.

## Open Questions

None blocking. An action whose lab cannot faithfully exercise the upstream tool
remains unavailable, which is a defined outcome rather than an unresolved design
choice.
