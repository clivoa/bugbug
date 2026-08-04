## 1. Baseline and exact catalog contracts

- [ ] 1.1 Add failing golden tests for the complete definitions and exact ordered set of 15 L3 action IDs, including inputs, targets, capabilities, characteristics, adapter/image identity, rate, closed ordered endpoint-binding schemas (roles, allowed schemes/protocols, and cardinality), evidence, cleanup, and provenance.
- [ ] 1.2 Add failing negative tests for excluded capabilities, nonexistent local provenance, shell/interpreter/raw-argv fields, arbitrary modules/scripts/payloads/commands, and incomplete definition validation.
- [ ] 1.3 Add failing tests that catalog activation, P3 evaluation, input binding, and permit issuance require the same snapshot identity, profile, and authority digest.
- [ ] 1.4 Replace the prototype catalog/loader/provenance implementation until 1.1-1.3 pass, including the exact corrected capability sets and disabled-by-default behavior.
- [ ] 1.5 Add a v1 isolation regression proving the executable P5b catalog and its rollback do not alter schema v1 bytes or behavior.

## 2. Snapshot-bound ExecutionPermitV2

- [ ] 2.1 Add failing tests for the exact canonical `ExecutionPermitV2` field set, domain separation, Ed25519 signer pinning, 1-300 second lifetime, and every snapshot/action/runner/image/input/network/rate/evidence/privilege binding.
- [ ] 2.2 Implement permit issuance on the control plane and extend verification on the Linux side until 2.1 passes without introducing another trust path.
- [ ] 2.3 Add failing protocol tests proving invalid, expired, unknown-field, mismatched, and tampered permits deny before any resource factory is called.
- [ ] 2.4 Integrate the permit with the existing P4 framed request/response chain and fixed SSH transport until 2.3 passes.
- [ ] 2.5 Add deployment-contract tests for a root-owned digest-pinned broker path and a dedicated forced-command SSH identity with shell, TTY, forwarding, agent, and X11 disabled.

## 3. Durable replay, rate, and mutable-target state

- [ ] 3.1 Add failing SQLite ledger tests for atomic replay reservation, concurrent duplicate rejection, retention, restart persistence, bounded pruning, file permissions, and corruption failure.
- [ ] 3.2 Implement the durable replay ledger and reserve `(authority_digest, run_id, nonce)` before resource creation until 3.1 passes.
- [ ] 3.3 Add failing rate-ledger tests for one-candidate/1-25-account spray bounds, concurrency one, 30-second minimum spacing, stale/missing lockout denial, cumulative `threshold - 1` budget, and restart persistence.
- [ ] 3.4 Implement durable rate reservations/commit/abort and `DENY_RATE_UNENFORCEABLE` behavior until 3.3 passes.
- [ ] 3.5 Add failing tests for durable mutable-target blocks after cleanup failure and explicit operator resolution.
- [ ] 3.6 Implement mutable-target block/recovery state until 3.5 passes.

## 4. Immutable OCI supply chain and promotion

- [ ] 4.1 Add failing strict-schema tests for the OCI lockfile: adapter, upstream release/commit, source, base image, package snapshot, built image, `linux/amd64`, and SBOM digests with no tags as runtime identity.
- [ ] 4.2 Add reproducible Docker build inputs pinned to the approved OpenLDAP, NetExec, Impacket, Certipy, BloodHound.py, Responder, broker, and controlled-proof sources.
- [ ] 4.3 Build the images on the authorized Linux host, generate SBOMs, record immutable digests in the lockfile, and pass its regenerate/check test.
- [ ] 4.4 Add failing tests for promotion-receipt schema, signature/integrity, action-definition/adapter/image/scenario binding, and automatic invalidation on drift.
- [ ] 4.5 Implement receipt generation/validation and expose only receipt-backed actions as executable until 4.4 passes.
- [ ] 4.6 Add publication guards proving a tag-only image, host-installed tool, missing SBOM, missing receipt, or digest drift returns `EXEC_TRUST_MISMATCH` before container creation.

## 5. Linux broker and typed adapter framework

- [ ] 5.1 Add failing interface tests for strict adapter input models, unknown-field rejection, immutable invocation/mount/network plans, closed result parsing, and independent target cleanup.
- [ ] 5.2 Implement the focused adapter protocol and exact registry without shell/interpreter/raw argv or arbitrary execution inputs until 5.1 passes.
- [ ] 5.3 Add failing broker lifecycle tests for authorization, containment, runtime, parsing, evidence, resource cleanup, target cleanup, and finalized states with secret-free stable reasons.
- [ ] 5.4 Implement the stdin/stdout `hackbot-l3-runner` orchestration, bounded OCI invocation, response chain, audit projection, and no-listening-service behavior until 5.3 passes.
- [ ] 5.5 Add failing crash-recovery tests for unfinished ledger entries and labeled containers, namespaces, nftables rules, tmpfs mounts, and cleanup receipts.
- [ ] 5.6 Implement startup reconciliation and refuse new work until recovery completes.
- [ ] 5.7 Add and verify idempotent remote install/uninstall scripts for the root-owned broker, dedicated user/key forced command, state directories, nftables prerequisites, and rollback.

## 6. Target normalization and network containment

- [ ] 6.1 Add failing scope tests for first-class CIDR targets, exact endpoint/auxiliary bindings with full URI and explicit port values, missing/default-port denial, deny-wins subnet containment, and SSH management-interface rejection.
- [ ] 6.2 Extend target normalization/scope parsing until 6.1 passes without changing v1 behavior.
- [ ] 6.3 Add failing DNS tests for explicit resolver binding, absent-resolver denial, no system-resolver fallback, permit-time resolution, pre-run re-resolution, mixed-scope answers, changed/missing addresses, redirects, proxies, and undeclared discovery.
- [ ] 6.4 Implement exact resolved-endpoint binding using the same explicit resolver and exact answer-set equality, with fail-closed DNS revalidation, until 6.3 passes.
- [ ] 6.5 Add failing namespace-plan tests for default-deny nftables, exact IP/port/protocol rules, read-only rootfs, private tmpfs, dropped capabilities, resource bounds, and Responder-only privilege exceptions.
- [ ] 6.6 Implement ephemeral namespace/container containment and cleanup until 6.5 passes.
- [ ] 6.7 Run negative remote escape tests against undeclared IPs, ports, protocols, the LAN gateway, SSH management address, and Internet; retain only sanitized containment receipts.

## 7. Secrets, evidence, and cleanup

- [ ] 7.1 Add failing P3 regression tests proving closed `structured` evidence is allowed for sensitive actions while `redacted-output` remains denied with `EVIDENCE_POLICY_DENIED`.
- [ ] 7.2 Correct evidence-mode enforcement to match the archived contract until 7.1 passes.
- [ ] 7.3 Add failing secret-delivery tests for post-authorization resolution, engagement namespace binding, read-only tmpfs/stdin/Kerberos-cache transport, byte caps, independent destruction, and absence from argv/env/labels/logs/audit/errors.
- [ ] 7.4 Implement broker-side ephemeral secret delivery and destruction until 7.3 passes.
- [ ] 7.5 Add failing strict-schema tests for every action result and the common run/image/rate/cleanup/response/evidence envelope.
- [ ] 7.6 Implement closed result validators and action parsers that never serialize raw sensitive output.
- [ ] 7.7 Add failing secret-canary tests for passwords, credential lines, NTLM/Kerberos material, private keys, tokens, managed-password blobs, and unknown/free-text result fields.
- [ ] 7.8 Implement the final secret detector and fail the evidence phase without demonstrated impact when a canary is present.
- [ ] 7.9 Add and pass timeout, resource-cleanup, target-cleanup, and cleanup-failure block tests for every state-changing adapter.

## 8. Authenticated directory adapters

- [ ] 8.1 Add failing invocation/parser/secret/network/evidence tests for `operator.internal.directory.policies` against one explicit DC/base DN.
- [ ] 8.2 Implement the OpenLDAP policies adapter and pass its focused unit/integration tests.
- [ ] 8.3 Add failing invocation/parser/secret/network/evidence tests for `operator.internal.directory.spns` with no automatic host follow-up.
- [ ] 8.4 Implement the OpenLDAP SPN adapter and pass its focused unit/integration tests.
- [ ] 8.5 Add failing invocation/parser/secret/network/evidence tests for Certipy `operator.internal.directory.adcs` using explicit DC/domain and ephemeral Kerberos material.
- [ ] 8.6 Implement the Certipy ADCS adapter and pass its focused unit/integration tests.
- [ ] 8.7 Add failing invocation/parser/secret/network/evidence tests for BloodHound.py `operator.internal.directory.graph` using only the code-owned `DCOnly` collection set.
- [ ] 8.8 Implement the BloodHound graph adapter, parse closed counts/digest, discard graph archives, and pass its focused tests.

## 9. Credential-material adapters

- [ ] 9.1 Add failing bounded-principal/invocation/parser/network/evidence tests for Impacket `operator.internal.credential.asrep`.
- [ ] 9.2 Implement the AS-REP adapter, discard raw material after parsing, and pass its focused tests.
- [ ] 9.3 Add failing bounded-principal/SPN/invocation/parser/network/evidence tests for Impacket `operator.internal.credential.kerberoast`.
- [ ] 9.4 Implement the Kerberoast adapter, discard tickets/hashes after parsing, and pass its focused tests.
- [ ] 9.5 Add failing bounded-computer/invocation/parser/network/evidence tests for NetExec `operator.internal.credential.laps`.
- [ ] 9.6 Implement the LAPS adapter returning only presence/schema/rotation metadata and pass its focused tests.
- [ ] 9.7 Add failing bounded-account/invocation/parser/network/evidence tests for NetExec `operator.internal.credential.gmsa`.
- [ ] 9.8 Implement the gMSA adapter returning only presence/count/rotation metadata and pass its focused tests.

## 10. Password validation and Responder adapters

- [ ] 10.1 Add failing end-to-end adapter tests connecting the durable rate ledger, ephemeral candidate/account files, one scoped SMB host, closed success counts, and lockout-safe stop behavior for password spray.
- [ ] 10.2 Implement `operator.internal.validation.password-spray` with the exact capability set and pass unit/rate/integration tests.
- [ ] 10.3 Add failing packet-mode tests proving `operator.internal.responder.analyze` observes for at most 120 seconds without poisoning/capture and returns counters only.
- [ ] 10.4 Implement the Responder analyze adapter with a dedicated authorized interface and minimum privileges.
- [ ] 10.5 Add failing packet-mode tests proving `operator.internal.responder.capture` is separate, state-changing, non-passive, bounded to 120 seconds, returns only sanitized capture metadata, and destroys collected material.
- [ ] 10.6 Implement the Responder capture adapter with dedicated interface/CIDR containment and minimum privileges.

## 11. Controlled proof adapters

- [ ] 11.1 Add failing closed-profile/fingerprint/proof-token/no-session tests for `operator.internal.exploit.verify`, including denial of `lab-proof-v1` outside `local-lab`.
- [ ] 11.2 Implement the code-owned `lab-proof-v1` exploit adapter and disposable vulnerable service without generic module or payload input.
- [ ] 11.3 Add failing create/read/delete marker and cleanup-failure tests for `operator.internal.payload.verify`.
- [ ] 11.4 Implement the benign payload-proof adapter with no operator/model command or marker-path input.
- [ ] 11.5 Add failing exact-host-key/batch-auth/fixed-`/usr/bin/true`/no-forwarding tests for `operator.internal.lateral.verify`.
- [ ] 11.6 Implement the lateral SSH proof adapter and closed authentication result.
- [ ] 11.7 Add failing inert user-level install/verify/remove receipt and durable cleanup-block tests for `operator.internal.persistence.verify`.
- [ ] 11.8 Implement the persistence proof adapter with no selectable mechanism or surviving marker.

## 12. Disposable lab and per-action E2E promotion

- [ ] 12.1 Add a deterministic remote lab harness with explicit create/test/destroy commands, synthetic secrets, unique resource labels, traps, and no dependency on the SSH management network as a target.
- [ ] 12.2 Provision internal Docker networks, isolated DNS, Samba AD realm `LAB.HACKBOT.INVALID`, policy/SPN/ADCS/LAPS/gMSA objects, SMB member, bounded accounts, and protocol-faithful directory scenarios.
- [ ] 12.3 Provision the Responder client/network, SSH source/destination, vulnerable proof service, and payload/persistence proof target.
- [ ] 12.4 Add and pass lab preflight tests proving no route to LAN/Internet, exact Docker/image/broker compatibility, synthetic-only credentials, and complete teardown after injected setup failure.
- [ ] 12.5 Add individually addressable E2E tests for all 15 action IDs, each proving permit/replay, image pin, allowed/blocked traffic, real tool/target interaction, closed evidence, secret absence, and cleanup.
- [ ] 12.6 Run every E2E on the authorized Linux host; generate a promotion receipt only for each action whose protocol-faithful test passes and leave any unproved action unavailable.
- [ ] 12.7 Run remote fault injection for broker restart, concurrent replay, rate persistence, timeout, parser failure, evidence canary, resource cleanup failure, target cleanup failure, and recovery blocking.
- [ ] 12.8 Run lab teardown and verify no Hackbot container, volume, namespace, nftables rule, tmpfs mount, marker, captured material, or synthetic secret remains.

## 13. Documentation, verification, review, and GitHub delivery

- [ ] 13.1 Update architecture, catalog, tool execution, remote runner, risk/approval, evidence, security, operator runbook, lab, image supply chain, recovery, README, CLAUDE, SECURITY, and next-steps documentation with executable behavior and limitations.
- [ ] 13.2 Add generated action/image/receipt matrices and publication guards so docs fail on catalog, lockfile, receipt, reason-code, command, or verification-count drift.
- [ ] 13.3 Run focused P5b tests, complete pytest, Ruff check/format, mypy, fixture/lock/doc drift, OCI/SBOM/receipt checks, OpenSpec strict validation, publication guards, secret scans, and `git diff --check`; record fresh local outputs.
- [ ] 13.4 Record sanitized remote host inventory, 15-action E2E results, containment/fault-injection results, image/SBOM digests, cleanup proof, and unavailable-action reasons in the verification report.
- [ ] 13.5 Request independent specification/compliance/security/code review, resolve every actionable finding, and rerun affected local and remote verification.
- [ ] 13.6 Commit intentional milestone changes, push the feature branch, open/update a draft PR, and confirm required GitHub checks.
- [ ] 13.7 Update Issue #10 and Project #2 fields through delivery; mark completed and archive the OpenSpec change only after implementation, E2E, review, merge, and checks succeed.
