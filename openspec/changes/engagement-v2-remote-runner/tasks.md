## 1. Pinned SSH transport and request binding

- [x] 1.1 Add failing tests for the SSH argv construction: pinned known_hosts, `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`, `BatchMode=yes`, forwarding/TTY disabled, and only the fixed helper path — no action/target/parameter/secret token appears in the argv.
- [ ] 1.2 Add failing tests for request binding: canonical UUIDv4 run ID, 32-byte base64url nonce, UTC issue time, 1–300s expiry, and execution digest over the execution projection; over-cap requests rejected before send (`EXEC_PROTOCOL_INVALID`); out-of-window expiry rejected (`EXEC_PROTOCOL_EXPIRED`).
- [ ] 1.3 Implement `engagement_v2.remote_transport` (SSH argv builder + P0-protocol request builder/sender over an injected stream) until 1.1–1.2 pass.

## 2. Response verification and equivalent semantics

- [ ] 2.1 Add failing loopback tests: a valid response echoing run ID/nonce/authority-digest/execution-digest with an ordered hash-chain verifies; a broken chain, wrong echo, or bad ordering fails closed (`EXEC_PROTOCOL_INVALID`).
- [ ] 2.2 Add failing tests proving a verified remote run reuses the P3 gate, secret handling, evidence redaction, lifecycle, and independent fail-closed cleanup (equivalent `ExecutionResult` semantics), including crash reconciliation of a partial run.
- [ ] 2.3 Implement the response verifier and the remote run driver reusing the P3 executor semantics until 2.1–2.2 pass.

## 3. Helper identity and executable digest

- [x] 3.1 Add failing tests: a helper self-report never satisfies identity; wrong protocol version rejected; an exact-digest action verifies the remote executable as a regular file before spawn and binds `argv[0]` to it; digest mismatch fails closed (`EXEC_TRUST_MISMATCH`).
- [x] 3.2 Implement `engagement_v2.remote_helper` identity/executable verification and the fixed `hackbot-remote-runner` helper skeleton until 3.1 passes.

## 4. Replay reservation and privilege permit

- [x] 4.1 Add failing tests: the helper atomically reserves `(authority_digest, run_id, nonce)` and rejects duplicate/expired runs for the P0 window (`EXEC_PROTOCOL_REPLAY`/`EXEC_PROTOCOL_EXPIRED`).
- [x] 4.2 Add failing Ed25519 permit tests (RFC 8032 vectors): valid permit accepted; wrong key, tampered message, and malleable signature rejected; permit bound to engagement/authority/action/runner/executable/privilege/nonce/expiry; privilege set must match exactly; static privileges are upper bounds and an out-of-set privilege denies (`EXEC_PRIVILEGE_MISMATCH`).
- [x] 4.3 Implement the replay reservation and the pure-Python Ed25519 permit verifier + preflight until 4.1–4.2 pass.

## 5. Egress attestation

- [x] 5.1 Add failing tests: `direct-interface` local address asserts no public egress; an `attested-egress` claim without a pinned adapter fails closed; a stale or mis-signed attestation fails closed; a signed, fresh attestation within the P0 age is accepted.
- [x] 5.2 Implement `engagement_v2.egress` attestation verification until 5.1 passes.

## 6. Isolation, CLI, fixtures, and documentation

- [x] 6.1 Extend the v2-consumer allowlist guard to the declared P4 modules and add a guard test proving the v1 command-string runner and default v1 CLI path never import the v2 remote modules.
- [ ] 6.2 Wire the explicitly-v2 remote CLI entry, add the loopback protocol harness and a harmless fixture helper, and add deterministic permit/protocol fixtures (no real host/target/credential material) with a regenerate/check tool.
- [x] 6.3 Document the P4 public transport/helper/permit/egress interfaces, the trust root, and that remote self-reports are never independent proof.

## 7. Verification and delivery

- [x] 7.1 Run focused P4 tests, the full pytest suite, Ruff check/format, mypy, schema/fixture drift, OpenSpec strict validation, the secret-scan regex over new paths, and `git diff --check`; record fresh outputs.
- [ ] 7.2 Request independent review, resolve findings, update Issue #4/Project fields, and archive the OpenSpec change only after implementation, verification, and merge.
