## Why

The v1 remote runner ships an SSH command string, which the umbrella design and
its threat-model review reject: it cannot pin identity, resist replay, verify the
executable, or keep egress claims honest. P0 froze the framed wire protocol and
runner trust projection, P1–P3 delivered the confirmed authority, bound argv,
and local executor. P4 replaces the SSH command string with a fixed, pinned,
replay-resistant remote helper that runs the same bound argv on an execution node
with equivalent semantics and no new trust the operator has not pinned.

## What Changes

- Replace the v1 SSH command-string runner with a **fixed exec-only helper
  transport**: a dedicated exec-only SSH identity, a pinned host key, disabled
  agent/X11/port forwarding and TTY, and an SSH argv that invokes only the fixed
  absolute `hackbot-remote-runner` helper path. No action executable, target,
  parameter, artifact, or secret is ever interpolated into a remote shell string.
- Speak the **P0 framed protocol** over that transport: build a canonical
  `hackbot-canonical-json-v1` request header bound to a unique UUIDv4 run ID, a
  32-byte base64url nonce, UTC issue time, and a 1–300 second expiry, plus the
  execution digest over the execution projection; send only request frame types
  (target-list/artifact/secret) within the P0 total/per-frame/count caps; and
  verify the response’s echoed run ID/nonce/authority-digest/execution-digest and
  its ordered, hash-chained frame descriptors. Malformed length, ordering,
  digest, expiry, or echo failures fail closed with the exact P0 `EXEC_*` reason.
- Enforce **replay resistance**: the helper atomically reserves
  `(authority_digest, run_id, nonce)` before creating any resource and rejects a
  duplicate or expired run for the P0 reservation window.
- Establish the **remote trust root**: the pinned SSH host key plus a
  pre-provisioned, pinned helper identity (SHA-256 digest or code-signing
  identity); a helper self-report never satisfies helper identity. For an
  exact-executable-digest action, the helper opens the remote executable as a
  regular file and verifies its digest before spawn (P0 review forward-carry N2:
  the remote consumer binds `argv[0]` to that verified executable).
- Verify **real privileges** against the confirmed authority: static runner OS,
  architecture, and permitted privileges are upper bounds; a trusted preflight
  compares the actual execution identity and held privileges. A privileged action
  requires a machine-signed **Ed25519 privilege permit** bound to engagement,
  authority digest, action, runner, executable digest, exact privilege set,
  nonce, issue time, and a ≤300-second expiry, verified against the runner
  projection’s pinned signer fingerprint.
- Keep **egress claims honest**: `direct-interface` and `attested-egress` are
  distinct claims. Observed egress requires a configured, pinned attestation
  adapter and a bounded observation age; a local interface address is not
  evidence of public egress, and any claim that cannot be mechanically verified
  fails closed. A target’s own state, privileges, egress, and cleanup remain
  unverified self-reports.
- Guarantee **equivalent semantics**: a remote run applies the same gate, bound
  argv, secret handling, evidence redaction, lifecycle, and independent
  fail-closed resource/target cleanup as the P3 local executor, plus crash
  reconciliation for a partially completed remote run.
- Preserve schema v1 behavior and the v1 command-string runner during the
  compatibility window; P4 adds the v2 remote path and does not change v1.

Non-goals:

- No internal-recon or L3 catalog actions (P5), autonomous workflows (P6), or
  effective migration (P7).
- No change to the P0 contracts, P1 loader/scope, P2 binder/policy, or P3 local
  executor; they are consumed as-is.
- No claim that a target self-report (state, privileges, egress, cleanup) is
  independently proven absent a separately pinned verifier.

## Capabilities

### New Capabilities

- `remote-runner-transport`: Fixed exec-only pinned-SSH transport speaking the P0
  framed protocol with request binding, replay reservation, and response
  hash-chain verification, and equivalent local/remote run semantics.
- `remote-helper-identity`: Pinned helper identity and remote executable-digest
  verification, where a helper self-report never satisfies identity.
- `privilege-permit`: Ed25519 machine-signed, short-lived, replay-bound privilege
  permits verified against the confirmed authority, with static privileges as
  upper bounds and a trusted preflight.
- `egress-attestation`: Distinct direct/observed egress claims with bounded,
  pinned attestation and fail-closed handling of unverifiable claims.

### Modified Capabilities

None. P4 consumes the archived P0 contracts and the P1–P3 capabilities without
changing their requirements, and does not alter the v1 capabilities.

## Impact

- New code under `src/hackbot/engagement_v2/` (remote transport, helper-identity,
  permit, egress modules) and a fixed `hackbot-remote-runner` helper, importing
  the P0 package and P1–P3 modules, the standard library, and an Ed25519 verifier
  (standard-library `hashlib`/`hmac` plus an approved minimal Ed25519
  implementation or an already-present optional dependency; no new heavy runtime
  dependency without a separate approved design).
- New CLI surface may reach the v2 remote path through a new, explicitly v2 entry
  point; the v2-consumer allowlist guard is extended to the declared P4 modules.
- New unit and property tests under `tests/engagement_v2/` using an in-process
  loopback framed-protocol harness and a harmless fixture helper; no real host,
  target, or credential material.

Architecture and review sources:

- `docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`
- `docs/reviews/2026-07-26-claude-remote-threat-model-disposition.md`
- `docs/reviews/2026-07-27-engagement-v2-p0-contracts-review-disposition.md`
  (forward-carry N2: the remote consumer binds `argv[0]` to the verified
  executable)
- `openspec/specs/remote-runner-protocol-contracts/spec.md`
- `openspec/specs/engagement-authority-contracts/spec.md`
- GitHub delivery: Issue #4.
