## Context

The v1 remote runner ships an SSH command string. The umbrella design and the
Claude remote threat-model review reject it: it cannot pin identity, resist
replay, verify the remote executable, or keep egress claims honest. P0 froze the
framed wire protocol (`b"HBV2RUN\x00"`, bounded frames, canonical request header,
replay tuple, response hash-chain) and the runner trust projection; P1–P3 gave
the confirmed authority, bound argv, and local executor. P4 is the remote
counterpart of P3, restricted to what the operator has pinned.

Trust boundary: the pinned SSH host key and the pinned helper identity are the
remote trust root. The remote host's self-reports about its own executable,
version, privileges, egress, and cleanup are untrusted unless a separately pinned
verifier proves them. P4 mechanically enforces the protocol, identity, permit,
and egress rules; it never assumes remote goodwill.

## Goals / Non-Goals

**Goals:**

- Speak the P0 framed protocol over a fixed exec-only pinned-SSH transport with
  request binding, replay reservation, and response hash-chain verification.
- Verify the pinned helper identity and, for exact-digest actions, the remote
  executable digest before spawn, binding `argv[0]` to it.
- Verify real privileges against the confirmed authority with static privileges
  as upper bounds and an Ed25519 machine-signed permit for privileged actions.
- Keep direct vs observed egress distinct and fail closed on unverifiable claims.
- Reuse the P3 gate, secret, evidence, lifecycle, and cleanup semantics so a
  remote run is equivalent to a local one, plus crash reconciliation.
- Keep the core dependency-free and leave the v1 command-string runner unchanged.

**Non-Goals:**

- No internal-recon/L3 catalog (P5), autonomous workflow (P6), or effective
  migration (P7).
- No change to P0–P3 or the v1 runner.
- No independent proof of a target's own state/privileges/egress/cleanup absent a
  separately pinned verifier.

## Decisions

### 1. Reuse the P0 protocol module; P4 owns transport and trust

Framing, the canonical request header, the replay tuple, and the response
hash-chain come from `hackbot.engagement_v2.protocol` (P0). P4 adds the SSH
transport (`ssh -T` to the fixed helper with pinned `known_hosts`,
`StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`, `BatchMode=yes`, all
forwarding and TTY disabled), the request builder/binder, and the response
verifier. No action content is ever placed in the SSH argv or a remote shell.

### 2. The helper is fixed and pinned; its self-report proves nothing

The remote side is a fixed `hackbot-remote-runner` helper at a pinned absolute
path with a pinned SHA-256 or code-signing identity and a pinned protocol
version. The client verifies identity from the confirmed runner projection, not
from anything the helper says. For an exact-digest action, the helper opens the
remote executable as a regular file and verifies its digest before spawn and
binds `argv[0]` to it (P0 review forward-carry N2).

### 3. Ed25519 permit verification is verification-only and stdlib-based

Hackbot never signs; it only verifies an externally issued permit. Ed25519
verification is implemented in pure Python over `hashlib.sha512`, so the core
stays dependency-free and no signing key ever exists in the process. The permit
binds engagement ID, authority digest, action, runner, executable digest, exact
privilege set, nonce, issue time, and a ≤300-second expiry, and is checked
against the pinned signer fingerprint and the request replay tuple.

Alternative considered: an optional `cryptography`/`pynacl` dependency. Deferred
— it would need a separate approved design; a small audited pure-Python verifier
avoids a new runtime dependency for a verify-only path.

### 4. Egress claims are typed and fail closed

`direct-interface` and `attested-egress` are distinct. A direct-interface local
address asserts nothing about public egress. An observed claim must come from the
pinned adapter (SHA-256 + signer fingerprint) with a bounded observation age;
anything unverifiable fails closed.

### 5. Remote run equals local run

The remote path reuses the P3 gate, secret resolution/delivery, evidence
redaction, lifecycle, and independent fail-closed resource/target cleanup, so the
`ExecutionResult` semantics match. A partially completed remote run is
reconciled: an unconfirmed remote resource cleanup is `cleanup_incomplete` with a
protected local record, exactly as locally.

### 6. Controlled v2 remote entry point

A new, explicitly v2 CLI entry reaches the remote path; the v2-consumer allowlist
guard is extended to the declared P4 modules. The v1 command-string runner and
default v1 CLI paths are unchanged and never import the v2 remote modules.

## Risks / Trade-offs

- A pure-Python Ed25519 verifier could be subtly wrong → implement to RFC 8032
  with test vectors (accept/reject, malleability, wrong-key, tampered-message)
  and constant-time-independent verification (verification needs no secrecy).
- Transport could leak action content into argv → the SSH argv is a fixed helper
  invocation only; a test asserts no action/target/secret token appears in it.
- Replay/expiry drift → reuse the P0 reservation window and skew bounds; tests
  cover duplicate, expired, and skewed runs.
- Remote self-report trusted → identity, executable digest, privileges, and
  egress are all verified against pinned/confirmed values; self-reports are
  rejected by tests.
- Loopback test harness diverging from real SSH → the framed protocol is
  transport-agnostic; the client is tested over an in-process bidirectional pipe
  that exercises the exact P0 read/write, and the SSH argv construction is tested
  separately.

## Migration Plan

1. Add remote transport, helper-identity, permit (Ed25519 verify), and egress
   modules under `src/hackbot/engagement_v2/`, plus the fixed helper, importing
   the P0 package and P1–P3 modules and the standard library only.
2. Add loopback framed-protocol tests, RFC 8032 permit vectors, a harmless
   fixture helper, and SSH-argv construction tests; extend the v2-consumer
   allowlist guard; wire the explicitly-v2 remote CLI entry.
3. Verify (full suite, ruff/format, mypy, drift, OpenSpec strict, secret scan,
   `git diff --check`), request independent review, merge, archive.

Rollback removes the P4 modules, helper, CLI wiring, and tests and reverts the
guard. P4 persists only per-run artifacts a documented cleanup removes; the v1
command-string runner remains available during the compatibility window.

## Open Questions

None blocking. The framed protocol, replay window, projection, and reason codes
are fixed by P0; the gate/evidence/cleanup semantics by P3. The pure-Python
Ed25519 verifier is the one implementation choice, made to preserve the
dependency-free core; introducing a third-party crypto dependency instead would
require a separately approved design.
