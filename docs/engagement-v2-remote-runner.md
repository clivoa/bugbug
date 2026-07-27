# Engagement v2 remote helper and trust protocol (P4)

**Status:** trust/crypto core implemented on `feat/engagement-v2-remote`; framed
data path and real-SSH wiring are documented follow-ups (below).

P4 replaces the v1 SSH command string with a fixed, pinned, replay-resistant
remote path built on the P0 framed protocol. This change implements the
**new trust and cryptographic core** that P4 adds; the remote data path reuses
the already-shipped P0 protocol and the P3 execution semantics.

## Public interfaces (implemented)

`hackbot.engagement_v2._ed25519`

- `verify(public_key, message, signature) -> bool` — pure-standard-library
  RFC 8032 Ed25519 **verification only** (no signing key ever exists in the
  process). Validated against the RFC 8032 test vectors and rejects
  non-canonical/malleable scalars, wrong keys, and tampered messages.

`hackbot.engagement_v2.remote_transport`

- `build_ssh_argv(runner) -> list[str]` — the fixed exec-only SSH argv:
  `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`, `BatchMode=yes`, agent/X11/
  port forwarding and TTY disabled, pinned `UserKnownHostsFile`, pinned identity,
  and only the fixed absolute helper path. No action/target/parameter/secret is
  ever interpolated.

`hackbot.engagement_v2.remote_helper`

- `verify_executable_digest(path, expected_sha256) -> str` — open the executable
  as a regular file (no symlink), verify its SHA-256, and return the verified path
  for the consumer to bind to `argv[0]` (P0 review N2). `verify_helper_identity`
  and `verify_protocol_version` reject self-reports and wrong versions.

`hackbot.engagement_v2.remote_permit`

- `verify_permit(permit, signature, signer_public_key, *, pinned_signer_fingerprint,
  context, now)` — Ed25519 machine-signed privilege permit verification bound to
  engagement/authority/action/runner/executable/exact-privilege-set/nonce/expiry,
  checked against the pinned signer fingerprint and a 1–300 s lifetime. Fails
  closed with `EXEC_PRIVILEGE_MISMATCH` / `EXEC_PROTOCOL_EXPIRED`.

`hackbot.engagement_v2.remote_replay`

- `ReplayCache.reserve(authority_digest, run_id, nonce, now)` — atomic reservation
  of the run tuple with the P0 retention window; a duplicate fails closed with
  `EXEC_PROTOCOL_REPLAY`.

`hackbot.engagement_v2.remote_egress`

- `verify_egress(source_identity, egress_attestation, *, signer_public_key,
  pinned_signer_fingerprint, now) -> str` — `direct-interface` and
  `attested-egress` are distinct claims; a local address asserts no public egress,
  and an observed claim requires a pinned, Ed25519-signed, fresh attestation or
  fails closed with `EXEC_TRUST_MISMATCH`.

## Trust root

The remote trust root is the pinned SSH host key plus the pre-provisioned pinned
helper identity (SHA-256 or code-signing) from the confirmed runner projection. A
helper self-report never satisfies identity. Static runner OS, architecture, and
permitted privileges are upper bounds; a privileged action additionally requires
a machine-signed Ed25519 permit. A target's own state, privileges, egress, and
cleanup remain unverified self-reports.

## Follow-ups (not yet implemented)

- The **framed request/response driver**: building the full P0 request header
  (via `hackbot.engagement_v2.protocol`), sending request frames, and verifying
  the response echo and hash-chain over a real transport. The P0 protocol module
  it will call is already implemented and tested; P4 will wire the request
  builder, the loopback test harness, and the response verifier.
- The **fixed `hackbot-remote-runner` helper process** and the **real SSH
  subprocess** transport, plus the **v2 remote CLI entry**. These need a real
  execution node to exercise end-to-end and reuse the P3 executor semantics for
  the remote run.
