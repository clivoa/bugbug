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

`hackbot.engagement_v2.remote_runner_helper`

- The fixed `hackbot-remote-runner` helper (remote side): reads one P0 framed
  request from stdin, runs the bound argv with `shell=False` under the request's
  timeout and output caps, and writes one P0 framed response (stdout/stderr
  frames plus a structured result carrying the response hash chain and exit
  code), echoing the request's run binding. Runnable as
  `python -m hackbot.engagement_v2.remote_runner_helper`.

## Real-host verification

The framed data path was exercised end-to-end against an operator-authorized Kali
VM (Linux aarch64, Python 3.13): a P0 framed request was sent over a real SSH
channel to the helper, which ran the bound argv on the VM and returned a P0
framed response; the client verified the echoed run binding and the response hash
chain. See `docs/reviews/2026-07-27-engagement-v2-p4-remote-review-disposition.md`.
A deterministic loopback version is committed as `test_remote_runner_helper.py`.

## Follow-ups (not yet implemented)

- The production **client-side driver** that builds the request, wires the SSH
  transport (`build_ssh_argv`) to the helper, and reuses the P3 executor
  semantics (secret handling, evidence redaction, lifecycle, independent
  fail-closed cleanup) plus crash reconciliation, and the **v2 remote CLI entry**.
  The framed protocol, helper, and trust primitives it composes are implemented
  and (for the framed path) real-host verified.
- A durable, cross-process replay reservation on the helper side (the in-process
  `ReplayCache` is the building block).
