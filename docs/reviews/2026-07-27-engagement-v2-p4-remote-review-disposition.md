# Engagement v2 P4 remote trust core — independent review disposition

**Date:** 2026-07-27

**Reviewer:** independent read-only subagent (security-focused review of the P4
remote trust and cryptographic core). The reviewer made no repository changes.

**Scope:** `src/hackbot/engagement_v2/{_ed25519,remote_permit,remote_transport,
remote_helper,remote_replay,remote_egress}.py` and their tests, checked against
the four P4 delta specs, `design.md`, and the archived P0 remote-protocol
contract.

## Summary

The reviewer confirmed the **Ed25519 verifier is trustworthy — no forgery and no
catastrophic verify flaw** (faithful to RFC 8032, accepts the RFC vectors,
rejects tampered/wrong-key/malleable/bad-length inputs). The transport, helper
digest, and egress typing were rated solid. Two **schema-level** binding gaps
(which cannot be fixed after signatures exist) and several lows were found. The
schema-level and low findings are **fixed**; the remaining items are recorded
follow-ups.

## Finding disposition

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| F1 | Medium (schema) | The permit omitted `execution_digest` and was not bound to the run tuple (`run_id`/`nonce`), so one signed permit satisfied any run of that action within its ≤300 s lifetime (cross-run replay). | **Fixed.** `execution_digest`, `run_id`, and `nonce` are now part of the signed permit body and `PermitContext`, and checked. Tests `test_permit_for_another_run_rejected`, plus the existing binding tests. |
| F2 | Medium (schema) | The egress attestation was not bound to `run_id`/`nonce`/`execution_digest`, so a valid attestation was reusable across runs within the 60 s window. | **Fixed.** The signed observation now carries and is checked against the run tuple and execution digest. Test `test_attestation_for_another_run_rejected`. |
| F3 | Low | `_recover_x` accepted the non-canonical `x²==0` point encoding with the sign bit set (RFC 8032 decode deviation; not exploitable given a pinned canonical key). | **Fixed.** The `x²==0` case is rejected with the sign bit set. Test `test_noncanonical_x_zero_encoding_rejected`. |
| F4 | Low | No not-yet-valid check on the permit (future `issued_at` accepted) and no future-timestamp bound on the egress observation. | **Fixed.** The permit rejects `now < issued_at`; egress rejects observations more than the clock-skew bound in the future. Tests `test_not_yet_valid_permit_rejected`, `test_future_attestation_rejected`. |
| F5 | Low | `ReplayCache.reserve` was an unlocked check-then-set despite the "atomic" wording. | **Fixed.** The check-and-set is guarded by a lock; the docstring notes a durable cross-process reservation is the helper-process concern. |
| F6 | Nit | Transport path regex permitted shell metacharacters (harmless: pinned config only, never action content); proposal/design over-claimed relative to unimplemented tasks. | Accepted/noted. The transport only ever sources pinned runner config; the doc records the implemented-vs-follow-up split explicitly. |

## Real-host verification (Kali VM, operator-authorized lab)

The framed data path was exercised end-to-end against the operator's Kali VM
(`192.168.64.4`, Linux aarch64, Python 3.13). A P0 framed request built locally
(with the bound `execution_digest`) was sent over a real SSH channel to the
`hackbot-remote-runner` helper, which ran the bound argv (`/usr/bin/uname -a`) on
the VM and returned a P0 framed response. The client verified the echoed run
binding (`run_id`/`nonce`/`authority_digest`/`execution_digest`) and the response
hash chain. Remote stdout confirmed real remote execution:
`Linux kali 7.0.12+kali-arm64 ... aarch64 GNU/Linux`. A deterministic loopback
version is committed as `test_remote_runner_helper.py`.

## Recorded follow-ups (not blocking)

- The production **client-side driver** that builds the request, wires the SSH
  transport to the helper, and reuses the P3 executor semantics (secret handling,
  evidence redaction, lifecycle, independent fail-closed cleanup) plus crash
  reconciliation, and the **v2 remote CLI entry**. The framed protocol, helper,
  and trust primitives it composes are implemented and (for the framed path)
  real-host verified.
- A durable, cross-process replay reservation on the helper side (the in-process
  `ReplayCache` is the building block).

## Status

The Ed25519 verifier is sound; the two schema-level per-run bindings and all lows
are fixed with tests, and the framed data path is verified against a real host.
Verification after the fixes: 1323 passed / 2 skipped; ruff, format, mypy,
OpenSpec strict, secret scan, and `git diff --check` clean.
