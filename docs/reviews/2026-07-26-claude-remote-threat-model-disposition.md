# Claude engagement v2 remote threat model — disposition

**Date:** 2026-07-26

**Reviewer execution:** local Claude CLI in `--safe-mode`, read-only
`Read,Glob,Grep` tools, no session persistence, and a USD 1.00 budget cap.
Only the umbrella design and prior audit disposition were placed in scope. The
reviewer made no repository changes.

## Summary

The threat model assumed a malicious or negligent action-manifest author in
addition to hostile targets and tool output. The approved Hackbot model trusts
the engagement operator as the authority for declared intent, so claims that
would require proving arbitrary executable semantics are not adopted.
Mechanically enforceable findings about secret isolation, evidence defaults,
remote trust, replay, egress, privilege checks, temporary residue, and
verification races are accepted.

## Finding disposition

| ID | Finding | Disposition |
|---|---|---|
| C1 | Global `secret:<name>` references could cross engagement boundaries. | Accepted. Operator-action secrets are namespaced by canonical engagement ID; global and cross-engagement fallback are prohibited. |
| C2 | Evidence safety relied on self-declared capabilities. | Partially accepted. Operator actions default to metadata-only. Redacted output requires an explicit engagement rule and is forbidden for declared or inferred credential/sensitive-data capabilities. Native structured evidence uses a closed schema. Operator semantic declarations remain an explicit trust boundary, not a proof. |
| I1 | An in-scope target can lie in receipts and preflight results. | Accepted. Target claims are labeled self-reports and cannot independently confirm egress, privilege, state, or cleanup. |
| I2 | Helper digest/version self-report lacked a verification path. | Accepted. The trust root is the pinned SSH host key plus a pre-provisioned digest or signing identity. |
| I3 | A locally assigned source IP does not prove observed egress. | Accepted. Direct interface and independently observed egress are separate claims; required egress needs a configured attestation adapter. |
| I4 | A configured privilege set did not prove privileges held at runtime. | Accepted. Static configuration is only an upper bound; trusted preflight must verify the actual execution identity/capabilities. |
| I5 | `execution-node` was exempt from target scope while able to receive secrets and traffic. | Accepted as a distinct trust principal. It is not a tested target, but its identity and trust anchors are bound into confirmed authority. |
| I6 | Secret files may remain after crash, `SIGKILL`, or SSH loss. | Accepted. Prefer memory-backed storage, reconcile stale run state, and report cleanup as incomplete. Physical erasure is not claimed. |
| M1 | LDAP stdin transport did not match the tool invocation. | Fixed by protected file transport and explicit `-D`/`-y` bindings. |
| M2 | Remote bootstrap retained shell/rc exposure. | Accepted. Use an exec-only SSH identity and forced fixed helper command with strict host-key pinning. |
| M3 | Framing lacked total caps, nonce, expiry, and replay handling. | Accepted. These enter the P0/P4 protocol contract. |
| M4 | Executable verification had a time-of-check/time-of-use race. | Accepted where the platform can hash and execute the same descriptor; exact-identity actions fail closed otherwise. |
| M5 | Remote revalidation was only structural. | Accepted. Requests and responses bind to confirmed authority and execution digests. |

## Trust claims

- The operator is trusted to declare engagement authority and the intended
  semantics of arbitrary executables.
- Scope, policy, binding, limits, file paths, secret transport, protocol
  framing, and runner identity are mechanically enforced.
- Target/tool output and self-reports are untrusted.
- The design does not claim that a generic runner can prove an arbitrary
  executable will honor undeclared behavior, avoid every external write, or
  never emit a previously unknown secret format.

## Status

The umbrella specification incorporates these dispositions. Exact protocol and
schema constants are gated on the P0 OpenSpec change before implementation.
