# Engagement v2 specification re-audit — disposition

**Date:** 2026-07-26

**Reviewer:** independent read-only Codex subagent

**Scope:** The umbrella engagement v2 design and the Claude internal-recon
audit disposition. The reviewer made no repository changes.

## Summary

The re-audit found one Critical, seven Important, and three Minor gaps. The
Critical authority-binding issue is resolved by the operator-approved
`confirmed_authority_digest`. The Important findings are incorporated or
explicitly decomposed into later OpenSpec changes. No v2 execution behavior is
enabled by these documentation changes.

## Finding disposition

| ID | Finding | Disposition |
|---|---|---|
| C1 | Confirmation was not bound to scope, rules, actions, workflows, executables, or runner identity. | Accepted. Confirmation stores a canonical digest over the complete security-relevant authority. A mismatch denies until engagement reconfirmation; no per-action approval is introduced. |
| I1 | Separate files did not form a provably coherent snapshot. | Accepted. Descriptor-based bounded reads, file-identity recheck, canonical digest verification, bounded retry, and fail-closed publication are required. |
| I2 | Metadata-only ignored tool-written files and an unspecified working directory. | Accepted. Each run receives private CWD/HOME/TMPDIR; retained outputs require strict relative declarations and limits. Undeclared outputs are removed and never become evidence. |
| I3 | Remote helper and privilege attestation lacked a trust root. | Accepted. Pinned SSH host key, exec-only identity, pre-provisioned/signed helper identity, and optional signed privilege permit define the root. In-scope target statements remain self-reports. |
| I4 | Several schemas and protocol constants were descriptive rather than normative. | Accepted as P0. Exact enums, bounds, grammars, projections, encodings, caps, states, and vectors must be approved before dependent code work. |
| I5 | Arbitrary executables could not generically honor request-rate policy. | Accepted. Network actions declare an enforceable argv/native rate-control strategy or are denied when finite limits apply. |
| I6 | Runner resource cleanup and target-state rollback were conflated. | Accepted. They have separate statuses, lifecycle stages, evidence, and autonomous barriers. |
| I7 | Autonomous workflows had no strict schema or state machine. | Accepted and deferred to P6. v2 rejects enabled autonomous progression until that separate contract is delivered. |
| M1 | LDAP example declared a secret but did not consume it. | Fixed. The example binds DN explicitly and uses `ldapsearch -y` with a protected secret file placeholder. |
| M2 | “Executed” was ambiguous for impact requirements. | Fixed with an explicit lifecycle. Impact entries are required after interaction is attempted, not for pre-spawn failures. |
| M3 | Catalog milestone was not acceptance-testable. | Fixed. Delivery requires real `skills/internal-recon/**` artifacts, provenance, adapter tests, and harmless fixtures. |

## Delivery consequence

The original umbrella scope is not treated as one implementation plan. It is
decomposed into P0–P7 OpenSpec changes. Effective migration remains last; only
dry-run analysis may arrive earlier. P5 is split between non-credential and
credential/L3 catalog work, while workflows remain a separate P6 design.

## Status

All findings have a concrete disposition in the umbrella specification. P0
still requires its own normative OpenSpec artifacts and operator review before
implementation.
