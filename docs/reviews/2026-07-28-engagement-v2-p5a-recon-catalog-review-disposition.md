# Engagement v2 P5a non-credential internal-recon catalog — review disposition

**Date:** 2026-07-28

**Reviewer:** independent read-only subagent (security-focused review of the
non-credential internal-recon catalog). The reviewer made no repository changes.

**Scope:** `src/hackbot/engagement_v2/recon_catalog.py`, the reviewed skill note,
tests and fixtures, and the consumed P2 manifest/policy contracts.

## Summary

The reviewer confirmed the catalog is solid on the argv/injection, provenance,
and no-live-scanning axes, and that the anonymous-LDAP actions are genuinely
non-credential (anonymous simple bind, attributes constrained to
`namingContexts`/`cn`, no authenticated or credential read). Two substantive
correctness/robustness defects and two lower-severity drifts were found — **all
fixed**.

## Finding disposition

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| F1 | Medium-High | The LDAP actions declared `not-applicable` rate control while declaring the network-rated `automated-scanning` capability, so P2 policy would deny them `DENY_RATE_UNENFORCEABLE` when a request-rate cap is set (dead entries) or allow them with an unenforced rate otherwise. | **Fixed.** The LDAP actions now use a code-owned `native-adapter` rate control (`internal-ldap-query`), which is honest (ldapsearch has no argv rate flag) and is not subject to the not-applicable unenforceable-rate denial. The nmap actions were already honest (argv-placeholder bound to `--max-rate`/`--min-parallelism`). |
| F2 | Medium | `FORBIDDEN_CAPABILITIES` omitted `privileged-execution` and `social-engineering`, both L3 policy floors, so an L2 action carrying an L3 capability would pass the disjointness guard. | **Fixed.** The forbidden set now includes every L3-floor capability, and a new test (`test_forbidden_set_covers_policy_l3_floor`) asserts the set covers policy's L3 floor so it cannot drift. |
| F3 | Low-Medium | The disabled-by-default guard sat only on `load_catalog`; `catalog_manifest()` and `validate_manifest` were public, so the registry was reachable ungated. | **Fixed.** `catalog_manifest` is now module-private (`_catalog_manifest`); the only public loader is the gated `load_catalog`, and every test routes through it. |
| F4 | Low | `netstate.interfaces`/`routes` were `L0`, but the umbrella table and the delta spec classify local network state as `L1`. | **Fixed.** All local-network-state actions are `L1` (action, provenance, skill note, and test tightened to `L1`/`L2`). |
| N1 | Nit | The synthetic-fixture test accepts any `172.` prefix (only `172.16/12` is RFC1918). | Accepted; the fixture uses `10.20.0.0/24` and TEST-NET-1 `192.0.2.0/24`, both synthetic. May tighten later. |
| N2 | Nit | `base_dn` is a non-scope-checked `{value:...}` string. | Accepted (reviewer agreed): a DN is a query subtree within the already-scope-checked `{target:endpoint}`, not a target-shaped type. |

## What the reviewer confirmed solid

Whole-token argv with no shell/interpreter/inline-eval/empty-token/pipeline;
target-shaped inputs (subnet/host/endpoint) routed through scope-checked
`{target:...}` bindings (rate/parallelism/top-ports are integer `{value:...}`, no
scope bypass); anonymous LDAP genuinely non-credential; nmap actions correctly
L2/automated-scanning with honest rate control; complete provenance with
attribution; and no live scanning (module imports no subprocess/socket, AST guard
enforces it, fixtures synthetic).

## Status

All findings are resolved with tests and spec-aligned classification.
Verification after the fixes: 1335 passed / 2 skipped; ruff, format, mypy,
OpenSpec strict, secret scan, and `git diff --check` clean. P5a is cleared to
open its PR.
