# Engagement v2 P2 actions/binder/policy — independent review disposition

**Date:** 2026-07-27

**Reviewer:** independent read-only subagent (security-focused code review of the
`engagement-v2-actions-policy` change). The reviewer made no repository changes.

**Scope:** `src/hackbot/engagement_v2/{manifest,binder,policy}.py` and their tests,
checked against the three P2 delta specs, `design.md`, and the archived P0
`action-execution-contracts` they consume.

## Summary

The reviewer's initial verdict was **not yet faithful/safe**: the layer was
deterministic and executed nothing, but had two severe gaps that defeated the
change's purpose — a shell/interpreter argv-injection path and a scope-bypass
path — plus a false-allow and several strictness gaps. All findings were
reproduced against the real code. **Every finding is now fixed** with tests and
spec scenarios; verification after the fixes is fully green.

## Finding disposition

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| F1 | Severe | Interpreter/shell inline-eval flags (`bash -c {value}`) were never rejected, even at L3 → request-driven command execution. | **Fixed.** The manifest rejects any argv token that is an inline-eval flag for a shell/interpreter executable basename (`INLINE_MODE_FLAGS_BY_BASENAME`); the only safe L3 form is an interpreter with an immutable `{artifact_file}` script. Test `test_interpreter_inline_eval_rejected_even_at_l3`; new spec scenario. |
| F2 | High | Target-shaped `{value:...}` parameters (url/host/ip/cidr/…) rendered to argv without any scope check, bypassing the all-target guarantee. | **Fixed.** The manifest rejects `{value:id}` referencing a target-shaped parameter type; target-shaped inputs must use scope-checked `{target}`/`{targets_file}` bindings. Test `test_target_typed_value_parameter_rejected`; new spec scenario. |
| F3 | Medium-High | Prohibited tools / vulnerability types / excluded impacts were never enforced (false-allow). | **Fixed.** Policy denies `DENY_POLICY_LIMIT` when the executable basename is in `prohibited_tools`, or the action's vulnerability types/impacts intersect the program's prohibited/excluded lists. Test `test_prohibited_tool_denies`; new spec requirement. |
| F4 | Medium | Elevation basenames were rejected as the executable but allowed as argv tokens. | **Fixed.** Any argv literal whose basename is an elevation basename is rejected. Test `test_elevation_argv_token_rejected`; new spec scenario. |
| F5 | Medium | No default scalar/per-token/total argv byte caps in the binder. | **Fixed.** The binder enforces the P0 default scalar cap (2,048), per-token cap (4,096), and total-argv cap (65,536). Test `test_unbounded_string_hits_default_scalar_cap`; new spec scenario. |
| F6 | Medium | Rate enforceability too narrow; request concurrency/rate never checked against the program. | **Fixed.** Rate-unenforceable now also covers fan-out (`{targets_file}`) and authenticated-testing; request rate and concurrency are checked against `max_requests_per_second`/`concurrency` (`DENY_POLICY_LIMIT`). Tests `test_fanout_not_applicable_rate_denies`, `test_concurrency_over_program_limit_denies`, `test_rate_over_program_limit_denies`. |
| F7 | Medium | `hackbot-safe-fullmatch-v1` patterns were not captured or enforced. | **Fixed.** The manifest compiles a declared pattern via the P0 matcher and the binder validates values with `safe_fullmatch`. Test `test_safe_pattern_is_enforced`; new spec scenario. |
| F8 | Low-Medium | Missing collection/enum/int bounds; per-action unknown fields not rejected; `artifact_bindings` hard-coded empty. | **Fixed.** Enum ≤256, int64 range and `min≤max`, `max_length` 1..8,192, action-id ≤128 bytes, and per-action collection caps are enforced; unknown action fields are rejected (`test_unknown_action_field_rejected`); artifact bindings are derived from `artifact-ref` parameters so the safe L3 form is representable. |
| F9 | Low | Effective risk was `max(declared, requested)` only. | **Fixed.** Effective risk now includes a per-capability inferred floor (`max(declared, inferred, requested)`); a request can only raise it. Test `test_capability_inference_raises_effective_level`. |

### Nits

- `decide` returns a `PolicyDecision(DENY, …)` for policy denials and raises
  `ContractError(INVALID_REQUEST)` only for structurally malformed requests
  (unknown action, non-mapping parameters). Retained by design.
- `DENY_AUTHORIZATION_STALE` is not re-emitted here: the P1 loader already
  verified the confirmed-authority digest before a snapshot exists, so policy
  trusts the frozen `confirmed` flag. Noted for completeness.

## What the reviewer confirmed solid

Determinism (no time/RNG; reads no `profile`); "executes nothing" (no
subprocess/socket/keyring import or exec-family call; secrets stay opaque
references); `argv[0]` is always the selected absolute executable and requests
carrying argv/executable are refused; the exact-boolean capability gate and the
all-target deny-wins loop (for target-binding targets — the bypass via value
params was F2, now closed).

## Status

All nine findings are resolved with tests and spec scenarios. Verification after
the fixes: 1271 passed / 2 skipped; ruff, format, mypy, OpenSpec strict, fixture
drift, secret scan, and `git diff --check` all clean. P2 is cleared to merge and
archive (after P1 merges, since P2 is stacked on it).
