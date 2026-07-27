# Engagement v2 P1 loader and scope — independent review disposition

**Date:** 2026-07-27

**Reviewer:** independent read-only subagent (security-focused code review of the
`engagement-v2-loader-scope` change). The reviewer made no repository changes.

**Scope:** `src/hackbot/engagement_v2/` (loader, projection, scope, migration),
`src/hackbot/cli/engagement_cmd.py` and the `engagement` subcommand wiring,
`scripts/generate_engagement_v2_engagement_fixtures.py`, and
`tests/engagement_v2/*`, checked against the three P1 delta specs, `design.md`,
and the archived P0 contracts they consume.

## Summary

The reviewer's verdict was **largely faithful and safe**: the fail-closed
loader, hardened decode, confirmation projection, and typed scope engine match
their specs, with **no confirmation-projection gap** and no cross-protocol,
CIDR, or host false-allow. One genuine false-allow (URL path traversal) and one
error-contract gap were found and are fixed. All findings are resolved.

## Finding disposition

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| F1 | Medium-High | `_url_matches` compared raw paths, so `https://app.example/admin/../secret` (and its `%2e%2e` form) inherited the `/admin` authorization — a real false-allow in the frozen scope layer. | **Fixed.** `scope._normalize_path` now percent-decodes and dot-segment normalizes the target and rule paths before the prefix comparison. Tests: `test_url_dot_segment_traversal_denied`, `test_url_encoded_traversal_denied`, `test_url_dot_segment_within_scope_authorized`. New spec scenario added. |
| F2 | Low-Medium | A scalar where a scope kind expects a list (or a non-mapping section/`testing_rules`) raised a bare `TypeError`, escaping the closed `ReasonCode`/`ContractError` contract. | **Fixed.** The loader validates nested structure and wraps the projection call, mapping malformed values to `INVALID_DOCUMENT_STRUCTURE`. Tests: `test_scalar_scope_kind_maps_to_contract_error`, `test_non_mapping_scope_section_rejected`. New spec scenario added. |
| F3 | Low (by-design footgun) | Exclusions were symmetric with inclusion, so a cross-kind exclusion (e.g. a `hosts` exclusion for an HTTP host) was silently ineffective — internally consistent, not a deny-wins gap. | **Fixed (hardened).** Exclusions are now kind-agnostic: any out-of-scope rule naming a host removes it for every protocol, strengthening deny-wins per CLAUDE.md. Tests: `test_cross_kind_host_exclusion_blocks_http`, `test_cross_kind_host_exclusion_blocks_endpoint`. New spec scenario added. |
| F4 | Low | Unknown-field strictness was only top-level, so an unknown/misspelled scope kind or `testing_rules` field was silently accepted (fail-closed, not a false-allow). | **Fixed.** `_validate_nested_fields` rejects unknown scope kinds and `testing_rules` fields with `INVALID_UNKNOWN_FIELD`. Tests: `test_unknown_scope_kind_rejected`, `test_unknown_testing_rules_field_rejected`. New spec scenario added. |
| N1 | Nit | Excessive nesting can surface as `INVALID_DOCUMENT_STRUCTURE` or `INVALID_LIMIT` depending on which check trips first. | Accepted; both are fail-closed contract codes. No change. |
| N2 | Nit | `confirmed_by`/`confirmation_timestamp` are required-present but not bound into the authority digest. | Accepted by design: they are audit metadata, not authority. No change. |

## What the reviewer confirmed solid

Fail-closed loading (`O_NOFOLLOW`, regular-file, size-before-read, exact read
with shrink/grow detection, full inode/size/mtime recheck); hardened decode with
no alias/merge/tag/duplicate/float/non-NFC/oversize/version bypass; the
confirmation projection covers every security-relevant authority field and
excludes non-security content, with set normalization that cannot collide; all
typed scope decisions (cross-protocol, host exact-match, endpoint exact
scheme/host/port, wildcard subdomain-only, CIDR literal-IP containment,
cross-family, exclusion-by-overlap deny-wins, DNS-never-widens); the pure,
read-only migration analyzer and its v1-only CLI orchestration; and the
tightened v2-consumer allowlist plus default-CLI non-activation.

## Status

All findings are resolved with tests and spec scenarios. Verification after the
fixes: 1222 passed / 2 skipped; ruff, format, mypy, OpenSpec strict, fixture and
schema drift, secret scan, and `git diff --check` all clean. P1 is cleared to
merge and archive.
