# Engagement v2 security contracts — final fix-wave re-review

Date: 2026-07-27  
Reviewed range: `5e87d51..4173929`  
Reviewed fix commit: `4173929b550ecb60eb8d6e1fda0d0f68933cf015`

## Executive verdict

- Combined Important findings: **5/5 ADDRESSED**
- Selected Minor findings: **5/5 ADDRESSED**
- New Critical findings in the fix-only diff: **0**
- New Important findings in the fix-only diff: **0**
- P1/P2/P3/P4 runtime activation: **none**
- Dependency expansion: **none**
- Generated schema/fixture/manifest coherence: **PASS**
- OpenSpec task 8.2: **still open**
- **Spec compliance: PASS**
- **Ready to merge: YES**

This verdict is for the P0 contract boundary and the fix-only range. OpenSpec
task 8.2 correctly remains open because issue/project updates, merge, and
post-merge archival have not yet occurred.

## Scope and method

The review read, in the requested order:

1. `final-openspec-compliance-review.md`
2. `final-security-quality-review.md`
3. the updated `task-8-report.md`
4. `review-5e87d51..4173929.diff`

The review then inspected only the changed P0 code, generated artifacts,
specification text, documentation, and focused regression coverage. It did not
edit implementation files, commit, push, open a PR, or run broad gates.

The following narrow, read-only checks were performed:

- an in-memory matcher oracle comparison covering 48,279 combinations of
  representative allowed atoms, bounded quantifiers, and values;
- exact in-memory `render_schema_files()` comparison against every committed
  schema and `manifest.json`;
- independent SHA-256 verification of every manifest entry;
- exact in-memory fixture generation comparison against every committed
  engagement-v2 fixture, including an exact fixture-set comparison.

All four checks passed with no mismatch or drift.

## Combined Important verdicts

### A. Matcher worst case, linear bound, and 8,192-byte input — ADDRESSED

Evidence:

- `src/hackbot/engagement_v2/patterns.py:186-231` replaces the prior
  start/repetition exploration with a per-atom sliding-window dynamic program.
  Each atom performs one pass over the input; its add/remove cursors advance
  monotonically, so evaluation is deterministic
  `O(input_length * atom_count)`.
- `src/hackbot/engagement_v2/patterns.py:189-194` rejects an ASCII input over
  8,192 bytes with `INVALID_LIMIT` before matcher transitions begin.
- `tests/engagement_v2/test_patterns.py:207-233` covers the exact 8,192/8,193
  boundary and deterministically counts exactly one character-acceptance
  transition per input character per atom for the former worst-case pattern.
- `openspec/changes/engagement-v2-security-contracts/specs/action-execution-contracts/spec.md:55-70`
  and `docs/engagement-v2-contracts.md:44-55` now state the exact complexity and
  input cap.
- The additional read-only oracle comparison found no semantic mismatch in
  48,279 cases.

The practical multi-second CPU amplification described in the original review
is removed.

### B. Root canonical-schema annotation, documentation, and tests — ADDRESSED

Evidence:

- `src/hackbot/engagement_v2/schemas.py:218-237` adds
  `x-hackbot-canonical-format: hackbot-canonical-json-v1` centrally in
  `_document()`, so all seven schema roots receive the same code-owned
  annotation.
- Every committed schema root contains the exact annotation.
- `tests/engagement_v2/test_schemas.py:90-105` asserts the annotation on the
  exact seven-document set.
- `docs/engagement-v2-contracts.md:57-69` explicitly says ordinary Draft
  2020-12 validation is necessary but not sufficient and requires the strict
  primitive/custom-annotation layer.
- Existing strict canonical primitive tests continue to cover float, control,
  non-NFC, integer, and exact-type rejection.
- In-memory schema rendering matched all committed schemas and the manifest
  exactly.

### C. Unregistered `INVALID_SCHEMA` — ADDRESSED

Evidence:

- The two normative branches now use the registered
  `INVALID_DOCUMENT_STRUCTURE` at
  `openspec/changes/engagement-v2-security-contracts/specs/engagement-authority-contracts/spec.md:72-73`
  and `:151-154`.
- No `INVALID_SCHEMA` reference remains in the active OpenSpec, docs, source,
  schemas, or tests.
- `tests/engagement_v2/test_constants.py:641-657` scans all backticked reason
  tokens in the delta specs and proves they are members of the closed
  `ReasonCode` registry.

### D. Complete runner-authority trust projection — ADDRESSED

Evidence:

- `src/hackbot/engagement_v2/constants.py:376-412` freezes an immutable,
  code-owned registry of all 29 security-projection leaves and the only two
  operational exclusions.
- The registry covers role/node identity; complete SSH endpoint, identity,
  known-hosts, host-key, and fixed-option state; helper path/protocol and both
  possible configured selectors; OS/architecture/privileges; source mode and
  address; the complete egress-attestation tuple; and the privilege signer
  fingerprint.
- `openspec/changes/engagement-v2-security-contracts/specs/engagement-authority-contracts/spec.md:111-143`
  and
  `openspec/changes/engagement-v2-security-contracts/specs/remote-runner-protocol-contracts/spec.md:96-120,164-176`
  align the authority and remote-runner requirements with that exact registry.
- `src/hackbot/engagement_v2/schemas.py:920-1055` aligns runner schema v2 with
  the egress trust tuple and keeps private-key content unrepresentable.
- `tests/engagement_v2/test_constants.py:601-638` freezes the registry;
  `tests/engagement_v2/test_schemas.py:672-704` proves the registry plus the two
  exclusions accounts for every runner-schema leaf except `schema_version`.
- `tests/fixtures/engagement_v2/canonical/runner-security-projection.json` and
  its golden digest are deterministic, and
  `tests/engagement_v2/test_canonical.py:171-199` proves changing every
  registered field changes the authority digest.

The original stale-confirmation gap for SSH/helper/egress/permit trust roots is
closed at the P0 contract boundary.

### E. Binding/placeholder snake case versus general value identifiers — ADDRESSED

Evidence:

- `src/hackbot/engagement_v2/constants.py:67-72,126-130` separates the
  64-byte snake-case `BINDING_NAME_PATTERN` from the 128-byte general
  `IDENTIFIER_PATTERN`.
- `src/hackbot/engagement_v2/schemas.py:196-205,496-503,566-579,611-625,743-769,813-867`
  applies the binding grammar to parameter keys, secret keys, target bindings,
  rate parameter names, action-request keys, and placeholder IDs while
  retaining the general grammar for value identifiers and secret-reference
  values.
- `src/hackbot/engagement_v2/protocol.py:60-64` uses the same binding grammar
  for request-header placeholder validation.
- `openspec/changes/engagement-v2-security-contracts/specs/action-execution-contracts/spec.md:8-17,80-102`
  and `docs/engagement-v2-contracts.md:33-36` make the distinction normative
  and explicit.
- `tests/engagement_v2/test_constants.py:562-587`,
  `tests/engagement_v2/test_schemas.py:307-343`, and
  `tests/engagement_v2/test_protocol.py:659-685` cover accepted snake case,
  rejected `1-target`/`target-name`/`target.name`, and preserved general
  value-identifier forms.

## Selected Minor verdicts

### M1. Publish manifest last — ADDRESSED

`scripts/export_engagement_v2_schemas.py:263-270` writes sorted schema documents
first and `manifest.json` last. Focused tests at
`tests/engagement_v2/test_schemas.py:765-819` freeze the order and prove a
schema publication failure does not publish the new manifest.

### M2. Bound one-byte short-read buffering — ADDRESSED

`src/hackbot/engagement_v2/protocol.py:138-148` uses one preallocated
`bytearray(count)` and copies each short read into it instead of retaining one
Python object per chunk. The focused 1 MiB/one-byte-read memory regression is at
`tests/engagement_v2/test_protocol.py:228-240`.

### M3. Derive the protocol frame-fixture boundary dynamically — ADDRESSED

`tests/engagement_v2/test_protocol.py:980-992` derives the frame offset from the
fixed prefix plus canonical header length. The stale private `[-60:]` literal is
gone. The fixture generator also derives and validates the header boundary at
`scripts/generate_engagement_v2_contract_fixtures.py:234-257`.

### M4. Caller-normalized checkbox wording and evidence — ADDRESSED

`openspec/changes/engagement-v2-security-contracts/tasks.md:8` now says
“caller-normalized set-like inputs.” The deterministic fixture at
`tests/fixtures/engagement_v2/canonical/caller-normalized-collections.json` and
`tests/engagement_v2/test_canonical.py:149-168` prove caller normalization while
preserving argv order. Documentation states that P0 provides neither a loader
nor semantic normalizer.

### M5. `FrameType` public-interface documentation — ADDRESSED

`docs/engagement-v2-contracts.md:14-21` lists immutable `FrameType` in the
public `protocol` interface, and
`tests/engagement_v2/test_v1_isolation.py:250-261` guards the exact interface
text.

## Fix-only new-breakage review

No new Critical or Important breakage was found in `5e87d51..4173929`.

The matcher transition rewrite preserved accepted-language semantics in the
focused oracle comparison. The schema changes are generated from one code-owned
source and remained byte coherent. The runner trust additions close accepted
objects rather than widening executable behavior. The exporter and fixture
changes affect developer publication/test tooling only.

## Runtime activation and dependency boundary

**PASS — zero P1/P2/P3/P4 runtime activation and zero dependency expansion.**

- The fix range changes no dependency manifest or lockfile.
- Runtime-source changes are confined to the existing isolated P0 modules
  `constants.py`, `patterns.py`, `protocol.py`, and `schemas.py`.
- The added imports are Python standard-library/test-only imports.
- No v2 loader, migration, binder, policy decision, secret resolver,
  subprocess execution, SSH transport, replay cache, privilege broker, network
  client, or autonomous workflow path was added.
- The package root and the v1 runtime activation boundary remain unchanged.

## Generated-artifact coherence

**PASS.**

- All eight outputs of `render_schema_files()`—seven schemas plus
  `manifest.json`—match committed bytes exactly.
- Every schema digest recorded in `manifest.json` matches the independently
  computed SHA-256 of the corresponding committed schema.
- Every in-memory generated fixture matches its committed bytes exactly.
- The generated fixture filename set and committed fixture filename set are
  identical.
- The new runner-security golden digest recomputes exactly.

## OpenSpec and gate status

- Tasks 1.1 through 8.1 are checked.
- Task 8.2 remains exactly `[ ]` at
  `openspec/changes/engagement-v2-security-contracts/tasks.md:39`.
- The updated Task 8 report records fresh focused/full pytest, publication,
  schema/fixture drift, strict OpenSpec, Ruff, mypy, secret, and diff checks for
  commit `4173929`.
- Per instruction, this re-review did **not** rerun those broad gates. Their
  execution freshness is therefore reported evidence, not independently
  reproduced evidence in this review.

Keeping 8.2 open is correct: this independent re-review removes the review
finding blocker, but issue/project updates, merge, and archive remain delivery
steps.

## Residual triage

### Load-bearing before merge

None.

### Safe to defer

The 13 previously deferred ledger observations remain outside the load-bearing
P0 security/spec boundary and were not made more severe by this fix wave. They
remain safe to defer under the original rationales; no second fix wave is
recommended.

The five selected Minor findings reviewed here are resolved and are not part of
the deferred set.

## Final decision

**Spec compliance: PASS**

The P0 implementation, generated schemas and fixtures, normative OpenSpec text,
and public documentation now agree on all five combined Important contracts.

**Ready to merge: YES**

No Critical/Important fix remains, no selected Minor remains, and no new
Critical/Important regression was found. OpenSpec task 8.2 should stay open
through merge and the remaining external delivery/archive actions.
