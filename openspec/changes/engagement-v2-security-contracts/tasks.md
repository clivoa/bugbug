## 1. Contract registry

- [ ] 1.1 Add failing tests for every version, enum, bound, identifier, reason code, shell/interpreter mode, and elevation basename in the three P0 specs.
- [ ] 1.2 Implement the isolated `engagement_v2.errors` and `engagement_v2.constants` modules until `tests/engagement_v2/test_constants.py` passes.

## 2. Canonical values and digests

- [ ] 2.1 Add failing canonicalization tests for valid primitives, NFC/control/float/int rejection, mapping order, set-like normalization inputs, ordered argv, domain separation, and golden authority digest.
- [ ] 2.2 Implement strict canonical bytes plus authority/execution digest helpers until `tests/engagement_v2/test_canonical.py` passes.

## 3. Safe full-match patterns

- [ ] 3.1 Add failing grammar and matcher tests covering all accepted atoms/classes/quantifiers, every prohibited regex construct, closed bounds, and operation-count limits.
- [ ] 3.2 Implement the non-backtracking parser and matcher until `tests/engagement_v2/test_patterns.py` passes.

## 4. Machine-readable schemas

- [ ] 4.1 Add failing schema/export drift tests for program, scope, authorization, actions, action request, runner, and protocol header documents.
- [ ] 4.2 Implement code-owned Draft 2020-12 schema dictionaries, atomic exporter, generated JSON files, and schema manifest until `tests/engagement_v2/test_schemas.py` passes.

## 5. Remote framing primitives

- [ ] 5.1 Add failing stream-framing tests for magic/version, all integer widths, canonical header, frame types, per-frame/aggregate caps, exact reads, hashes, EOF, run binding, expiry/skew, and response echo.
- [ ] 5.2 Implement bounded stream reader/writer and immutable framing/run-binding values until `tests/engagement_v2/test_protocol.py` passes.

## 6. Golden and negative fixtures

- [ ] 6.1 Add deterministic synthetic canonical, pattern, protocol, malformed-length, and digest fixtures with no real target or credential material.
- [ ] 6.2 Add fixture regeneration/check tooling and prove committed fixture bytes and hashes are reproducible.

## 7. Compatibility and documentation

- [ ] 7.1 Add and pass a guard test proving no v1 CLI/program/risk/tool module imports or activates `hackbot.engagement_v2`.
- [ ] 7.2 Document P0 public interfaces, generated-schema workflow, trust claims, and the fact that v2 execution remains unavailable.

## 8. Verification and delivery

- [ ] 8.1 Run focused P0 tests, the full pytest suite, Ruff check/format, mypy, schema drift, OpenSpec strict validation, secret scan, and `git diff --check`; record fresh outputs.
- [ ] 8.2 Request independent review, resolve findings, update Issue #1/Project fields, and archive the OpenSpec change only after implementation, verification, and merge.
