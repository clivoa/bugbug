# Task 2 Report: Strict Canonical Values and Domain-Separated Digests

## Status

Completed and committed as `de485a1495a3e81b2216b827af1d1c82fd2f2c07` (`feat: add canonical engagement digests`).

## Implementation

- Added `canonical_bytes(value)` using recursive, exact-type validation and deterministic UTF-8 JSON (`sort_keys=True`, compact separators, no ASCII escaping).
- Accepted only `None`, exact `bool`, signed 64-bit exact `int`, NFC strings with no surrogate or C0/C1 controls, and recursively valid exact `list`, `tuple`, and `dict` values.
- Rejected unsupported values, malformed mapping keys, non-NFC/control/surrogate strings, out-of-range integers, and nesting past `MAX_DOCUMENT_NESTING_DEPTH` with the required `ContractError` reason codes.
- Added lower-case, prefixed SHA-256 `digest_value` plus domain-separated `authority_digest` and `execution_digest` envelopes using the exact Task 1 projection formats.
- Added synthetic golden fixture input, canonical bytes, and authority digest. The target is exclusively `scanner.example.invalid`; the artifact digest is synthetic and no secrets are present.

## Files

- `src/hackbot/engagement_v2/canonical.py`
- `tests/engagement_v2/test_canonical.py`
- `tests/fixtures/engagement_v2/canonical/authority-input.json`
- `tests/fixtures/engagement_v2/canonical/authority-canonical.json`
- `tests/fixtures/engagement_v2/canonical/authority-digest.txt`

## RED / GREEN Evidence

RED command:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_canonical.py -q
```

Result: collection failed with the expected `ModuleNotFoundError: No module named 'hackbot.engagement_v2.canonical'`.

GREEN commands:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_canonical.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/canonical.py tests/engagement_v2/test_canonical.py
.venv/bin/mypy src/hackbot/engagement_v2/canonical.py
```

Results: 14 focused tests passed; Ruff reported `All checks passed!`; mypy reported `Success: no issues found in 1 source file`.

## Full-Suite Evidence

```text
.venv/bin/python -m pytest
```

Result: `944 passed, 1 skipped in 18.17s` before commit.

## Fixture Inspection and Hashes

The implementation generated and printed the canonical fixture value once; it was then visually inspected and frozen as literal fixture content:

```text
{"action":{"argv":["--target","https://scanner.example.invalid/health","--format","json"],"artifact_hash":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","endpoint":"https://scanner.example.invalid/health"},"profile":"private-pentest","schema_version":1}
sha256:f11f6f5b24b8919c71daade6c6721d88c843c4c427d7361629623376e491f318
```

`shasum -a 256 tests/fixtures/engagement_v2/canonical/authority-canonical.json` produced:

```text
6b86affbe1d4beb79aecdb431fece5f05c903a37af820cb6a68a3ed655373f24
```

Raw-byte inspection confirmed `authority-canonical.json` ends in `7d` (no trailing newline), while `authority-digest.txt` ends in `0a` (exactly one trailing newline). The test reads the frozen canonical bytes and digest rather than constructing expected values in its assertions.

## Self-Review

- Reviewed the staged five-file diff and ran `git diff --cached --check`; no whitespace errors.
- Confirmed the module depends only on the standard library and Task 1's immutable constants/errors.
- Confirmed mapping key checks use Task 1's `MAPPING_KEY_PATTERN`, signed integer checks use Task 1 bounds, and the authority/execution values are exact `hackbot-authority-v1` and `hackbot-execution-v1` formats supplied by Task 1.
- Confirmed list/tuple ordering is preserved and dictionaries are sorted only during serialization.
- Confirmed no real targets, secrets, environment-derived inputs, or legacy/v1 module imports were introduced.

## Concerns

None. The worktree contains an unrelated untracked `.venv` directory; it was intentionally not staged or modified by this task.

## Fix Round 1/5: Canonical Coverage Gaps

### Changes

Expanded `tests/engagement_v2/test_canonical.py` only; no final production-code change was needed.

- `test_canonical_bytes_accepts_exact_literal_values` is parameterized with `None`, both exact booleans, an NFC UTF-8 string, a tuple, and both signed-int64 endpoints.
- `test_invalid_canonical_value_fails_closed` now covers exact-type subclasses of `int`, `str`, `list`, `tuple`, and `dict`; integer and byte mapping keys; and the actual C1 controls U+0080 and U+009F, in addition to the original invalid values.
- `test_canonical_bytes_accepts_maximum_nesting_depth` proves depth 32 is accepted with exact canonical bytes, complementing the existing depth-33 rejection.
- `test_execution_digest_uses_the_frozen_execution_domain` asserts a hand-inspected literal execution digest. Its value was independently derived with `shasum -a 256` over this literal canonical envelope, not by the helper under test:

  ```text
  {"contract":"hackbot-execution-v1","value":{"profile":"private-pentest","schema_version":1}}
  fd637f9f65ed2aacc2f3b5b409b8d9531606469264af4a1fdfdaee4922f3eaa7
  ```

### RED / GREEN Evidence

Important 1 RED: after temporarily weakening the exact integer check to `isinstance(value, int)`, this focused command failed exactly because `IntegerSubclass(1)` was accepted:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_canonical.py -q -k invalid_canonical_value
```

Result: `FAILED tests/engagement_v2/test_canonical.py::test_invalid_canonical_value_fails_closed[1]` with `DID NOT RAISE ContractError`.

After restoring the original exact-type implementation, the Important 1 targeted gate passed:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_canonical.py -q -k 'exact_literal or invalid_canonical_value'
```

Result: `25 passed`.

Important 2 RED: after temporarily changing the depth guard from `>` to `>=` and substituting the authority format in the execution helper, this focused command failed both boundary/domain assertions:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_canonical.py -q -k 'maximum_nesting_depth or frozen_execution_domain'
```

Results: depth 32 raised `ContractError(INVALID_LIMIT)` and the digest assertion received the authority-domain digest rather than frozen execution digest.

After restoring both original implementation lines, the final focused gates were:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_canonical.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/canonical.py tests/engagement_v2/test_canonical.py
.venv/bin/mypy src/hackbot/engagement_v2/canonical.py tests/engagement_v2/test_canonical.py
```

Results: `32 passed`; Ruff `All checks passed!`; mypy `Success: no issues found in 2 source files`.

### Self-Review

- Confirmed the final source diff for `canonical.py` is empty; the commit contains only the requested coverage additions.
- Confirmed every static expected value is literal test data; no assertion derives the execution digest from `execution_digest` or `digest_value`.
- Confirmed the subclass values make an `isinstance` regression observable, C1 coverage uses U+0080/U+009F rather than only DEL, and the nesting tests cover both sides of the exact boundary.
- Ran `git diff --check`; no whitespace errors.

### Concerns

- The temporary depth-failure witness surfaced an existing Python 3.14 interaction: propagating immutable `ContractError` through `contextlib` can attempt to assign `__traceback__` and raise `AttributeError`. This is in Task 1's immutable error interface, was not changed in this round, and does not affect the final green test paths. It is recorded here for final triage rather than broaden this task.
- The unrelated untracked `.venv` remains intentionally unstaged.
