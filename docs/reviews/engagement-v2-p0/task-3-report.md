# Task 3 Report: Bounded Safe-Fullmatch Grammar

## Status

Completed and committed as `10112a9ae3716aca788ab314311abe90f562d42e`
(`feat: add bounded action pattern grammar`).

## Implementation

- Added immutable, slotted `CharacterSet`, `PatternAtom`, and `SafePattern`
  values.
- Added `compile_safe_pattern(source)` as an integer-index parser for the exact
  `hackbot-safe-fullmatch-v1` grammar. It accepts only ASCII source through the
  256-byte maximum, the closed unescaped/escaped literal sets, character
  classes with 1 through 64 syntactic items, same-category ascending
  uppercase/lowercase/digit ranges, optional leading class negation, and one
  `{m}` or `{m,n}` quantifier with `0 <= m <= n <= 1024`.
- Added `safe_fullmatch(pattern, value)` using iterative reachable-position
  sets. It rejects non-printable or non-ASCII values before evaluation and
  counts atom-position and repetition operations against the exact
  `(len(value) + 1) * (len(atoms) + 1) * 1025` limit, raising
  `INVALID_LIMIT` if exceeded.
- The implementation is standard-library-only, imports only Task 1 constants
  and errors, does not import Python `re`, does not recurse, and does not
  import legacy/v1 modules.

## Files

- `src/hackbot/engagement_v2/patterns.py`
- `tests/engagement_v2/test_patterns.py`
- `tests/fixtures/engagement_v2/patterns/cases.json`

## RED / GREEN Evidence

Before production code existed:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_patterns.py -q
```

Result: collection failed with exit 2 and the required:

```text
ModuleNotFoundError: No module named 'hackbot.engagement_v2.patterns'
```

After implementation and formatting, the final focused gate was:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_patterns.py -q
.......................................................... [100%]
58 passed
```

The exact upper quantifier boundary received an additional mutation witness:
temporarily changing the parser guard from `> 1024` to `>= 1024` caused
`test_quantifier_limits_are_exact` to fail because `a{1024}` was rejected.
Restoring the exact guard made that focused test pass.

## Fixture Inspection

`tests/fixtures/engagement_v2/patterns/cases.json` contains only literal,
synthetic cases. Its sole hostname is `scanner.example.invalid`; it contains
no secrets, real targets, or environment-derived values. Python's JSON parser
accepted the frozen fixture.

## Gate Evidence

Final pre-commit commands and results:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_patterns.py -q
58 passed

.venv/bin/ruff check src/hackbot/engagement_v2/patterns.py tests/engagement_v2/test_patterns.py
All checks passed!

.venv/bin/ruff format --check src/hackbot/engagement_v2/patterns.py tests/engagement_v2/test_patterns.py
2 files already formatted

.venv/bin/mypy src/hackbot/engagement_v2/patterns.py
Success: no issues found in 1 source file

git diff --check
exit 0, no output

.venv/bin/python -m pytest
1024 passed, 1 skipped in 18.45s
```

The clean baseline before Task 3 was `966 passed, 1 skipped in 18.55s`.

## Self-Review

- Re-read the Task 3 brief, design, and authoritative action-execution
  requirement against the staged diff.
- Confirmed the required valid examples, implicit full-match behavior, every
  forbidden regex construct category, malformed escapes/classes/quantifiers,
  256/257-byte source boundary, 64/65 class-item boundary, 0/1024/1025
  quantifier boundaries, invalid/cross-category/descending ranges, non-ASCII
  and control denial, and immutable compiled values are behavior-covered.
- Confirmed ranges count as one syntactic class item before expansion. This is
  required for the authoritative valid example
  `[A-Za-z0-9._\-]{1,64}`, whose expanded character set exceeds 64 members.
- Confirmed the behavioral safety coverage uses both a 256-atom bounded
  pattern and a runtime operation-limit seam; it does not grep production
  source to assert implementation text.
- Reviewed the three staged files and ran `git diff --cached --check` before
  committing. Only the prescribed Task 3 files were committed.

## Concerns

- No open Task 3 implementation concern remains.
- The worktree's unrelated untracked `.venv` remains preserved and was not
  staged or committed.
- This ignored report file is intentionally outside the product commit, as
  with the prior SDD task reports.

## Fix Round 1/5: Behavioral Runtime and Operation-Budget Proofs

Committed as `f333c588579ac98e144681250df4382e389a1140`
(`test: prove bounded pattern runtime behavior`).

### Changes

- Replaced the outcome-only large-pattern test with a behavioral regex guard
  that patches `re._compile`, `re.compile`, `re.Scanner`, and the common
  matching, iteration, splitting, and substitution entry points to raise,
  then compiles and matches a real safe pattern successfully.
- Added `sys.setprofile` instrumentation limited to frames owned by
  `hackbot.engagement_v2.patterns`. It compares a one-atom control match with
  a 256-atom match and asserts module call depth does not grow with atom
  count. This is a relative behavioral assertion, not a source/AST check or
  fragile absolute stack limit.
- Added literal assertions for representative instances of the exact
  `(value_length + 1) * (atom_count + 1) * 1025` formula:
  `1_025`, `32_800`, and `539_757_825`.
- Replaced the zero-budget-only seam with two boundary behaviors. The
  two-operation `a`/`a` match succeeds with a budget of exactly two, while a
  budget of one raises `ContractError(INVALID_LIMIT)` on the next counted
  operation.
- No production code changed in this fix commit.

### Mutation / RED Evidence

Each strengthened behavior was made observably RED against a temporary
production mutation, then the mutation was removed:

```text
Temporary re.fullmatch call:
test_compile_and_match_do_not_call_python_re
FAILED: AssertionError: safe patterns must not call Python re

Temporary atom-recursive safe_fullmatch:
test_matching_call_depth_does_not_grow_with_atom_count
FAILED: assert 257 <= 2

Temporary (atom_count + 2) operation formula:
test_operation_limit_formula_is_exact
3 failed: 2050 != 1025, 41000 != 32800,
541858050 != 539757825

Temporary operations >= operation_limit boundary:
test_operation_budget_allows_the_operation_at_the_limit
FAILED: ContractError(INVALID_LIMIT) at operation 2 with limit 2
```

After restoring the original production implementation, all new focused
behaviors passed.

### Final GREEN and Gates

```text
.venv/bin/python -m pytest tests/engagement_v2/test_patterns.py -q
63 passed

.venv/bin/ruff check src/hackbot/engagement_v2/patterns.py tests/engagement_v2/test_patterns.py
All checks passed!

.venv/bin/ruff format --check src/hackbot/engagement_v2/patterns.py tests/engagement_v2/test_patterns.py
2 files already formatted

.venv/bin/mypy src/hackbot/engagement_v2/patterns.py
Success: no issues found in 1 source file

git diff --check
exit 0, no output

.venv/bin/python -m pytest
1029 passed, 1 skipped in 18.68s
```

### Self-Review and Concerns

- Verified the final commit changes only
  `tests/engagement_v2/test_patterns.py`; `patterns.py` has no diff from the
  approved Task 3 implementation.
- Confirmed the regex test executes the real compiler and matcher while all
  patched entry points are live.
- Confirmed profiler state is restored in `finally`, existing profiler state
  is preserved, and the depth assertion measures only pattern-module Python
  calls.
- Confirmed the equality test distinguishes `>` from `>=`, while the
  following test proves the next counted operation fails closed with the
  required reason code.
- The unrelated untracked `.venv` remains preserved and excluded. No open
  Task 3 fix-round concern remains.
