# Task 1 report: typed failures and immutable contract registry

## Status

Completed and committed as `b17847e831d1310fb4b089f7abbad6c328aa9e18`
(`feat: add engagement v2 contract registry`).

## Implementation

- Added `hackbot.engagement_v2` as a dependency-free P0 package. Its stable
  package surface exports only `ContractError` and `ReasonCode`.
- Added the closed `ReasonCode` string enum and typed `ContractError`.
  Construction accepts only an exact enum member, derives a code-owned
  deterministic message, and `as_dict()` exposes only `reason_code` and
  `message`.
- Added immutable contract constants for all exact values in the three
  authoritative capability specifications: artifact versions, authority and
  action bounds, canonical identifier/digest patterns, policy fields, action
  parameter/placeholder/platform/privilege/risk/evidence/rate/secret enums,
  shell/interpreter/elevation registries and inline-mode flags, retained-output
  type and bounds, lifecycle/cleanup states, and remote protocol framing,
  frame, nonce, signature, source-identity, and private-storage values.
- Used `frozenset` and `MappingProxyType` for set/map registries, `str, Enum`
  for closed string values, `IntEnum` for wire frame types, and `re.ASCII` only
  for identifier/digest syntax. There are no imports of v1 runtime modules.
- Added behavior-level contract tests for exact values, closed membership,
  registry immutability, rejected identifier/digest syntax, typed secret-free
  public errors, and package exports.

## Files

- `src/hackbot/engagement_v2/__init__.py`
- `src/hackbot/engagement_v2/errors.py`
- `src/hackbot/engagement_v2/constants.py`
- `tests/engagement_v2/__init__.py`
- `tests/engagement_v2/test_constants.py`

## TDD evidence

### RED

After creating the focused tests and before creating production code, ran:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_constants.py -q
```

Result: expected collection failure, exit non-zero:

```text
ModuleNotFoundError: No module named 'hackbot.engagement_v2'
```

### GREEN

After implementation and final review fixes, ran:

```text
.venv/bin/ruff format src/hackbot/engagement_v2 tests/engagement_v2
.venv/bin/ruff check src/hackbot/engagement_v2 tests/engagement_v2
.venv/bin/python -m pytest tests/engagement_v2/test_constants.py -q
.venv/bin/mypy src/hackbot/engagement_v2
git diff --check
```

Results:

```text
All checks passed!
15 passed
Success: no issues found in 3 source files
```

## Full-suite evidence

Immediately before commit, ran:

```text
.venv/bin/python -m pytest
```

Result:

```text
927 passed, 1 skipped in 17.50s
```

## Self-review

- Verified the implementation against the Task 1 brief and all three specified
  OpenSpec capability documents.
- Confirmed the dependency boundary with a source search: no imports from
  existing v1/runtime modules occur in `hackbot.engagement_v2`.
- Confirmed staged whitespace with `git diff --cached --check` before commit.
- Performed an independent read-only code review. It identified two Important
  registry gaps: retained output `file`/`directory` values and per-basename
  inline-mode flags. Both were implemented and regression-tested. The
  follow-up review found no Critical or Important issues.

## Concerns

- The worktree contains an unrelated untracked `.venv`; it was not staged or
  included in the commit.
- No remaining Task 1 implementation concerns were identified.

## Review fix round 1

Committed as `1b696221909dff852cc2c5d3b83a6900bc20cf0d`
(`fix: harden engagement v2 contract registry`).

### Implementation and files

- `src/hackbot/engagement_v2/constants.py`: added the exact
  `EXECUTION_PROJECTION_FORMAT = "hackbot-execution-v1"` and
  `SAFE_FULLMATCH_FORMAT = "hackbot-safe-fullmatch-v1"` contract identifiers.
- `src/hackbot/engagement_v2/errors.py`: made public error attributes
  read-only, stored the exact enum in protected exception state, and made
  `message` and `as_dict()` derive only from that exact enum.
- `tests/engagement_v2/test_constants.py`: added exact identifier tests and
  mutation/metadata-injection coverage proving public serialization remains
  the two deterministic code-owned fields.

Exact covering tests:

- `test_projection_format_identifiers_are_exact`
- `test_safe_fullmatch_format_identifier_is_exact`
- `test_contract_error_is_immutable_and_ignores_arbitrary_metadata`

### RED evidence

Each regression was run independently before production changes:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_constants.py::test_projection_format_identifiers_are_exact -q
FAILED: AttributeError: module ...constants has no attribute 'EXECUTION_PROJECTION_FORMAT'

.venv/bin/python -m pytest tests/engagement_v2/test_constants.py::test_safe_fullmatch_format_identifier_is_exact -q
FAILED: AttributeError: module ...constants has no attribute 'SAFE_FULLMATCH_FORMAT'

.venv/bin/python -m pytest tests/engagement_v2/test_constants.py::test_contract_error_is_immutable_and_ignores_arbitrary_metadata -q
FAILED: DID NOT RAISE AttributeError
```

### GREEN and gate evidence

The three focused regressions each passed independently after the minimal
production changes. Final focused verification:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_constants.py -q
.................. [100%]

.venv/bin/ruff check src/hackbot/engagement_v2 tests/engagement_v2
All checks passed!

.venv/bin/mypy src/hackbot/engagement_v2
Success: no issues found in 3 source files

git diff --check
exit 0, no output
```

### Self-review and concerns

- Rechecked all three reviewer findings against the authoritative contract
  wording; the new format values are exact.
- Confirmed ordinary mutation of `reason_code`, `message`, `args`, and
  arbitrary metadata is rejected. Even direct exception-dictionary injection
  cannot shadow the read-only properties or affect/enter `as_dict()`.
- Confirmed the staged diff contained only the three Task 1 files above and
  passed `git diff --cached --check`.
- No open implementation concern remains. The unrelated untracked `.venv`
  remains preserved and was excluded from the commit.

## Review fix round 3

Base: `f333c588579ac98e144681250df4382e389a1140`.

Committed as `e8dde5055aec1e749bb87044b145e752d8d00e22`
(`fix: add closed runner role contract`).

### Authoritative contract and implementation

The remote-runner protocol contract states that `execution-node` is a
confirmed trust principal and `in-scope-target` independently passes scope
validation. Task 4 needs these exact prior-contract values without duplicating
security literals.

Added:

```text
RunnerRole.EXECUTION_NODE = "execution-node"
RunnerRole.IN_SCOPE_TARGET = "in-scope-target"
```

Files changed:

- `src/hackbot/engagement_v2/constants.py`
- `tests/engagement_v2/test_constants.py`

`RunnerRole` is a closed standard-library `str, Enum` available from
`hackbot.engagement_v2.constants`; package-level
`hackbot.engagement_v2.__all__` remains exactly `ContractError` and
`ReasonCode`.

### RED evidence

Before production code, ran:

```text
.venv/bin/python -m pytest \
  tests/engagement_v2/test_constants.py::test_runner_roles_are_closed -q
```

Result: expected collection failure:

```text
ImportError: cannot import name 'RunnerRole' from
'hackbot.engagement_v2.constants'
```

### GREEN and verification evidence

Focused role and package-export tests after the minimal implementation:

```text
.venv/bin/python -m pytest \
  tests/engagement_v2/test_constants.py::test_runner_roles_are_closed \
  tests/engagement_v2/test_constants.py::test_package_exports_only_stable_failure_types -q
.. [100%]
```

Required gates before commit:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_constants.py -q
....................... [100%]

.venv/bin/ruff check src/hackbot/engagement_v2 tests/engagement_v2
All checks passed!

.venv/bin/mypy src/hackbot/engagement_v2
Success: no issues found in 5 source files

git diff --check
exit 0, no output

.venv/bin/python -m pytest
1030 passed, 1 skipped in 18.70s
```

### Self-review and concerns

- Verified both values verbatim against the authoritative remote-runner spec.
- Verified exact enum membership and closed rejection of an unknown role.
- Verified the existing package-export test remained green and
  `src/hackbot/engagement_v2/__init__.py` had no diff.
- Verified only the two listed Task 1 files were staged and
  `git diff --cached --check` was clean.
- No open implementation concern remains. The unrelated untracked `.venv`
  remains preserved and was excluded from the commit.

## Review fix round 2

Base: `16b490dab106832b8e83af5598d639e09749a627`.

Committed as `c303befdde5d1c3392da2d107d1ac429ba98ff87`
(`fix: preserve contract errors through exception handling`).

### Root cause and implementation

On CPython 3.14.3, `ContractError.__setattr__` and `__delattr__` rejected every
attribute. That correctly protected application-facing state, but also
intercepted the interpreter-managed `BaseException` descriptors
`__traceback__`, `__cause__`, `__context__`, and `__suppress_context__`.
`contextlib._GeneratorContextManager.__exit__` assigns `exc.__traceback__`,
which converted the outward typed failure into
`AttributeError("ContractError is immutable")`.

The fix uses a private immutable allowlist for only those four bookkeeping
attributes and delegates their assignment/deletion to `BaseException`.
`reason_code`, `message`, `args`, and arbitrary application metadata remain
immutable. `as_dict()` remains derived solely from the exact `ReasonCode`.

Files changed:

- `src/hackbot/engagement_v2/errors.py`
- `tests/engagement_v2/test_constants.py`

Exact regression coverage:

- `test_contract_error_allows_direct_traceback_assignment`
- `test_contract_error_allows_standard_exception_bookkeeping`
- `test_generator_contextmanager_propagates_same_contract_error`
- `test_normal_raise_and_bare_reraise_preserve_contract_error`
- Existing `test_contract_error_is_immutable_and_ignores_arbitrary_metadata`

### RED evidence

Before the production edit, the five focused behaviors ran against the real
current implementation:

```text
.venv/bin/python -m pytest -q \
  tests/engagement_v2/test_constants.py::test_contract_error_allows_direct_traceback_assignment \
  tests/engagement_v2/test_constants.py::test_contract_error_allows_standard_exception_bookkeeping \
  tests/engagement_v2/test_constants.py::test_generator_contextmanager_propagates_same_contract_error \
  tests/engagement_v2/test_constants.py::test_normal_raise_and_bare_reraise_preserve_contract_error \
  tests/engagement_v2/test_constants.py::test_contract_error_is_immutable_and_ignores_arbitrary_metadata
```

Result:

```text
FFF.. [100%]
direct __traceback__: AttributeError: ContractError is immutable
__cause__ bookkeeping: AttributeError: ContractError is immutable
contextmanager propagation: outward AttributeError at contextlib.py:195
```

The normal bare re-raise and existing application-state immutability cases
were already green, isolating the defect to descriptor delegation.

### GREEN and verification evidence

After the minimal production change, the same focused set returned:

```text
..... [100%]
```

Required gates before commit:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_constants.py -q
...................... [100%]

.venv/bin/python -m pytest tests/engagement_v2/test_canonical.py -q
................................ [100%]

.venv/bin/ruff check src/hackbot/engagement_v2 tests/engagement_v2
All checks passed!

.venv/bin/mypy src/hackbot/engagement_v2
Success: no issues found in 4 source files

git diff --check
exit 0, no output

.venv/bin/python -m pytest
966 passed, 1 skipped in 18.35s
```

### Self-review and concerns

- Verified the allowed names are exactly the four interpreter-managed
  bookkeeping descriptors requested by the finding.
- Verified delegation preserves native `BaseException` validation and
  deletion semantics rather than bypassing them.
- Verified direct assignment, generator-contextmanager propagation, ordinary
  catch/bare re-raise identity, exact reason preservation, deterministic
  serialization, and the existing immutability boundary.
- Verified Task 2 canonical tests and the full suite because this error is a
  cross-task public boundary.
- The staged diff contained only the two listed Task 1 files and passed
  `git diff --cached --check`.
- No open implementation concern remains. The unrelated untracked `.venv`
  remains preserved and was excluded from the commit.
