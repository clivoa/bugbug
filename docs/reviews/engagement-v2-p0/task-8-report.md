# Task 8 verification report

Status: **VERIFIED AND COMMITTED** — Task 8.1 is complete. Task 8.2 remains
unchecked because its independent review, GitHub/Project update, and post-merge
archive are deliberately coordinated by the root agent.

Branch/worktree: `feat/engagement-v2-security-contracts`; Task 8 dispatch base
`b0b8d49`; verified Task 8 HEAD `5e87d51`.

## P0-focused gates

```console
$ .venv/bin/python -m pytest tests/engagement_v2 -q
........................................................................ [ 30%]
........................................................................ [ 60%]
........................................................................ [ 90%]
.......................                                                  [100%]
$ .venv/bin/python scripts/export_engagement_v2_schemas.py --check
$ .venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py --check
EXIT_CODES p0_pytest=0 schema_check=0 fixture_check=0
```

All three commands exited 0.

## Initial repository-wide evidence (RED)

```console
$ .venv/bin/python -m pytest
1151 passed, 1 skipped in 18.00s
$ .venv/bin/ruff check .
All checks passed!
$ .venv/bin/ruff format --check .
5 files would be reformatted, 200 files already formatted
$ .venv/bin/mypy src
Success: no issues found in 58 source files
$ OPENSPEC_TELEMETRY=0 openspec validate engagement-v2-security-contracts --type change --strict --no-interactive
Change 'engagement-v2-security-contracts' is valid
$ git diff --check
EXIT_CODES full_pytest=0 ruff_check=0 ruff_format=1 mypy=0 openspec_validate=0 diff_check=0
```

Fresh full-suite count: **1151 passed, 1 skipped**. The sole skip is
`tests/tools/test_actions.py:104` because `nmap` is not installed.

The blocking `ruff format --check .` output identifies these tracked files:

- `docs/superpowers/plans/2026-07-26-engagement-v2-security-contracts.md`
- `scripts/export_engagement_v2_schemas.py`
- `src/hackbot/engagement_v2/protocol.py`
- `tests/engagement_v2/test_canonical.py`
- `tests/engagement_v2/test_protocol.py`

`git diff --quiet b0b8d49 --` over those five paths exited 0, so their
formatting state exactly matches the dispatch base rather than being introduced
by this Task 8 verification run. Correcting them is outside this dispatch's
authorization to avoid altering prior-task runtime/tests/docs.

## Publication and secret guards

```console
$ .venv/bin/python -m pytest tests/publication_guard -q
....                                                                     [100%]
$ ! rg -n '(gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9]{32,})' src/hackbot/engagement_v2 schemas/engagement-v2 tests/fixtures/engagement_v2 docs/engagement-v2-contracts.md
EXIT_CODES publication_guard=0 secret_guard=0
```

Publication guard: 4 passed (exit 0). The negated `rg` secret guard exited 0
and emitted no matches; therefore the underlying scan found no matching secret
pattern in the required paths.

## OpenSpec JSON evidence

```console
$ OPENSPEC_TELEMETRY=0 openspec status --change engagement-v2-security-contracts --json
exit 0
```

Status summary: `isComplete: true`; proposal, design, specs, and tasks
artifacts are each `done`; next step says to review tasks before implementation.
This is planning-artifact completeness, not completed task checkboxes.

```console
$ OPENSPEC_TELEMETRY=0 openspec validate engagement-v2-security-contracts --type change --strict --no-interactive --json
exit 0
```

Strict-validation JSON summary: `items: 1`, `passed: 1`, `failed: 0`; change
`engagement-v2-security-contracts` is `valid: true` with no issues.

## Remediation and fresh GREEN evidence

The controller reproduced the failure with Ruff 0.16.0 and confirmed that it
was canonical formatting only. The following mechanical remediation was applied
to exactly these five paths:

```console
$ .venv/bin/ruff format docs/superpowers/plans/2026-07-26-engagement-v2-security-contracts.md scripts/export_engagement_v2_schemas.py src/hackbot/engagement_v2/protocol.py tests/engagement_v2/test_canonical.py tests/engagement_v2/test_protocol.py
5 files reformatted
```

The resulting diff changed only line wrapping/parenthesization: 22 insertions
and 75 deletions across those five paths, with no other file changed. It passed
`git diff --check` before the fresh gate run.

```console
$ .venv/bin/python -m pytest tests/engagement_v2 -q
$ .venv/bin/python scripts/export_engagement_v2_schemas.py --check
$ .venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py --check
EXIT_CODES p0_pytest=0 schema_check=0 fixture_check=0

$ .venv/bin/python -m pytest
1151 passed, 1 skipped in 18.33s
$ .venv/bin/ruff check .
All checks passed!
$ .venv/bin/ruff format --check .
205 files already formatted
$ .venv/bin/mypy src
Success: no issues found in 58 source files
$ OPENSPEC_TELEMETRY=0 openspec validate engagement-v2-security-contracts --type change --strict --no-interactive
Change 'engagement-v2-security-contracts' is valid
$ git diff --check
EXIT_CODES full_pytest=0 ruff_check=0 ruff_format=0 mypy=0 openspec_validate=0 diff_check=0

$ .venv/bin/python -m pytest tests/publication_guard -q
....                                                                     [100%]
$ ! rg -n '(gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9]{32,})' src/hackbot/engagement_v2 schemas/engagement-v2 tests/fixtures/engagement_v2 docs/engagement-v2-contracts.md
EXIT_CODES publication_guard=0 secret_guard=0
```

Fresh counts: focused P0 gate exit 0; full suite **1151 passed, 1 skipped**;
publication guard **4 passed**. The negated secret scan exited 0 and emitted no
matches. The one full-suite skip remains the expected missing-`nmap` skip at
`tests/tools/test_actions.py:104`.

OpenSpec JSON was rerun after the task-checkbox update:

```console
$ OPENSPEC_TELEMETRY=0 openspec status --change engagement-v2-security-contracts --json
exit 0; isComplete: true; proposal/design/specs/tasks artifacts: done
$ OPENSPEC_TELEMETRY=0 openspec validate engagement-v2-security-contracts --type change --strict --no-interactive --json
exit 0; summary totals: items=1, passed=1, failed=0; valid=true; issues=[]
```

## Commit scope and follow-up

Commit `5e87d51` (`test: verify engagement v2 security contracts`) contains
exactly the five formatter-remediation paths and
`openspec/changes/engagement-v2-security-contracts/tasks.md`. Checkboxes
1.1–8.1 are marked complete from the accumulated verified evidence; 8.2 remains
unchecked for the root-owned independent review/publication/archive workflow.
`git diff --cached --check` passed before commit. Post-commit `git status`
contains only the pre-existing untracked `.venv`; it was not staged.

Deferred/parked observations from `progress.md`, not changed here: Task 2
single-trailing-newline assertion; Task 4 exporter preflight, safe-pattern
example, explicit `O_NONBLOCK`, and zero-byte-write fail-closed hardening;
Task 5 partial-write behavior and descriptor-vs-frame mutation test coverage;
Task 6 determinism, Windows-path coverage, concurrent directory-swap race, and
portable `O_NOFOLLOW`. The former Task 7 `FrameType` documentation omission is
resolved in the final review fix wave below.

## Final review fix wave

Commit: `4173929` (`fix: resolve engagement v2 final review findings`)

The final compliance/security reviews were read with the complete OpenSpec
design, all three delta specs, and the progress ledger. The combined initial
focused RED produced 13 expected failures. Key deterministic evidence:

- safe-pattern worst case: 29,368,320 matcher calls before the fix versus the
  required 65,536 `input_length * atom_count` bound;
- one-byte exact reads: 93,383,361-byte traced peak before the bounded buffer;
- schema check: all seven schemas plus manifest reported drift before
  regeneration;
- reasons, binding/projection registries, root canonical annotation,
  manifest-last order/failure semantics, runner trust tuple, and `FrameType`
  documentation each failed at their intended assertion.
- direct `5e87d51` base probes confirmed the private `[-60:]` slice was present
  and the required caller-normalized wording and `FrameType` interface text
  were absent.

Finding resolution:

1. I1 — sliding-window matcher, 8,192-byte ASCII preflight with typed
   `INVALID_LIMIT`, deterministic worst-case transition assertion, and 50,673
   exhaustive reference-equivalence cases.
2. I2 — exact `x-hackbot-canonical-format` root annotation on all seven schemas,
   regenerated manifest, exact coverage, and necessary-but-insufficient Draft
   validation documentation without a runtime schema dependency.
3. I3 — both normative branches now use `INVALID_DOCUMENT_STRUCTURE`; a
   namespace-scoped backtick-token test proves spec membership in `ReasonCode`.
4. I4 — code-owned 29-leaf runner-security registry, two exact operational
   exclusions, runner-schema leaf alignment, complete egress trust tuple, and a
   golden vector whose digest changes for every registered leaf.
5. I5 — one 64-byte snake-case binding grammar now drives parameter/request
   keys, secret/target bindings, schema/runtime placeholders; the three
   conflicting names are rejected while general value identifiers remain
   available.
6. M1 — schema documents publish before `manifest.json`; a schema failure
   preserves the prior manifest.
7. M2 — `_read_exact` uses one preallocated bounded `bytearray`; the 1 MiB
   one-byte-read regression stays below four times input size.
8. M3 — the protocol fixture frame boundary is derived from prefix and
   canonical header length; `[-60:]` is gone.
9. M4 — task 2.1 now says caller-normalized set-like inputs; a narrow generated
   fixture distinguishes that boundary from ordered argv without a P1
   normalizer.
10. M5 — `FrameType` is listed in the public protocol interface and guarded by
    the documentation test.

Fresh GREEN gates:

```console
focused engagement-v2: 245 passed in 1.25s
full pytest: 1157 passed, 1 skipped in 19.45s
publication guard: 4 passed in 0.03s
schema exporter --check: exit 0
fixture generator --check: exit 0
OpenSpec strict validation: valid, exit 0
Ruff check: All checks passed
Ruff format --check: 205 files already formatted
mypy src: no issues in 58 source files
secret scan: no matches, exit 0
git diff --check: exit 0
```

OpenSpec 8.2 remains `[ ]`. No P1/P2/P3/P4 runtime, dependency, push, PR,
GitHub mutation, archive, or v2 activation entered this wave.
