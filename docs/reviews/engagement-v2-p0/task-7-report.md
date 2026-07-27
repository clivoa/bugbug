# Task 7 report: v1 isolation and P0 contract boundary

## Scope

Task 7 changed only its four deliverables:

- `tests/engagement_v2/test_v1_isolation.py`
- `docs/engagement-v2-contracts.md`
- `docs/next-steps.md`
- `docs/openspec-and-github-project-workflow.md`

No production runtime file and no OpenSpec task checkbox was changed. This
report is an ignored SDD record and is intentionally outside the Task 7 commit.

## RED/GREEN

### RED

After adding the AST/runtime/schema guards and before creating the contract
document, the focused command produced the required single documentation
failure:

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_v1_isolation.py -q
```

```text
...F
FileNotFoundError: [Errno 2] No such file or directory:
'docs/engagement-v2-contracts.md'
```

The three passing checks were:

- AST import analysis over `src/hackbot/cli`, `programs`, `risk`, `scope`, and
  `tools`;
- a clean child interpreter importing and exercising the relevant v1 CLI,
  schema, risk, scope, and tool-runner entrypoints, then checking
  `sys.modules` for `hackbot.engagement_v2`;
- `hackbot.programs.schema.SCHEMA_VERSION == 1`.

The static guard parses `ast.Import` and `ast.ImportFrom`; it resolves absolute
and relative forms rather than searching source text for a module substring.

### GREEN

After writing the document and roadmap/workflow updates:

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_v1_isolation.py -q
```

```text
....                                                                     [100%]
```

## Verification

All following commands exited 0:

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_v1_isolation.py -q
.venv/bin/ruff check tests/engagement_v2/test_v1_isolation.py
.venv/bin/ruff format --check tests/engagement_v2/test_v1_isolation.py
.venv/bin/mypy --explicit-package-bases tests/engagement_v2/test_v1_isolation.py
.venv/bin/python scripts/export_engagement_v2_schemas.py --check
.venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py --check
git diff --check
```

The schema and fixture commands ran in check mode only; they made no writes.

## Requirement mapping

| Task requirement | Evidence |
| --- | --- |
| Guard v1 imports without source substring matching | `test_v1_source_does_not_import_engagement_v2` parses AST imports, including relative `ImportFrom` forms. |
| Prove v1 runtime cannot activate P0 | `test_v1_runtime_does_not_activate_engagement_v2` uses a separate interpreter, exercises entrypoints, and asserts no v2 module is in `sys.modules`. |
| Preserve v1 schema | `test_current_runtime_schema_remains_v1` asserts `SCHEMA_VERSION == 1`. |
| Establish the initially failing document assertion | `test_contract_document_declares_v2_unavailable` failed only because the document was absent, then passed on the required exact statement. |
| Document actual P0 interfaces and boundaries | `docs/engagement-v2-contracts.md` maps package modules, canonical/digest semantics, safe grammar, generated artifacts, protocol values, P1/P2/P4 consumers, OpenSpec, and Issue #1. |
| Explicitly deny P0 execution, SSH/helper/replay claims | The document says `P0 does not enable engagement v2 execution` and that no SSH, helper, or replay cache exists in P0. |
| Mark P0 Ready/current and retain dependencies | `docs/next-steps.md` identifies P0 as active Ready and P1–P7 as dependent. |
| Record the active change in workflow inventory | `docs/openspec-and-github-project-workflow.md` records `openspec/changes/engagement-v2-security-contracts/` in the P0 inventory row. |

## Self-review and concerns

- Reviewed the four-file diff and `git diff --check`; no whitespace error found.
- The runtime proof intentionally runs the current Python executable with
  `-c pass` through the existing v1 `CommandRunner`; it exercises the runner
  without target activity or v2 activation and does not assume `/usr/bin/true`.
- P0 does contain protocol and trust *constants* for P4 consumption, but no
  P0 SSH client, helper, replay storage, privilege broker, loader, or executor
  was documented as existing.
- Independent review found no Critical or Important issue. Its one Minor
  cleanup (a redundant package-path conditional) was simplified before the
  single commit; the runtime exercise uses `sys.executable -c pass` for
  portability.
- OpenSpec task checkboxes are deliberately unchanged. Task 8 owns final gates
  and task-status completion.

## Fix round 1/5

### RED

After adding controlled AST regressions and documentation/status assertions,
the focused guard failed as expected:

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_v1_isolation.py -q
```

```text
F.....FF
```

- The absolute-form AST regression proved the defect: only
  `import hackbot.engagement_v2` was detected; both
  `from hackbot.engagement_v2 import ContractError` and
  `from hackbot import engagement_v2` were incorrectly prefixed with the
  importing package.
- The documentation assertion failed because the Markdown contained two
  reverse solidi in the magic and did not state replay retention after expiry.
- The roadmap assertion failed because it did not label the 912/913 result as
  historical or state that Task 8 full verification/delivery remains pending.

The runtime child was simultaneously strengthened to call the configured
`hackbot.cli.main:app` entrypoint, evaluate a real deterministic L0 policy
decision, use only explicit `if ...: raise SystemExit(...)` checks, and retain
the schema, scope, command-runner, and `sys.modules` checks.

### GREEN

The fix uses an empty base for absolute `ImportFrom` nodes and calculates a
package-relative base only when `level > 0`. The tests now cover the required
absolute forms and `from ..engagement_v2 import ReasonCode` from both a normal
module and a package `__init__.py`.

All following commands exited 0:

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_v1_isolation.py -q
.venv/bin/ruff check tests/engagement_v2/test_v1_isolation.py
.venv/bin/ruff format --check tests/engagement_v2/test_v1_isolation.py
.venv/bin/mypy --explicit-package-bases tests/engagement_v2/test_v1_isolation.py
.venv/bin/python scripts/export_engagement_v2_schemas.py --check
.venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py --check
git diff --check
```

Focused pytest initially reported `8 passed`. After the post-review `__init__`
matrix amendment, fresh focused pytest reported:

```text
.........                                                                [100%]
```

That is `9 passed`. The protocol document now renders the exact
magic as `b"HBV2RUN\x00"` and says P4 retains a replay reservation for 600
seconds after expiry or until a longer in-progress run finalizes; it continues
to state that no replay cache exists in P0. The roadmap now separates the
historical v1 snapshot from current P0 Ready status and leaves Task 8 pending.

Post-commit review found that the absolute-import regression matrix initially
covered only a normal module. The same three absolute forms were added for a
package `__init__.py`; the relative-form initializer regression remains
separate. A temporary mutation restoring `base = package` made that new focused
initializer test fail before the empty absolute base was restored.
