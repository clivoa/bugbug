# SDD ledger — plan: docs/superpowers/plans/2026-07-26-engagement-v2-security-contracts.md

Setup: branch `feat/engagement-v2-security-contracts` created from `30dd1e2`.
Setup: baseline `.venv/bin/python -m pytest` — 912 passed, 1 skipped.
Setup: operator approved both pre-flight rulings.
Setup ruling 1: replace source-text import grep with AST import analysis plus runtime isolation evidence.
Setup ruling 2: follow the approved plan's private draft-PR workflow after final verification.
Task 1: fix round 1/5 (3 addressed, 0 open; commits b17847e..1b69622)
Task 1: complete (commits 30dd1e2..1b69622, review clean)
Task 2: minor (deferred): authority digest fixture assertion uses `rstrip("\n")` and does not enforce exactly one trailing newline.
Task 2: fix round 1/5 (2 addressed, 0 open; commits de485a1..16b490d)
Task 2: complete (commits 1b69622..16b490d, review clean; 1 deferred minor)
Task 1: reopened — Important demonstrated on CPython 3.14: immutable `ContractError` blocks standard exception traceback bookkeeping through `contextlib`.
Task 1: fix round 2/5 (1 addressed, 0 open; commits 16b490d..c303bef)
Task 1: complete after reopen (commits 16b490d..c303bef, review clean)
Task 3: fix round 1/5 (2 addressed, 0 open; commits 10112a9..f333c58)
Task 3: complete (commits c303bef..f333c58, review clean)
Task 4: paused after RED — missing Task 1 `RunnerRole` enum; uncommitted Task 4 files preserved in stash `sdd task4 paused for RunnerRole registry fix`.
Task 1: reopened — registry omitted exact runner roles `execution-node` and `in-scope-target`; Task 4 must consume rather than duplicate them.
Task 1: fix round 3/5 (1 addressed, 0 open; commits f333c58..e8dde50)
Task 1: complete after second reopen (commits f333c58..e8dde50, review clean)
Task 4: resumed — paused files restored after `RunnerRole` registry fix.
Task 4: original implementer exhausted usage before commit/report; untracked WIP preserved and recovery handoff written to `task-4-recovery.md`.
Task 4: review open — Critical TOCTOU in path-based symlink checks.
Task 4: review open — Important `--check` ignores unexpected directory entries.
Task 4: review open — Important nonce schema permits noncanonical final base64url character.
Task 4: review decision required — identity-key uniqueness, safe-pattern grammar, and UTF-8 byte caps cannot be enforced by standard Draft 2020-12 alone without a custom runtime validator, conflicting with the approved dependency-free P0 boundary.
Task 4: minor (deferred): remote-header URN hardcodes protocol version rather than using `PROTOCOL_VERSION`.
Task 4: operator ruling — preserve dependency-free P0; publish machine-readable `x-hackbot-unique-by`, `hackbot-safe-fullmatch-v1` format, and `x-hackbot-max-utf8-bytes` contracts for strict P1/P2/P4 enforcement rather than adding a P0 runtime validator.
Task 4: operator additionally approved fixing the deferred remote-header URN while regenerating schemas.
Task 4: fix round 1/5 (5 findings plus URN addressed; Critical temporary-entry substitution and new Important FIFO blocking remain open; commits 1f100cf..81617c5)
Task 4: minor (deferred): write mode could preflight every expected entry before any replacement to fail earlier on a stable later-name symlink.
Task 4: minor (deferred): add a prohibited safe-pattern example to better document why future validators must enforce the custom format.
Task 4: minor (deferred): require `O_NONBLOCK` explicitly instead of `getattr(..., 0)` to make fail-closed support self-documenting.
Task 4: minor (deferred): reject a theoretical zero-byte `os.write` result to prevent a possible infinite write loop.
Task 4: fix round 2/5 (2 addressed, 0 open; commits 81617c5..5ed72b7)
Task 4: complete (commits e8dde50..5ed72b7, review clean; 4 deferred out-of-scope/minor observations remain for final triage)
Task 5: plan illustration drift resolved — approved OpenSpec/generated remote-header schema keys (`argv`, nested `executable`, `frames`) govern over stale illustrative helper field names.
Task 5: review open — Critical request execution identity is only syntax-checked and not recomputed from the request projection.
Task 5: review open — Important aggregate declared size is not preflighted from all header descriptors before any payload read.
Task 5: decision required — OpenSpec enumerates execution-projection contents but does not freeze the literal canonical object shape.
Task 5: minor (deferred): write_message rejects legal partial writes instead of completing the unwritten suffix.
Task 5: operator ruling — execution projection v1 is exactly `{"schema_version": 1, "request": <all canonical request-header fields except execution_digest>}`; the `hackbot-execution-v1` digest envelope hashes this object.
External Claude Task 4 review: inspected after commits `81617c5`/`5ed72b7`; its C1 and I1–I3 describe the pre-hardening exporter and are addressed by descriptor-pinned/no-follow/nonblocking/fail-closed implementation plus exact-directory `--check`.
External Claude Task 4 review ruling: automatic deletion of unexpected files in write mode is rejected as destructive and outside the approved exporter contract; `--check` reports them as drift and leaves them untouched.
External Claude Task 4 review residual: multi-file export remains per-file atomic with manifest last, not globally transactional; accepted for repository artifacts and detectable/repairable by `--check`.
Task 5: minor (deferred): descriptor-vs-frame-prefix mutation test now rejects earlier on execution-digest mismatch unless it rebinds the digest after mutation.
Task 5: fix round 1/5 (2 addressed, 0 open; commits 59cb233..395bb6e)
Task 5: complete (commits 5ed72b7..395bb6e, review clean; 2 deferred minors)
Task 6: review open — Important fixture update/check path handling follows managed symlinks and permits predictable staging symlink overwrite outside the fixture root.
Task 6: review open — Important generator duplicates public nonce/lifetime bounds and a private 60-byte frame-layout literal instead of deriving them from P0 interfaces.
Task 6: review open — Important `--check` ignores unexpected fixture-tree entries; update mode must fail closed and require manual removal, consistent with the prior non-destructive publication ruling.
Task 6: minor (deferred): determinism regression does not explicitly guard hostname/getpass/datetime/urandom/secrets/arbitrary-environment access.
Task 6: minor (deferred): home-path safety regression does not cover Windows/backslash path spellings.
Task 6: minor (deferred): path-based managed-parent checks do not close an actively concurrent directory-swap race; accepted for the repository fixture-generator threat model.
Task 6: minor (deferred): unconditional `os.O_NOFOLLOW` is not portable to every Python platform supported by Python itself; current project/runtime support needs final triage.
Task 6: fix round 1/5 (3 addressed, 0 open; commits 53c522c..2070e15)
Task 6: complete (commits 395bb6e..2070e15, review clean; 4 deferred minors)
Task 7: review open — Important AST resolver treats absolute `ImportFrom` as package-relative and misses common forbidden v2 imports.
Task 7: review open — Important runtime proof does not dispatch the configured `hackbot.cli.main:app` entrypoint and its risk assertion is tautological.
Task 7: review open — Important protocol documentation renders the wire magic incorrectly and truncates the replay-retention rule.
Task 7: review open — Important roadmap mixes a historical v1 test-count snapshot with current P0 Ready status before Task 8 verification.
Task 7: minor (deferred): public protocol interface map omits `FrameType`.
Task 7: fix round 1/5 (4 addressed, 0 open; commits 9a7cb17..b0b8d49)
Task 7: complete (commits 2070e15..b0b8d49, review clean; 1 deferred minor)
Task 8: gate blocked before checkbox updates — `ruff format --check .` found five files; all other initial gates passed, including 1151 passed/1 skipped, strict OpenSpec validation, publication guard, and no secret-scan matches.
Task 8: root cause — the base plan's Python code blocks and four P0 files from Tasks 2/4/5 were never normalized by the repository-wide Ruff 0.16 formatter; prior task gates ran lint/focused format checks but not the final whole-tree format gate.
Task 8: remediation — exact five-path Ruff formatting only; all fresh gates passed at 1151 passed/1 skipped; OpenSpec tasks 1.1–8.1 checked in commit 5e87d51, 8.2 correctly remains open.
Task 8: minor (deferred): ignored task-8 report labels `b0b8d49` as current worktree state instead of dispatch base; committed HEAD is `5e87d51`.
Task 8: in-repo gate complete (commits b0b8d49..5e87d51, scoped review clean; external review/publication/archive item 8.2 pending).
Final review: Important — safe-pattern matcher admits valid worst cases taking ~8.4 seconds because the operation ceiling is theoretical rather than a production-sized linear bound.
Final review: Important — generated schemas omit a root machine-readable prerequisite for `hackbot-canonical-json-v1`, allowing standard-schema success to be mistaken for complete primitive validation.
Final review: Important — authority spec mandates `INVALID_SCHEMA` in two branches although that value is absent from the closed `ReasonCode` registry.
Final review: Important — confirmed authority projection does not bind all runner trust roots accepted/required by the runner and remote protocol contracts.
Final review: Important — broad identifier grammar conflicts with canonical snake-case mapping keys for parameter/secret/target bindings and placeholder IDs.
Final review: minor selected for final fix wave — publish schema manifest last; remove short-read chunk-object amplification; remove private `[-60:]` fixture assertion; align set-like checkbox evidence; document public `FrameType`.
Final review: deferred triage — all 13 previously deferred implementation observations remain safe to defer; no prior deferred item independently blocks merge.
Final review: single fix wave complete — five Important plus five selected Minor findings resolved in commit 4173929.
Final review: scoped re-review PASS — 10/10 addressed, 0 new Critical/Important, spec compliance PASS, ready to merge YES.
Task 8: complete for pre-merge delivery (commits b0b8d49..4173929, full gates 1157 passed/1 skipped, review clean; OpenSpec 8.2 remains open for GitHub handoff, merge, and post-merge archive).
Final review fix wave: RED — 13 expected focused failures reproduced missing matcher byte/complexity enforcement, binding/projection registries, reason/spec consistency, canonical schema annotations, runner trust tuple, manifest-last semantics, bounded exact-read memory, and public protocol documentation.
Final review fix wave: I1-I5 resolved in the isolated dependency-free P0 contract; no loader, normalizer, binder, policy, SSH, replay, permit, subprocess, or v2 activation implementation added.
Final review fix wave: M1-M5 resolved; schema/fixture artifacts regenerated by their code-owned scripts and OpenSpec 8.2 remains unchecked.
Final review fix wave: GREEN — 245 focused engagement-v2 tests passed; exhaustive matcher/reference comparison covered 50,673 cases; full suite 1,157 passed and 1 skipped; schema/fixture checks, strict OpenSpec, Ruff check/format, mypy, publication guard, secret scan, and diff check passed.
Final review fix wave: committed as 4173929 (`fix: resolve engagement v2 final review findings`); no push, PR, GitHub mutation, or archive performed.
