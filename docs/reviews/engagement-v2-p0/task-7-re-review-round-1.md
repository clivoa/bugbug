# Task 7 scoped re-review — fix round 1/5

Review scope: reconciled `task-7-report.md` and fix diff
`9a7cb17..b0b8d49` only.

## Prior Important verdicts

1. AST absolute/relative `ImportFrom`: **ADDRESSED**

   `tests/engagement_v2/test_v1_isolation.py` now starts absolute
   `ImportFrom` resolution with an empty base and uses the importing package
   only when `node.level > 0`. The added regression matrix covers all four
   required forms:

   - `import hackbot.engagement_v2`;
   - `from hackbot.engagement_v2 import ContractError`;
   - `from hackbot import engagement_v2`;
   - `from ..engagement_v2 import ReasonCode`.

   Each form is covered from a normal module and from a package
   `__init__.py`. The expectations verify both the forbidden package module
   and the imported member where applicable.

2. Runtime entrypoint proof: **ADDRESSED**

   The child interpreter now calls the configured CLI entrypoint through
   `cli_main.app(["version"])`, performs schema validation and a real scope
   decision, builds a valid L0 request/context, calls
   `RiskEngine.evaluate(...)`, and requires an `ALLOW` decision. It also
   retains the portable `CommandRunner(sys.executable, "-c", "pass")`
   exercise and the final `sys.modules` check for the forbidden package.
   Child checks use explicit conditional `SystemExit` failures, so optimizer
   removal of `assert` statements cannot suppress the exercises.

3. Exact magic and replay retention: **ADDRESSED**

   `docs/engagement-v2-contracts.md` now gives the eight-byte magic as
   `b"HBV2RUN\x00"` with one escape introducer. It states that P4 retains the
   replay reservation for 600 seconds after expiry or until a longer
   in-progress run finalizes. The adjacent boundary still explicitly says no
   replay cache exists in P0. Focused documentation assertions cover the
   corrected magic and both retention clauses.

4. Roadmap verification status: **ADDRESSED**

   `docs/next-steps.md` now labels 912/913 as a historical v1 snapshot that
   predates P0, separates the current P0 Ready status into its own section,
   keeps P1–P7 dependent, and explicitly says Task 8 full verification and
   delivery remain pending. It publishes no replacement full-suite count.
   A focused assertion covers the historical-section label and pending Task 8
   statement.

## New breakage

New Critical breakage: **NONE**

New Important breakage: **NONE**

The fix diff changes only the isolation test and the two documents needed to
resolve the four prior Important findings. No production runtime or OpenSpec
file is touched in this fix round.

The prior Minor concerning `FrameType` is deliberately outside this scoped
loop and was not reconsidered.

## Verification boundary

The reconciled report records nine focused tests and the listed focused
quality/drift checks as passing. Per instruction, this re-review did not rerun
broad gates; those recorded executions are not independently established by
the diff alone. The test implementations and their coverage claims are
directly present in the reviewed fix diff.

## Final ruling

Fix round 1: **PASS**
