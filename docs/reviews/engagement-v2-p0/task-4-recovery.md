# Task 4 recovery handoff

The original Task 4 implementer exhausted its usage limit before committing or
writing `task-4-report.md`. Preserve and inspect the current untracked WIP:

- `src/hackbot/engagement_v2/schemas.py`
- `scripts/export_engagement_v2_schemas.py`
- `tests/engagement_v2/test_schemas.py`
- `schemas/engagement-v2/**`

Recorded checkpoints from the original implementer:

1. The initial focused test collection failed with the expected
   `ModuleNotFoundError` for `hackbot.engagement_v2.schemas`.
2. After adding the schema generator, collection advanced and failed with the
   expected missing `scripts.export_engagement_v2_schemas`.
3. Task 1 was temporarily reopened to add the closed `RunnerRole` enum. Commit
   `e8dde50` is reviewed and available; Task 4 must consume it rather than
   duplicate runner-role literals.
4. The first GREEN had 16 focused tests passing; real generation plus
   `--check`, Ruff, and mypy passed. Generated JSON parsed and manifest hashes
   matched independently.
5. Self-review added and reportedly made GREEN regressions for:
   - nesting-depth annotation;
   - exact whole-token placeholder schema;
   - raw nonce-size annotation;
   - symlinked parent-directory rejection;
   - the `not-applicable` rate-control relationship;
   - Windows-style retained-output traversal.
6. Artifact inspection then found an unresolved local `$ref` in the remote
   schema caused by a misplaced shared definition. The implementer intended to
   add a generic local-reference integrity regression before correcting it.
7. No blocker or unresolved schema ambiguity was reported. The approved
   detailed v2 design supplied document nesting where the capability specs
   delegated that detail to P0.

Recovery requirements:

- Treat all prior GREEN claims as unverified until rerun.
- Inspect the existing WIP before changing it.
- First add/run the generic local `$ref` integrity test and confirm it fails
  for the known remote-schema defect.
- Correct the generator, regenerate all committed schemas, and rerun every
  Task 4 focused/exporter/static/full-suite gate.
- Preserve strict TDD evidence in the final report, including this recovery
  history and any new RED/GREEN cycles.
- Commit only the prescribed Task 4 files after self-review.
