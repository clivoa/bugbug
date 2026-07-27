# Task 4 report: code-owned schemas and drift-proof exporter

## Status

Task 4 is implemented and committed as `1f100cf` (`feat: publish engagement
v2 schemas`). The report itself is intentionally excluded from that commit,
per the recovery instruction to commit only the Task 4 deliverables.

## Recovery history and preserved WIP

This task was recovered from untracked WIP after its first implementer reached
the usage limit. I inspected, retained, and verified the existing generator,
exporter, test module, and generated JSON before editing. The WIP already
consumed the reviewed `RunnerRole` enum from `e8dde50`; no runner-role literals
were duplicated in the generator.

The recovery handoff recorded a remote-schema local-reference failure caused by
a shared definition being misplaced. The inspected generator already had
`digest` in the remote schema's `$defs`, so the earlier narrow `$defs` test was
green. I replaced it with a generic JSON-Pointer integrity regression that
resolves every local `#/...` `$ref` against its owning document.

## RED/GREEN evidence

### Original recovery checkpoints (not trusted without rerun)

- The original author recorded RED collection failures for the missing schema
  module and then missing exporter module.
- They reported a 16-test focused GREEN, generation/check, Ruff, mypy, JSON,
  and manifest-hash checks, followed by security hardening regressions.
- Per the handoff, none of those claims was accepted as final evidence; the
  gates below were rerun in this recovery.

### Local-reference regression

1. Added `test_every_local_json_pointer_reference_resolves_within_its_document`.
2. To witness the recorded failure despite the preserved WIP already containing
   its repair, temporarily removed only the remote schema's `digest` definition.
3. Ran:

   ```text
   .venv/bin/python -m pytest tests/engagement_v2/test_schemas.py::test_every_local_json_pointer_reference_resolves_within_its_document -q
   ```

   RED: the test failed with four unresolved
   `('remote-header.schema.json', '#/$defs/digest')` references.
4. Restored the shared definition in the remote generator and reran the same
   test: GREEN (1 passed).
5. Reran the focused suite at that checkpoint: GREEN (19 passed).

### Check-mode symlink hardening

Self-review found that write mode rejected symlink destinations and parents,
but `--check` treated them as ordinary drift. The global Task 4 requirement is
to reject symlink destinations and symlinked parents, so test coverage was
extended to both modes.

1. Added `--check` variants for final-path, destination-directory, and
   parent-directory symlinks.
2. Ran the affected tests before the exporter change:

   ```text
   .venv/bin/python -m pytest \
     tests/engagement_v2/test_schemas.py::test_exporter_rejects_symlink_destinations \
     tests/engagement_v2/test_schemas.py::test_exporter_rejects_a_symlinked_destination_parent -q
   ```

   RED: three `--check` parameterizations did not raise and reported all files
   as drift instead.
3. Added component rejection before check-mode reads and per-file symlink
   rejection in `_drifted_files`.
4. Reran the affected tests: GREEN (6 passed), then the focused suite: GREEN
   (22 passed).

## Deliverables

- `src/hackbot/engagement_v2/schemas.py`
  - Fresh Draft 2020-12 schema documents for program, scope, authorization,
    actions, action request, runner, and remote headers.
  - Strict object helper, local `$defs`, stable URNs, constants/enums imported
    from the engagement-v2 contract modules, deterministic JSON rendering, and
    a final manifest with sorted filenames and SHA-256 hashes.
- `scripts/export_engagement_v2_schemas.py`
  - Default atomic per-file export using exclusive `0600` sibling temporaries,
    file and directory fsync, replace, and cleanup.
  - Rejects symlink destinations, output files, and parent components in both
    write and check modes. `--check` writes nothing and reports sorted drift.
- `tests/engagement_v2/test_schemas.py`
  - Contract assertions, local-reference integrity regression, deterministic
    bytes/manifest assertions, and exporter safety/drift tests.
- `schemas/engagement-v2/`
  - Generated schema artifacts and `manifest.json`.

## Fresh verification

All commands below were run after the repairs and artifact regeneration:

```text
.venv/bin/python scripts/export_engagement_v2_schemas.py
.venv/bin/python scripts/export_engagement_v2_schemas.py --check
.venv/bin/python -m pytest tests/engagement_v2/test_schemas.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/schemas.py scripts/export_engagement_v2_schemas.py tests/engagement_v2/test_schemas.py
.venv/bin/mypy src/hackbot/engagement_v2/schemas.py
.venv/bin/python -m pytest
```

Results:

- Focused schema tests: `22 passed`.
- Ruff: `All checks passed!`.
- Mypy: `Success: no issues found in 1 source file`.
- Full suite: `1052 passed, 1 skipped` in 18.32 seconds.

An independent stdlib inspection parsed all seven generated schema documents,
resolved every local `$ref`, verified the manifest's sorted file list and
schema IDs, and recomputed every listed SHA-256 hash: `validated 7 schema JSON
documents and manifest hashes`.

## Self-review

- Confirmed the generator imports its versions, bounds, regex sources, and
  closed enums from existing engagement-v2 constants, including `RunnerRole`.
- Confirmed every explicit `type: object` schema is closed with
  `additionalProperties: false`; conditional schemas are intersected with those
  closed base object schemas rather than defining permissive payload objects.
- Confirmed no runtime JSON Schema or Pydantic dependency was introduced and
  no schema-level permission-granting default is emitted.
- Confirmed generated artifact bytes equal `render_schema_files()` output,
  local references resolve, and manifest hashes are correct.
- Confirmed exporter tests exercise atomic replacement failure cleanup, 0600
  files, fsync, zero-write drift checking, missing destinations, and symlinked
  final paths/directories/parents in both exporter modes.
- Ran `git diff --check` against each Task 4 source/test file; no whitespace
  errors were reported.

## Concerns

No open Task 4 concerns. The existing conditional JSON Schema fragments use
partial `properties` views only to constrain already-closed base objects; they
do not introduce additional payload object shapes. A separate read-only review
was requested as an additional check but did not return findings within this
task's completion window; the recorded self-review and fresh verification are
the evidence for this commit.

---

## Fix round 1: descriptor-pinned exporter and enforcement contracts

### Root cause and RED/GREEN evidence

The prior exporter checked `Path` names and then later read, created temporary
files, and replaced by path. A symlink or directory swap could therefore occur
between check and use. Check mode also examined expected names only, ignoring
unexpected regular entries and symlinks.

Before production changes, added focused tests for every approved finding and
ran the nine-test set. RED: all nine failed, showing missing uniqueness,
pattern-format, UTF-8-byte, canonical-nonce, and protocol-derived-URN
contracts; ignored unexpected entries; unused deterministic race hooks; and no
fail-closed behavior without `O_NOFOLLOW`.

After implementation, the same set was GREEN (`9 passed`). The first full
Task 4 run exposed intended schema-byte expectation/artifact updates and one
test-double signature mismatch for descriptor-relative `os.replace`; those
were corrected, artifacts regenerated, and the focused suite was GREEN (`30
passed`).

### Implementation

- On POSIX the exporter walks every destination component with pinned
  `O_DIRECTORY|O_NOFOLLOW` descriptors, creating only with `mkdir(dir_fd)`.
  It fails closed when required descriptor-safe primitives are unavailable.
- All entry reads, exclusive 0600/O_NOFOLLOW temporary writes, cleanup, and
  `os.replace(src_dir_fd=..., dst_dir_fd=...)` calls are relative to the same
  pinned destination descriptor. Temporary and directory descriptors are
  fsynced.
- Check mode lists that descriptor, reports sorted missing/changed/unexpected
  regular names, rejects expected or unexpected symlinks, and performs no
  writes. Deterministic test seams swap the public destination path between
  check/use and before replacement; both modes keep operating on the original
  pinned directory and leave the attacker directory untouched.
- Actions and remote frames publish `x-hackbot-unique-by: id` and `index`.
  Pattern-bearing parameters require `pattern_format` and publish
  `format: hackbot-safe-fullmatch-v1`. Every bounded string publishes exact
  `x-hackbot-max-utf8-bytes`; negative examples document why standard JSON
  Schema alone does not supply these P0-enforcement semantics.
- Remote nonce syntax is now canonical unpadded base64url for 32 bytes:
  `^[A-Za-z0-9_-]{42}[AQgw]$`; invalid final values are tested. The remote
  header URN now derives from `PROTOCOL_VERSION`.

### Fresh verification

Ran after regeneration:

```text
.venv/bin/python scripts/export_engagement_v2_schemas.py
.venv/bin/python scripts/export_engagement_v2_schemas.py --check
.venv/bin/python -m pytest tests/engagement_v2/test_schemas.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/schemas.py scripts/export_engagement_v2_schemas.py tests/engagement_v2/test_schemas.py
.venv/bin/mypy src/hackbot/engagement_v2/schemas.py scripts/export_engagement_v2_schemas.py
.venv/bin/python -m pytest
git diff --check
```

Results before the final report append: Task 4 `30 passed`; Ruff clean; mypy
clean for two source files; full suite `1060 passed, 1 skipped` in 18.05
seconds; no diff-check errors. An independent stdlib inspection parsed all
seven generated schemas, resolved every local reference, and verified sorted
manifest names, schema IDs, and all manifest hashes.

### Self-review and concerns

No open concerns on the supported POSIX path. No runtime validator or new
dependency was added; annotations are contracts for future validators, not P0
runtime enforcement. The exporter intentionally fails closed rather than
falling back on platforms without the descriptor-safe primitive set.

Final fresh rerun after the report edits: Task 4 `30 passed`, full suite
`1060 passed, 1 skipped` in 17.90 seconds, with generate, `--check`, Ruff,
mypy, independent JSON/reference/hash inspection, and `git diff --check`
all clean. Committed as `81617c5` (`fix: harden engagement v2 schema export`).

---

## Fix round 2: temporary publication identity and nonregular entries

### Scoped findings and RED/GREEN evidence

The scoped re-review found two remaining blockers in the descriptor-pinned
exporter: its temporary descriptor was closed before publication and therefore
could not prove the named temporary or final entry was the file it wrote; and
entry reads could block on FIFOs/devices because they did not include
`O_NONBLOCK` or reject all nonregular entries.

Added tests before production changes, then ran:

```text
.venv/bin/python -m pytest \
  tests/engagement_v2/test_schemas.py::test_exporter_rejects_substituted_temporary_entry_before_publish \
  tests/engagement_v2/test_schemas.py::test_exporter_rejects_final_name_symlink_injected_before_replace \
  tests/engagement_v2/test_schemas.py::test_exporter_rejects_fifo_entries_without_blocking -q
```

RED: five failures. Temporary substitution and final-name symlink insertion
were silently accepted. The three FIFO variants (expected `--check`,
unexpected `--check`, and existing write target) demonstrated missing
`O_NONBLOCK` via a deterministic guard before any FIFO could block.

Added a direct post-replace substitution regression too. Its dedicated RED
failed because the injection hook was not observed; after adding the hook and
the final identity check it was GREEN. The complete blocker set was GREEN (`6
passed`), followed by the Task 4 suite (`36 passed`).

### Implementation and self-review

- The exclusive temporary descriptor stays open from creation through final
  verification. Content is written with bounded `os.write` calls and fsynced
  without closing that descriptor.
- Immediately before relative `os.replace`, the exporter opens the temporary
  name through the pinned descriptor with `O_NOFOLLOW`, compares its
  `(st_dev, st_ino)` to the still-open temporary descriptor, and rejects any
  substitution. The final-name preflight is performed after the pre-replace
  hook, so an injected symlink is rejected instead of atomically replacing it.
- After replace, the final name is opened no-follow and compared to the same
  still-open temporary descriptor. A mismatch (including a nonregular/symlink
  publication) is removed with descriptor-relative `unlink`, which does not
  follow the substituted name, then fails closed.
- Descriptor-relative read flags include `O_NONBLOCK` when available.
  Expected entries, unexpected check-mode entries, and write preflight entries
  must all be regular files after `fstat`; FIFO/device entries fail before any
  blocking read.
- The temporary, final-symlink, final-substitution, and FIFO tests prove the
  intended behavior deterministically. The test guard intercepts a missing
  `O_NONBLOCK` flag rather than allowing a RED run to hang.

No out-of-scope observations were changed in this round.

### Fresh verification

```text
.venv/bin/python scripts/export_engagement_v2_schemas.py
.venv/bin/python scripts/export_engagement_v2_schemas.py --check
.venv/bin/python -m pytest tests/engagement_v2/test_schemas.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/schemas.py scripts/export_engagement_v2_schemas.py tests/engagement_v2/test_schemas.py
.venv/bin/mypy src/hackbot/engagement_v2/schemas.py scripts/export_engagement_v2_schemas.py
.venv/bin/python -m pytest
git diff --check
```

Results: Task 4 `36 passed`; Ruff clean; mypy clean for two source files; full
suite `1066 passed, 1 skipped` in 18.55 seconds; no diff-check errors. An
independent stdlib inspection again parsed all seven generated documents,
resolved local references, and verified every manifest hash and schema ID.

### Concerns

No open concern for the two scoped blockers. Out-of-scope observations remain
ledgered for final triage, as directed.

Committed separately as `5ed72b7` (`fix: verify schema export publication`).
