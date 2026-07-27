# Task 6 scoped re-review — fix round 1/5

Reviewed fix range: `53c522c..2070e15`

Overall: PASS

New Critical/Important breakage: NONE

## Prior Important 1 — symlink escape

Verdict: ADDRESSED

The fix now rejects a symlink/non-directory root and symlink/non-directory
managed parent components through `_directory` and `_managed_parent`. Managed
destinations are inspected with `lstat`; reads use `O_NOFOLLOW` and verify the
opened descriptor is regular. Update mode replaces the predictable
`.<name>.tmp` staging path with an exclusive, unpredictable sibling created by
`tempfile.mkstemp`, checks the destination again immediately before
publication, publishes with sibling `os.replace`, and cleans staging state in a
`finally`.

The fix diff adds focused coverage for:

- a symlink used as the fixture root;
- a managed destination symlink whose external target already has matching
  bytes;
- a managed parent-directory symlink;
- the previously exploitable predictable staging symlink, including proof that
  its external target is unchanged.

These tests cover the static repository-controlled symlink cases from the
original Important and verify external targets are not modified.

Minor/deferred, outside this fix loop: the path-based parent checks still do not
provide descriptor-relative protection against an actively concurrent
directory-swap race, and unconditional `os.O_NOFOLLOW` is not portable to every
Python platform. Neither is a new Critical/Important regression for the
repository fixture-generator threat model reviewed here.

## Prior Important 2 — duplicated P0 bounds/private frame length

Verdict: ADDRESSED

The generator now imports and uses `NONCE_BYTES` and
`MAX_REQUEST_LIFETIME_SECONDS` alongside `PROTOCOL_VERSION`. The fixed issue
instant remains deterministic, while expiry is derived from the public
lifetime bound.

The private `[-60:]` assumption is removed. The generator computes the
canonical header once, requires that it occur exactly once in the serialized
public `write_message` output, requires a non-empty suffix, and stores the full
suffix after that header as `request-frame.bin`.

The new focused protocol fixture test proves that the frozen frame equals the
complete message suffix after the unique canonical header boundary, so the test
no longer shares the private 60-byte assumption with the implementation.

## Prior Important 3 — unexpected fixture entries

Verdict: ADDRESSED

`_fixture_entries` enumerates the actual fixture tree with `lstat` and without
following symlink entries. `generate` merges unexpected actual paths with
missing/changed managed paths and returns one sorted tuple.

Update mode writes only `managed_differences`; it therefore reports unexpected
entries in the returned tuple and preserves them, matching the binding ruling
instead of deleting them. Check mode reports the same entries, and the existing
CLI path prints them and exits 1.

The fix diff adds:

- API assertions that an unexpected file is reported by both check and update
  modes and remains byte-identical;
- a CLI assertion that the unexpected path is included in the correctly sorted
  drift output;
- continued no-write comparison of the whole copied tree.

## New breakage review

No new Critical or Important breakage was introduced by
`53c522c..2070e15`. The changes remain scoped to the fixture generator and its
focused tests. They do not modify P0 runtime behavior, dependencies, fixture
bytes, or forbidden package boundaries.

## Evidence limitation

Per instruction, broad gates were not rerun. The appended implementer report
records a five-failure RED run, a 13-test focused GREEN run, a 171-test combined
focused run, clean lint/type checks, successful generator update/check, and
clean `git diff --check`.

⚠️ Cannot verify from diff: the actual command execution, temporal RED/GREEN
order, and raw gate output. The fix diff itself contains the asserted regression
tests and the corresponding implementation paths described above.

