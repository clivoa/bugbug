# Independent review — Task 6

Reviewed range: `395bb6e..53c522c`

Spec compliance: FAIL

Task quality: WITH FIXES

The implementation gets the central happy path right: it exposes the required
typed `generate(root: Path, *, check: bool) -> tuple[str, ...]`, constructs the
seven expected values before filesystem comparison, orders the managed relative
paths, performs read-only `--check`, returns/prints drift, exits 1 for CLI
drift, regenerates the currently approved bytes through the canonical, pattern,
and protocol P0 modules, and introduces no core dependency or forbidden P0
import. The range contains only the generator and its focused tests.

The verdict is nevertheless failing because the generator duplicates public P0
bounds/protocol details instead of consistently consuming them, and because its
update path can follow repository-controlled symlinks outside the fixture root.
The reproducibility check also has a false-clean case for unexpected fixture
files.

## Critical

None.

## Important

1. `scripts/generate_engagement_v2_contract_fixtures.py:179` — update mode is
   not confined to the requested fixture tree when symlinks are present.

   Impact: `_atomic_write` follows a pre-existing predictable
   `.<name>.tmp` symlink when it opens the temporary path at line 182, so running
   regeneration can truncate and overwrite the symlink target before
   `os.replace`. Symlinked managed parent directories are followed as well.
   Separately, `generate` uses `is_file()`/`read_bytes()` at lines 194–195, so a
   destination symlink to a matching external file is accepted as clean. A
   branch or copied fixture tree can therefore make this repository utility
   read or write outside `root`. This is material even for a developer tool:
   the script writes with the invoking developer/CI account's permissions.

   Concrete fix: resolve or open `root` once, reject symlinks/non-directories in
   every managed parent component with `lstat` (and reject symlink destinations
   in check mode), create the sibling temporary file with an unpredictable
   `tempfile.mkstemp(..., dir=path.parent)`/exclusive descriptor, clean it in a
   `finally`, and retain sibling `os.replace` publication. Add focused tests
   proving that a symlinked destination, parent, and would-be staging entry do
   not touch their external targets.

2. `scripts/generate_engagement_v2_contract_fixtures.py:131` — public P0 bounds
   and a private wire-layout size are duplicated as literals.

   Impact: the nonce uses literal `32` even though `NONCE_BYTES` is a public P0
   constant, the fixed 12:00–12:05 window at lines 132–133 encodes the public
   `MAX_REQUEST_LIFETIME_SECONDS == 300` bound, and the `[-60:]` extraction at
   line 167 encodes the current private frame-prefix size plus payload length.
   A legitimate P0 contract evolution can therefore leave regeneration stale,
   make `FramedMessage` fail before regeneration, or silently truncate/include
   unrelated bytes in `request-frame.bin`. This conflicts with the binding
   requirement that consumed versions and bounds come from already-public P0
   interfaces; importing only `PROTOCOL_VERSION` is insufficient.

   Concrete fix: import and use `NONCE_BYTES` and
   `MAX_REQUEST_LIFETIME_SECONDS` from `engagement_v2.constants` while retaining
   the fixed issue instant. Remove the magic frame length by deriving the frame
   suffix from the serialized message and its already-computed canonical header
   with explicit uniqueness/boundary validation, or use a public P0 frame
   serializer if one is intentionally added by the P0 owner. Add a focused test
   that the standalone frame is exactly the complete frame suffix, not merely
   the last 60 bytes.

3. `scripts/generate_engagement_v2_contract_fixtures.py:190` — `--check`
   ignores unexpected files below the managed fixture root.

   Impact: `differing` iterates only the generated mapping. For example, a
   stale `canonical/old-contract.json` or `patterns/obsolete.json` can remain in
   the committed corpus while `generate(root, check=True)` and the CLI report a
   clean tree. The protocol test happens to enumerate its immediate directory,
   but the canonical and pattern tests do not; the new clean-tree test at
   `tests/engagement_v2/test_fixture_generation.py:34` cannot expose the case
   because it starts from the currently approved tree. This weakens the fixture
   corpus reproducibility guard and the promise to return divergent relative
   paths.

   Concrete fix: enumerate regular entries under the managed root without
   following symlinks, compare the actual relative-path set with
   `generated.keys()`, and merge missing/changed/unexpected paths into one
   sorted tuple. Define update-mode handling explicitly: either remove only
   safely confined unexpected regular fixture files so a subsequent check is
   clean, or fail closed and require manual removal. Add clean/check/update
   coverage for an unexpected file.

## Minor

1. `tests/engagement_v2/test_fixture_generation.py:94` — the process-state test
   does not directly exercise several determinism sources named by the
   requirement.

   Impact: it changes cwd, `HOME`, `USER`, `time.time`, and
   `random.getrandbits`, but it does not guard hostname APIs, `getpass.getuser`,
   `datetime.now`, `os.urandom`/`secrets`, or reads of arbitrary environment
   keys. The current implementation is deterministic by inspection, but a
   future regression through one of those APIs could still pass this test while
   its name and report overstate the evidence.

   Concrete fix: monkeypatch the named process-state APIs to raise on access and
   compare output under two scrubbed/replaced environment mappings. Keep the
   byte-for-byte comparison already present.

2. `tests/engagement_v2/test_fixture_generation.py:133` — the home-path safety
   assertion recognizes only slash-delimited Unix `/home/` and `/users/`
   spellings.

   Impact: Windows forms such as `C:\Users\name\...` or backslash-delimited home
   paths would pass even though the requirement excludes user home paths. The
   present fixtures contain no such path, so this is a guard-coverage issue
   rather than current fixture leakage.

   Concrete fix: normalize separators before checking or use a case-insensitive
   expression covering both `/` and `\`, including optional Windows drive
   prefixes, and add representative Unix and Windows negative cases.

## Verification notes

- The supplied diff and commit metadata confirm that no core runtime source or
  dependency changed and that the range does not touch `hackbot.programs`,
  `hackbot.risk`, `hackbot.scope`, `hackbot.tools`, or `hackbot.cli`.
- Existing frozen tests in the parent revision retain the exact canonical,
  pattern, protocol fixture checks and protocol SHA-256 values; Task 6 adds an
  empty-tree byte-for-byte regeneration comparison.
- `git diff --check 395bb6e..53c522c` is clean.
- Per the review instruction, broad gates were not rerun.
- ⚠️ Cannot verify from diff: the temporal claim that the focused test first
  failed before implementation, and the freshness/raw output of the reported
  final focused and broad gates. The author report states these events and exit
  statuses, but the review package contains no raw command transcript.

