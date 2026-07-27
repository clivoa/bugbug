# Task 6 report: fixture regeneration and reproducibility guard

## RED/GREEN

- RED: `.venv/bin/python -m pytest tests/engagement_v2/test_fixture_generation.py -q`
  failed during collection with the expected `ModuleNotFoundError` for
  `scripts.generate_engagement_v2_contract_fixtures`.
- GREEN: the same behavioral suite passed after adding the generator.

## Reproducibility and no-write evidence

- `generate(root, check=True)` accepts a copied clean fixture tree without
  modifying any bytes.
- A changed `canonical/authority-digest.txt` returns exactly
  `("canonical/authority-digest.txt",)` and preserves the changed bytes.
- CLI `--check` returns 1, prints sorted relative paths, and makes no writes
  when two paths are drifted; it rejects every option other than `--check`.
- Update mode from an empty tree recreates every approved fixture byte.
- Varying cwd, HOME, USER, `time.time`, and `random.getrandbits` produces the
  same generated tree.
- The generated corpus is checked for secret/password/token strings, every
  RFC1918 prefix, user-home path prefixes, and domains outside
  `example.invalid` (with the defined non-domain action identifier
  `operator.fixture` allowed).

The generator builds the complete path-to-bytes mapping before comparing it;
comparison and update loops sort relative paths. Update writes a sibling
temporary file followed by `os.replace`; check mode only reads fixture bytes.

Approved fixture SHA-256 values after regeneration:

| Path | SHA-256 |
| --- | --- |
| `canonical/authority-input.json` | `ae0b0ea909b44f667b1a4834e1ff5d9402379fffa7a7a0b6d2f139caed32d925` |
| `canonical/authority-canonical.json` | `6b86affbe1d4beb79aecdb431fece5f05c903a37af820cb6a68a3ed655373f24` |
| `canonical/authority-digest.txt` | `6f0e8303cd8f403da8e0160f6104a58d35ed601c39f6de9b0cba89fe509d9153` |
| `patterns/cases.json` | `1d2630a6af70ece0e89a8d543a359906e96458bc51cd4048b10de7d328201771` |
| `protocol/request-frame.bin` | `4bb15f8f8b9731fe3169e4f948263c5c3ce8b33b3106d828adbae091b0e4064b` |
| `protocol/request-header.json` | `50ec1ad9750fdc919b0ce8358d0bfe47425dacf417ec5271fbf21de9f4b7e096` |
| `protocol/request-message.bin` | `332d44b38bb1730f4ce6fe11f671b62f95b0309e16fd0f7b98e90c9c1080fdd9` |

`git diff -- tests/fixtures/engagement_v2` was empty after update/check.

## Gates

- `python scripts/generate_engagement_v2_contract_fixtures.py` — exit 0
- `python scripts/generate_engagement_v2_contract_fixtures.py --check` — exit 0
- Focused fixture/canonical/pattern/protocol pytest suite — exit 0
- `ruff check .` — exit 0
- Repository-normal `mypy src` — exit 0
- Scoped `mypy --explicit-package-bases scripts/generate_engagement_v2_contract_fixtures.py tests/engagement_v2/test_fixture_generation.py` — exit 0
- Full `python -m pytest -q` — exit 0

## Self-review and concerns

- Reviewed the complete new-script and new-test diffs plus `git diff --check`;
  no issue found.
- The repository intentionally has no `scripts/__init__.py`. Plain scoped mypy
  discovers the script both as a top-level module and a namespace-package
  member, so the scoped check uses `--explicit-package-bases`; the repository
  normal gate remains `mypy src`.
- No fixture semantic mismatch was exposed, so no approved fixture bytes were
  changed.

## Fix round 1/5

### RED

Added regression coverage for root, managed-parent, managed-destination, and
predictable staging symlinks; unexpected fixture entries in API and CLI checks;
and protocol-frame suffix boundaries. Before the correction:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_fixture_generation.py -q
..FFFFF.....
5 failed, 7 passed
```

The failures demonstrated that destination and parent symlinks were accepted,
the predictable staging symlink overwrote its external target, and extra paths
were omitted from API and CLI drift output.

### GREEN

- Managed root, parent, and destination components use `lstat` and reject
  symlinks or non-directories/non-regular files. Reads additionally use an
  `O_NOFOLLOW` descriptor.
- Update creates exclusive unpredictable sibling staging files with
  `tempfile.mkstemp`, cleans them in `finally`, and publishes through
  `os.replace` only after a final destination check.
- Check and update enumerate entries with `lstat`, merge missing/changed and
  unexpected paths into one ordered result, and leave extras untouched in
  update mode.
- The protocol fixture now derives its full frame suffix from the unique
  canonical-header boundary in the serialized message. It imports
  `NONCE_BYTES` and `MAX_REQUEST_LIFETIME_SECONDS` for the P0-derived values.

Commands and results:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_fixture_generation.py -q
13 passed

.venv/bin/ruff check scripts/generate_engagement_v2_contract_fixtures.py tests/engagement_v2/test_fixture_generation.py
All checks passed!

.venv/bin/mypy --explicit-package-bases scripts/generate_engagement_v2_contract_fixtures.py tests/engagement_v2/test_fixture_generation.py
Success: no issues found in 2 source files

.venv/bin/python -m pytest tests/engagement_v2/test_fixture_generation.py tests/engagement_v2/test_canonical.py tests/engagement_v2/test_patterns.py tests/engagement_v2/test_protocol.py -q
171 passed

.venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py
.venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py --check
both exit 0

git diff --check
exit 0
```
