# Task 5 report: allocation-bounded remote framing and run binding

## Status

Task 5 is implemented and committed as `59cb233`
(`feat: add bounded remote framing contract`). The commit contains only the
prescribed protocol module, protocol tests, and three protocol fixtures. The
report and the pre-existing untracked `.venv` are intentionally excluded.

## Approved contract and resolved illustration drift

The generated remote-header schema and approved OpenSpec contract govern the
request header. The plan's illustrative helper used stale field names
(`argv_projection`, `executable_path`, `executable_digest`, and
`frame_descriptors`). Per the operator ruling, the implementation, tests, and
fixtures consistently use the generated schema's exact `argv`, nested
`executable`, and `frames` fields. The approved schema was not changed. A
regression rejects both unknown fields and the stale illustrative shape.

## RED/GREEN evidence

### Missing-module RED

After creating `tests/engagement_v2/test_protocol.py` and before creating
production code, ran:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_protocol.py -q
```

Collection failed with exit 2 and:

```text
ModuleNotFoundError: No module named 'hackbot.engagement_v2.protocol'
```

This was the required missing-module RED.

### Framing and run-binding GREEN

Implemented `protocol.py` with the exact `!8sHIH` 16-byte message prefix and
`!HQ32s` 42-byte frame prefix, immutable exact values, bounded exact reads,
canonical header decoding, request/response direction checks, descriptor and
payload binding, run binding, expiry/echo validation, and the response hash
chain. The initial focused implementation run was GREEN at 56 tests.

Two self-review refinements were witnessed RED before their repairs:

- Empty-response direction inference failed because a zero-frame message was
  initially inferred as a request.
- The valid generated-schema placeholder `{target:primary}` was initially
  rejected by an overly narrow argv check.

The affected run reported `2 failed`; after header-based empty-direction
inference and the exact generated placeholder grammar were added, the same two
tests passed.

### Fixture RED/GREEN

The deterministic fixture test first failed with `FileNotFoundError` for
`tests/fixtures/engagement_v2/protocol`. The fixed synthetic header, frame, and
message were then generated and the dedicated fixture test passed. The final
focused suite is GREEN at 61 tests.

## Allocation-before-read evidence

The tests use instrumented streams, not only final error assertions:

- Header-length cap: a forged 16-byte prefix declares 1,048,577 header bytes.
  The guarded stream records exactly `[(0, 16)]`; no header read occurs.
- Frame-count cap: a forged prefix declares 257 frames. The guarded stream
  again records exactly `[(0, 16)]`; no header read occurs.
- Oversized frame: a descriptor/prefix declares 67,108,865 bytes. Validation
  fails before any payload read.
- Response aggregate cap: a legal per-frame length of 41,943,040 bytes would
  exceed the complete response cap after framing. The decoder reads the fixed
  header and frame prefix, then rejects before the guarded payload offset.
- Request aggregate cap: a synthetic stream supplies one exact 67,108,864-byte
  zero payload without materializing the forged input. The decoder reads and
  hashes all 67,108,864 bytes, reads the second 42-byte prefix, then rejects the
  aggregate before any second-payload read. The guard would raise if that read
  occurred.
- Exact-length behavior is exercised by a stream limited to three-byte chunks,
  plus truncated fixed header, canonical header, frame prefix, and payload
  cases.

The reader starts its aggregate at 16 bytes, checks the applicable
75,497,472-byte request or 41,943,040-byte response cap before each declared
header/frame read, limits a frame to 67,108,864 bytes, and hashes payloads in
65,536-byte chunks.

## Exact fixtures and hashes

The fixtures contain a fixed synthetic UUIDv4, 32 zero nonce bytes encoded as
43-character unpadded base64url, fixed UTC-second times, `example.invalid`
runner/executable identity, and payload `b"synthetic-artifact"`.

The synthetic execution projection produces:

```text
sha256:5012021e9f1b0f2e960ee0ff09e06c61fc6ad0f7df274a420ff78f0905be18a8
```

Prescribed `xxd` inspection showed:

```text
00000000: 4842 5632 5255 4e00 0001 0000 03b3 0001  HBV2RUN.........
...
000003c0: 3630 7d00 0200 0000 0000 0000 128d d6df  60}.............
...
000003f0: 7468 6574 6963 2d61 7274 6966 6163 74    thetic-artifact
```

Exact artifact sizes and SHA-256 values:

```text
request-header.json  947 bytes
2601565df2807994c7867d3cf59b7adf0b481d8e49f89efb65c8c5e54a609786

request-frame.bin     60 bytes
4bb15f8f8b9731fe3169e4f948263c5c3ce8b33b3106d828adbae091b0e4064b

request-message.bin   1023 bytes
c364a6b70086e544c123dd7e50450aefdd8cba9db30b17492802dd996c657854
```

The exact two-frame response-chain vector is:

```text
execution digest: sha256: + 64 "2" characters
frames: (stdout, b"out"), (stderr, b"err")
final chain: 42b00ddbd663cb83b8e064e93a10e171d5c1dc9ebfe123f242d17e44c2804e4c
```

## Fresh verification

Ran on the final tree before commit:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_protocol.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/protocol.py tests/engagement_v2/test_protocol.py
.venv/bin/mypy src/hackbot/engagement_v2/protocol.py
.venv/bin/python -m pytest
git diff --check
```

Results:

- Focused protocol suite: `61 passed`.
- Ruff: `All checks passed!`.
- Mypy: `Success: no issues found in 1 source file`.
- Full suite: `1127 passed, 1 skipped in 17.66s`.
- Diff check: no whitespace errors.

An independent standard-library inspection also:

- parsed the module AST and confirmed its only Hackbot imports are
  `hackbot.engagement_v2.canonical`, `.constants`, and `.errors`;
- confirmed all 18 runtime request-header fields exactly match the generated
  remote-header schema properties;
- unpacked the fixture prefix as magic `b"HBV2RUN\x00"`, version `1`, header
  length `947`, frame count `1`;
- proved the embedded header equals the canonical JSON fixture;
- recomputed all three fixture hashes.

## Self-review

- Confirmed all production imports are standard library or prior approved
  engagement-v2 contract modules. There are no v1 imports.
- Confirmed there is no SSH, socket, helper, replay cache, child process,
  runtime activation, or external dependency.
- Confirmed `Frame` requires exact `FrameType` and exact `bytes`;
  `FramedMessage` requires an exact tuple, rejects mixed direction, validates
  every ordered descriptor, and deep-freezes the copied canonical header.
- Confirmed the writer preflights every header/frame/aggregate bound before
  its first write and rejects short writes.
- Confirmed strict JSON rejects invalid UTF-8, duplicate keys at every object
  level, non-standard constants, non-canonical bytes, wrong magic/version,
  truncation, unknown frame types, digest mismatch, and trailing bytes with
  only `EXEC_PROTOCOL_INVALID`.
- Confirmed UUIDv4 canonical lowercase text, canonical unpadded 32-byte nonce,
  UTC RFC3339 seconds, 1/300-second lifetime boundaries, 301 rejection, and
  exact ±30-second skew behavior.
- Confirmed response echo mismatches produce `EXEC_TRUST_MISMATCH` and expired
  windows produce `EXEC_PROTOCOL_EXPIRED`.
- Performed a mutation check across struct widths/order, cap branches,
  descriptors, hashes, EOF, UUID/nonce/time/digest parsing, echo fields, and
  hash-chain byte order; each realistic mutation is covered by a focused
  assertion.

## Concerns

No open functional or security concern was found in Task 5 self-review. A
separate read-only reviewer was requested as an additional check but did not
return a verdict within the completion window; it was stopped after the fresh
focused, static, independent fixture/schema inspection, and full-suite gates
were complete.

---

## Fix round 1: request execution identity and whole-message preflight

Fix round 1 is committed as `395bb6e`
(`fix: bind remote request framing`).

### Approved normative shape

The operator supplied the previously missing execution-projection contract.
Execution projection v1 is exactly:

```json
{"schema_version":1,"request":<all canonical request-header fields except execution_digest>}
```

The `request` mapping retains every other top-level field and nested value
unchanged. The remote OpenSpec capability spec now lists protocol version,
timestamps, caps, descriptors, and security identity explicitly; the design
records the same literal shape and states that response execution digests are
echo-only.

### Root causes

1. Request validation checked only lowercase `sha256:` syntax. A caller could
   consistently substitute payload bytes, descriptor length/hash, and wire
   length/hash while retaining the old syntactically valid execution digest.
2. Aggregate accounting advanced frame-by-frame. A later descriptor could make
   the complete declared message exceed its cap only after an earlier payload
   had already been read and allocated.

### RED/GREEN evidence

Added three focused regressions before production changes and ran:

```text
.venv/bin/python -m pytest \
  tests/engagement_v2/test_protocol.py::test_consistent_frame_substitution_retaining_execution_digest_fails \
  tests/engagement_v2/test_protocol.py::test_response_aggregate_cap_fails_before_any_frame_read \
  tests/engagement_v2/test_protocol.py::test_request_aggregate_cap_fails_before_any_frame_read -q
```

RED: all three failed.

- The consistent substitution raised no `ContractError`.
- Both aggregate cases reached the guarded first post-header read and raised
  `AssertionError` while requesting the 42-byte frame prefix.

After the two production changes, the same command was GREEN (`3 passed`).
The final focused protocol suite was GREEN (`63 passed`).

### Implementation

- Request validation now builds a fresh exact mapping containing
  `schema_version=1` and the complete request header minus only its top-level
  `execution_digest`, calls the existing domain-separated
  `execution_digest()`, and compares the result exactly.
- The comparison runs in `FramedMessage` acceptance, writer validation, and
  reader validation. Response validation continues to require only canonical
  digest syntax; `RunBinding.validate_response_echo` performs the request echo
  comparison.
- Immediately after canonical header/schema/descriptor validation and before
  the frame loop, the reader computes:

  ```text
  16 + header_length + frame_count * 42 + sum(descriptor.length)
  ```

  and rejects values over the applicable request/response cap.
- The request and response aggregate guarded streams now contain only the
  fixed prefix plus canonical header and forbid the very next read. Both
  produce `EXEC_PROTOCOL_INVALID` without requesting a frame prefix or payload.

### Refreshed semantic fixtures

The fixture header retains its exact 947-byte length and all semantic fields
except the corrected execution digest:

```text
sha256:02e262e0114492b8078130e3b9f8c18244cb8d12c7f05224ff4b1012b411ac7c
```

Prescribed binary/hash inspection was rerun. Current exact values are:

```text
request-frame.bin     60 bytes
4bb15f8f8b9731fe3169e4f948263c5c3ce8b33b3106d828adbae091b0e4064b

request-header.json  947 bytes
50ec1ad9750fdc919b0ce8358d0bfe47425dacf417ec5271fbf21de9f4b7e096

request-message.bin 1023 bytes
332d44b38bb1730f4ce6fe11f671b62f95b0309e16fd0f7b98e90c9c1080fdd9
```

The fixture test independently enumerates all 17 retained request fields and
recomputes the exact projection digest. The frame bytes and payload remain
unchanged.

### Fix-round verification and self-review

Ran on the final fix tree before commit:

```text
.venv/bin/python -m pytest tests/engagement_v2/test_protocol.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/protocol.py tests/engagement_v2/test_protocol.py
.venv/bin/mypy src/hackbot/engagement_v2/protocol.py
OPENSPEC_TELEMETRY=0 openspec validate engagement-v2-security-contracts --type change --strict --no-interactive
.venv/bin/python -m pytest
git diff --check
```

Results:

- Focused protocol suite: `63 passed`.
- Ruff: `All checks passed!`.
- Mypy: `Success: no issues found in 1 source file`.
- Strict OpenSpec: `Change 'engagement-v2-security-contracts' is valid`.
- Full suite: `1129 passed, 1 skipped in 18.54s`.
- Diff check: no errors.

Self-review confirmed:

- the projection removes exactly one top-level field and does not normalize,
  rename, omit, or rebuild any retained request value;
- all canonical request fields, nested executable identity, ordered
  descriptors, security identity, timestamps, timeout, and output caps affect
  execution identity;
- request object construction, writing, and reading all enforce the digest;
- response headers are not reinterpreted as request projections and remain
  echo-only;
- complete-size preflight runs only after exact descriptor validation and
  before any frame-prefix or payload read;
- per-frame caps, wire descriptor checks, incremental payload hashing, and EOF
  checks remain intact;
- no SSH, socket, helper, replay-cache, runtime-activation, v1 import, or
  non-standard-library dependency was introduced.

No open Critical or Important concern remains in fix round 1. The reviewed
minor observation that a short writer may have partially emitted bytes before
reporting the short count remains ledgered for final triage and was not changed
in this scoped fix.
