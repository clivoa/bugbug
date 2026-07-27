# Final security / quality review — `30dd1e2..5e87d51`

Scope reviewed: the complete 9,672-line review package for 18 commits, the
architectural boundary in `openspec/changes/engagement-v2-security-contracts/design.md`,
the SDD ledger, the P0 OpenSpec requirements, and the resulting source, schemas,
scripts, tests, fixtures, and documentation.

This was a read-only adversarial review. I did not rerun the broad test, lint,
type-check, OpenSpec, drift, or secret-scan gates. I ran only two narrow,
non-mutating probes: one malformed-depth decoder probe and one safe-pattern
runtime profile.

## Verdict

**Ready to merge: WITH FIXES**

Counts:

- Critical: 0
- Important: 3
- Minor: 3
- Deferred ledger items triaged: 13
  - Must fix before merge: 0
  - Safe to defer: 13

The three Important findings are inside the P0 normative/security boundary and
should be resolved before merge. The deferred ledger items remain genuinely
minor or outside the active threat model and do not independently block merge.

## Strengths

- `ContractError` exposes only an exact closed `ReasonCode`; its public string
  and dictionary forms are code-owned, and the implementation permits normal
  exception traceback/cause/context bookkeeping without allowing mutation of
  the public reason.
- Canonicalization rejects non-exact primitives, floats, out-of-range signed
  integers, non-NFC strings, surrogates, C0/C1 controls, invalid mapping keys,
  and depth over 32. Domain-separated authority and execution digest envelopes
  are simple and explicit.
- The safe-pattern grammar does not delegate user patterns to `re`, has no
  recursive matcher or backtracking constructs, and strictly parses the stated
  literals, classes, ranges, and bounded quantifiers.
- Request framing validates the fixed prefix and top-level caps first, validates
  the canonical header and all descriptors, then preflights the complete
  declared wire size before reading any frame prefix or payload. Frame direction,
  exact reads, prefix/descriptor agreement, payload hashes, execution-digest
  recomputation, EOF, UUID/nonce/timestamp syntax, lifetime, skew helper,
  response echo helper, and response-chain bytes are all explicit.
- `FramedMessage`, `Frame`, and `RunBinding` freeze security-relevant values;
  the write path validates aggregate size before emitting the prefix.
- The schema exporter pins the destination directory by descriptor, rejects
  symlink/FIFO/non-regular entries, uses exclusive no-follow temporary files,
  verifies inode identity before and after publication, fsyncs file data and
  the directory, and makes `--check` exact and non-mutating.
- Fixture generation uses fixed synthetic values, derives protocol data from
  public contracts, reports extras rather than deleting them, and rejects
  ordinary root/managed-parent/managed-file symlinks.
- P0 remains isolated from the v1 CLI/program/risk/scope/tool runtime, and the
  new core package has only standard-library dependencies.

## Issues by severity

### Critical

None found.

### Important

#### I1. A valid safe pattern can monopolize a process for seconds; the “operation budget” is only a theoretical ceiling

- Path: `src/hackbot/engagement_v2/patterns.py:185`
- Scenario: `_operation_limit()` scales as
  `(value_length + 1) * (atom_count + 1) * 1025`, while the matcher at
  `patterns.py:201-219` explores every reachable start and up to 1,024
  repetitions from each start. The valid 176-byte pattern
  `"a{0,1024}" * 16` matched an allowed 8,192-byte ASCII string in **8.402
  seconds** on the review environment (CPython 3.14.3). The computed budget is
  roughly 143 million operations, so it does not reject this production-hostile
  case.
- Impact: an untrusted parameter/target value evaluated against an approved but
  broad manifest pattern can consume a worker for seconds per match. Repeated
  validations create a practical local CPU-denial-of-service path. This also
  falls short of the architectural claim that the matcher is linear in input
  length times pattern length in a useful bounded-runtime sense.
- Fix: implement an actual `O(input_length * atom_count)` transition, for
  example using a sliding-window/prefix-count DP per atom, and enforce the
  contract’s maximum match-input length before matching. If an absolute
  operation budget remains part of the contract, give it a fixed,
  production-sized value and reject exactly the first operation beyond it.
  Add deterministic worst-case tests; avoid a wall-clock-only assertion.

#### I2. Generated schemas do not machine-readably require the strict canonical primitive model

- Path: `src/hackbot/engagement_v2/schemas.py:208`
- Scenario: `_document()` annotates depth and UTF-8 byte limitations, but never
  attaches `CANONICAL_JSON_FORMAT` or an equivalent strict-primitive
  prerequisite. A standard Draft 2020-12 validator can therefore accept, among
  other examples, a mathematical integer represented/decoded as `1.0`, a
  generic string containing `\u0000`, or a non-NFC string. Those values are
  rejected by `hackbot-canonical-json-v1`. The code-owned
  `CANONICAL_JSON_FORMAT` constant is not consumed anywhere in schema
  generation.
- Impact: P1/P2/P4 consumers can treat a standard schema-success result as the
  complete P0 contract and admit values that later fail canonicalization or
  produce a different validation path. The existing `x-hackbot-unique-by`,
  custom safe-pattern format, UTF-8-byte, and depth annotations show that
  machine-readable limitations are an intended part of this boundary; omitting
  the canonical prerequisite leaves the most fundamental limitation implicit.
- Fix: add a root annotation such as
  `x-hackbot-canonical-format: hackbot-canonical-json-v1` to every generated
  document, explicitly document that ordinary Draft validation is necessary
  but not sufficient, and add tests proving consumers must reject
  float/control/non-NFC values through the strict primitive layer. If more
  granular extensions are desired, define them once and generate them
  consistently rather than implying standard keywords enforce them.

#### I3. The normative requirements demand an unregistered reason code

- Paths:
  - `openspec/changes/engagement-v2-security-contracts/specs/engagement-authority-contracts/spec.md:73`
  - `openspec/changes/engagement-v2-security-contracts/specs/engagement-authority-contracts/spec.md:144`
  - conflicting closed registry:
    `src/hackbot/engagement_v2/errors.py:15`
- Scenario: two requirements mandate `INVALID_SCHEMA` for a non-boolean policy
  field and a malformed authorization digest. `INVALID_SCHEMA` is absent from
  the exact stable registry at OpenSpec lines 158-170 and from `ReasonCode`.
  `ContractError("INVALID_SCHEMA")` correctly fails construction.
- Impact: later authority/authorization loaders cannot simultaneously satisfy
  the normative behavior and the closed typed-error contract. An implementer
  must invent a non-registered string, emit the wrong required code, or diverge
  from the spec, defeating P0’s purpose as the unique reason-code authority.
- Fix: rule the two cases to existing exact codes (for example the appropriate
  `INVALID_DOCUMENT_STRUCTURE`/`INVALID_CANONICAL_VALUE` distinction), update
  the two normative references, and add a test that every backticked
  `INVALID_*`/`DENY_*`/`EXEC_*`/`CLEANUP_*` requirement value belongs to
  `ReasonCode`.

### Minor

#### M1. The manifest is not published last despite the accepted residual ruling

- Path: `scripts/export_engagement_v2_schemas.py:263`
- `_write_files()` sorts every filename, which places `manifest.json` before
  `program`, `remote-header`, `runner`, and `scope`. A failure on a later entry
  can therefore leave a newly published manifest describing files not yet
  published. Hash-aware consumers still fail closed, so this is not an
  integrity bypass, but it contradicts the ledger’s accepted “manifest last”
  residual and makes partial publication less clear. Publish all schema
  documents first and `manifest.json` last.

#### M2. One-byte short reads amplify a 1 MiB header into roughly one million Python objects

- Path: `src/hackbot/engagement_v2/protocol.py:137`
- `_read_exact()` appends each non-empty short read to a list and joins at the
  end. A stream returning one byte per call remains within the wire cap but
  allocates a list with up to 1,048,576 `bytes` entries. Use a bounded
  `bytearray`/preallocated buffer or `readinto` loop to preserve exact-read
  behavior without chunk-object amplification.

#### M3. A golden fixture assertion reintroduces the private 60-byte frame suffix literal

- Path: `tests/engagement_v2/test_protocol.py:949`
- The generator correctly derives the frame boundary from the encoded header,
  and `test_protocol_frame_fixture_is_the_complete_message_suffix_after_header`
  also tests that dynamic relationship. This later assertion slices `[-60:]`,
  making fixture coverage stale if the payload or fixed frame layout changes.
  Derive the offset from `_PREFIX`, canonical header length, and message bytes,
  or rely on the existing dynamic boundary test.

## Deferred triage

| Ledger item | Triage | Rationale |
|---|---|---|
| Task 2 — digest fixture uses `rstrip("\n")` rather than enforcing exactly one newline | **Safe to defer** | The deterministic fixture generator and exact-byte drift check catch extra newlines. This is a local assertion-quality gap, not a digest ambiguity in production canonical bytes. |
| Task 4 — preflight every expected exporter entry before any replacement | **Safe to defer** | Per-file publication is atomic and a later unsafe entry fails closed; `--check` detects/repairs the partial repository state. Global transactionality is not a P0 runtime guarantee. Manifest-last ordering should still be corrected under M1. |
| Task 4 — add a prohibited safe-pattern example to schema limitation documentation | **Safe to defer** | The public contract documentation and OpenSpec already name grouping, alternation, wildcards, lookaround, backreferences, and unbounded quantifiers as prohibited. An extra example improves usability but does not change enforcement. |
| Task 4 — require `O_NONBLOCK` explicitly rather than `getattr(..., 0)` | **Safe to defer** | The supported macOS/Linux environment supplies `O_NONBLOCK`, and FIFO tests exercise the nonblocking path. A future platform expansion should convert this to an explicit capability check and controlled failure. |
| Task 4 — reject a theoretical zero-byte `os.write` result | **Safe to defer** | A non-empty blocking write to the regular exclusive temporary file is expected either to make progress or raise. A zero result is worth a defensive guard but is not a plausible supported-kernel attack path here. |
| Task 5 — complete legal partial writes instead of rejecting them | **Safe to defer** | The current writer fails closed on a short write and never proceeds as if the message were complete. P4 should close/discard the stream on failure. Looping over the unwritten suffix is a worthwhile compatibility improvement before broader stream support. |
| Task 5 — rebind the execution digest in the descriptor-vs-prefix mutation test | **Safe to defer** | The present mutation test rejects earlier than its name suggests, but the implementation independently compares validated descriptor type/length/hash against the frame prefix before payload allocation. This is a targeted coverage-quality gap, not a missing check. |
| Task 6 — broaden determinism regression to hostname/getpass/datetime/urandom/secrets/arbitrary environment | **Safe to defer** | Static inspection shows generated bytes derive only from fixed literals and deterministic P0 functions. Staging filenames are random but not fixture content. Broader monkeypatch guards would improve future regression sensitivity. |
| Task 6 — cover Windows/backslash home-path spellings | **Safe to defer** | The repository’s supported runtime is macOS/Linux-focused, generated contents are fixed ASCII, and no home lookup enters fixture generation. Add this if Windows becomes a supported repository workflow. |
| Task 6 — close actively concurrent managed-directory swap races | **Safe to defer** | This is real path-based TOCTOU, but the fixture generator is developer tooling operating inside a trusted checkout; a local actor able to rename repository directories concurrently can already alter executable project code. Do not run the generator privileged. |
| Task 6 — unconditional fixture-generator `os.O_NOFOLLOW` portability | **Safe to defer** | `O_NOFOLLOW` exists on the supported macOS/Linux targets and is security-positive there. If the supported OS set expands, fail explicitly with a controlled capability error or adopt descriptor-pinned platform-specific handling. |
| Task 7 — public protocol interface map omits `FrameType` | **Safe to defer** | `FrameType` is exported by `protocol.__all__` and fully documented by the numeric frame-type mapping. The table omission is a small API discoverability issue. |
| Task 8 — ignored report labels `b0b8d49` as current worktree state | **Safe to defer** | The committed HEAD, package range, ledger, and scoped review identify `5e87d51`; the stale label is in an ignored internal report. Correct it before retaining/archiving that report, but it does not alter shipped code or committed verification metadata. |

## Gate evidence

⚠️ **Cannot verify** the recorded broad gate results from the review package.
The package contains the resulting code/diff and the ledger records 1,151
passed / 1 skipped plus Ruff, mypy, OpenSpec, drift, publication, and secret
scan success, but it does not contain independently reproducible raw external
gate output. Per review instructions, those broad gates were not rerun. After
the Important fixes, an independent reviewer should rerun the complete Task 8
matrix and attach durable output to the delivery record.

The following narrow facts were directly verified during this review:

- worktree HEAD is `5e87d51629327c6fdbcbf21f6a4a191c588737e6`;
- merge base is `30dd1e2c1bac749a1680e9770263f1cf7987c402`;
- the safe-pattern worst-case probe above completed in 8.402 seconds;
- the malformed-depth probe returned a typed `ContractError` on the current
  CPython 3.14.3 environment rather than escaping as an interpreter exception.

## Recommendations

1. Fix I1-I3 and add focused regressions for each before merge.
2. Publish the schema manifest last and remove short-read object amplification.
3. Replace the private 60-byte fixture slice with the already established
   dynamic frame boundary.
4. Keep OpenSpec Task 8.2 open until the post-fix independent review and fresh
   broad gates are complete; do not archive the change before that evidence is
   durable.
5. Retain the dependency-free and v1-isolated P0 boundary while making the
   schema limitations explicit; none of the required fixes needs a runtime
   dependency or activates v2 execution.
