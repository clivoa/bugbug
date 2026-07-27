# Final OpenSpec compliance review

Review scope: complete branch range `30dd1e2..5e87d51` (18 commits), using the
frozen review package
`.superpowers/sdd/2026-07-26-engagement-v2-security-contracts/review-30dd1e2..5e87d51.diff`,
the complete OpenSpec proposal/design/tasks and all three delta specifications,
and the SDD progress ledger.

Review axis: P0 OpenSpec requirement compliance only. This review did not
request P1/P2/P3/P4 runtime implementations and did not rerun broad gates.

Finding count:

- Critical: **0**
- Important: **3**
- Minor: **2**
- Deferred/parked ledger observations triaged: **14** (**1 must fix before
  merge**, **13 safe to defer**)

## Strengths

- The branch preserves the P0 isolation boundary. The only production imports
  of `hackbot.engagement_v2` occur within the isolated package, and the package
  contains no socket, SSH, subprocess, secret-resolution, replay-cache, action
  binder, policy-decision, or migration implementation. The v1 AST/runtime
  guards are in `tests/engagement_v2/test_v1_isolation.py:151-247`, and current
  runtime schema v1 is asserted at line 244.
- Versions, numeric bounds, closed enums, protocol values, lifecycle states,
  cleanup states, interpreter/elevation tables, and reason codes are
  centralized in `src/hackbot/engagement_v2/constants.py` and
  `src/hackbot/engagement_v2/errors.py`, with detailed exact-value coverage in
  `tests/engagement_v2/test_constants.py:93-624`.
- `hackbot-canonical-json-v1` is genuinely restricted: exact primitive types,
  signed int64, NFC, C0/C1/surrogate rejection, ASCII snake-case mapping keys,
  maximum depth, compact sorted-key UTF-8, and domain-separated authority and
  execution digests are implemented in
  `src/hackbot/engagement_v2/canonical.py:21-82` and covered by canonical golden
  vectors and negative cases.
- `hackbot-safe-fullmatch-v1` uses its own immutable parser/matcher rather than
  Python `re`. The grammar, maximum source/class/quantifier values, printable
  ASCII value boundary, non-recursive behavior, and explicit operation budget
  are covered in `tests/engagement_v2/test_patterns.py:50-234`.
- The generated Draft 2020-12 schema set is closed and code-owned. The seven
  schemas plus manifest are derived by
  `src/hackbot/engagement_v2/schemas.py:1178-1223`; non-portable enforcement is
  explicitly published through `x-hackbot-unique-by`,
  `hackbot-safe-fullmatch-v1`, and `x-hackbot-max-utf8-bytes`, matching the
  operator ruling that custom P1/P2/P4 enforcement is deferred without adding
  a P0 dependency.
- Framing uses the exact 16-byte fixed prefix and 42-byte frame prefix,
  preflights complete declared wire size before any frame read, validates
  direction/order/hash/canonical header/EOF, and recomputes the frozen execution
  projection exactly. The implementation is at
  `src/hackbot/engagement_v2/protocol.py:49-718`; substitution, aggregate,
  binding, expiry, echo, and chain tests are at
  `tests/engagement_v2/test_protocol.py:194-963`.
- The frozen execution projection decision is implemented exactly as
  `{"schema_version":1,"request":<all request-header fields except
  execution_digest>}` in
  `src/hackbot/engagement_v2/protocol.py:405-408`, the fixture generator at
  `scripts/generate_engagement_v2_contract_fixtures.py:154-155`, and the exact
  fixture assertion at `tests/engagement_v2/test_protocol.py:916-944`.
- Targeted read-only byte checks in this review confirmed that every committed
  schema SHA-256 equals its manifest entry; protocol fixture hashes equal the
  frozen test registry; and `request-message.bin` is 1,023 bytes beginning with
  `48 42 56 32 52 55 4e 00 00 01 00 00 03 b3 00 01` (magic, version,
  947-byte header, one frame).

## Requirement trace summary

### `engagement-authority-contracts`

| Requirement | Implementation / schema / test / fixture / documentation trace | P0 result |
| --- | --- | --- |
| Versioned authority artifacts | Constants and limits: `constants.py:10-39`; closed schema versions/IDs and document annotations: `schemas.py:225-390`, `schemas.py:1178-1191`; tests: `test_constants.py:233-252`, `test_schemas.py:116-199`. Loading/early byte rejection remains P1 by design. | PASS at the P0 contract boundary. |
| Strict authority primitive model | Canonical validator: `canonical.py:21-52`; duplicate/non-canonical JSON header rejection: `protocol.py:131-165`; negative primitive/depth tests: `test_canonical.py:60-113`. YAML aliases/tags/duplicate-file-key loading remains P1. | PASS at the P0 contract boundary. |
| Exact profiles and policy limits | Closed `Profile`, numeric bounds, and sensitive-field registry: `constants.py:24-65`, `constants.py:84-88`; program schema: `schemas.py:226-323`; tests: `test_constants.py:254-291`, `test_constants.py:345-394`, `test_schemas.py:201-268`. Sensitive booleans are optional in the schema so a P1 normalizer can implement deny-by-absence; profiles grant no runtime capability. | PASS; defaults/materialization are correctly not activated in P0. |
| Canonical JSON bytes | `canonical.py:21-82`; canonical/digest fixtures under `tests/fixtures/engagement_v2/canonical/`; tests: `test_canonical.py:42-144`; documentation: `docs/engagement-v2-contracts.md:20-36`. Set-like field normalization is intentionally a semantic P1 input step, while ordered lists remain ordered. | PASS in implementation, with Minor M1 on checkbox evidence wording. |
| Confirmed authority projection | Domain-separated helper: `canonical.py:74-77`; runner schema: `schemas.py:906-1028`; authority composition remains a P1 projection consumer. | **FAIL: Important I1.** The normative included-field list is incomplete/inconsistent with the accepted runner security schema and remote trust requirements. |
| Confirmation contract | Authorization schema: `schemas.py:354-390`; confirmation/digest fields in generated schema; denial reasons in `errors.py:27-31`. Validation against a frozen snapshot remains P1; no per-action approval state exists. | **FAIL: Important I3** because two required malformed-input branches name an unregistered reason. |
| Stable reason code registry | Exact enum/error: `errors.py:12-86`; closed registry tests: `test_constants.py:594-624`; package root exports only the stable failure types. | Implementation matches the closed list, but the authority spec contradicts it; **FAIL: Important I3**. |

### `action-execution-contracts`

| Requirement | Implementation / schema / test / fixture / documentation trace | P0 result |
| --- | --- | --- |
| Exact action manifest bounds | Constants: `constants.py:117-148`; action schema collection caps: `schemas.py:538-717`; generated schema and tests: `test_schemas.py:270-389`. | **FAIL: Important I2** for the parameter/binding identifier grammar mismatch. |
| Exact parameter and prepared-input bounds | Parameter types and bounds: `constants.py:90-105`, `constants.py:117-148`; schemas/annotations: `schemas.py:415-478`, `schemas.py:718-796`, `schemas.py:801-854`; exact tests: `test_constants.py:299-343`, `test_schemas.py:303-389`, `test_schemas.py:521-557`. Boolean-vs-integer binding, lower-of-policy target cap, and aggregate preparation enforcement remain P2. | PASS at the P0 contract boundary. |
| Deterministic safe full-match pattern | Parser/matcher: `patterns.py:18-223`; closed tests: `test_patterns.py:50-234`; synthetic cases: `tests/fixtures/engagement_v2/patterns/cases.json`; custom schema format: `schemas.py:449-454`. | PASS. |
| Whole-token placeholder grammar | Closed kinds: `constants.py:108-113`; schema/runtime token pattern: `schemas.py:112-116`, `protocol.py:60-64`; tests: `test_schemas.py:506-519`, `test_protocol.py:627-647`. `argv[0]` selection/binding remains P2/P4. | PARTIAL: whole-token behavior passes, but the `<id>` contract is inconsistent with declared mapping keys under I2. |
| Exact platform, architecture, privilege, and execution enums | `constants.py:151-192`; schema defs: `schemas.py:744-754`; closed tests: `test_constants.py:109-130`, `test_constants.py:254-291`, `test_schemas.py:303-389`. Superuser annotations are at `schemas.py:664-675`. | PASS. |
| Shell, interpreter, and elevation contract | Immutable registries: `constants.py:194-272`; exact/case-mode tests: `test_constants.py:396-472`. Enforcement against a selected executable/argv remains P2. | PASS as a contract-only P0 deliverable. |
| Rate-control contract | Closed modes and schema conditions: `constants.py:183-187`, `schemas.py:484-510`, `schemas.py:689-715`; schema tests: `test_schemas.py:445-504`. Matching parameter types and policy denial remain P2. | PASS as a contract-only P0 deliverable. |
| Evidence and output contract | Evidence/output enums and bounds: `constants.py:177-187`, `constants.py:272-305`; closed retained-output paths and structured-operator rejection: `schemas.py:514-535`, `schemas.py:569-575`, `schemas.py:677-688`; tests: `test_schemas.py:445-557`. Redaction, inferred capability denial, symlink cleanup, and aggregate runtime enforcement remain P2/P3. | PASS as a contract-only P0 deliverable. |
| Execution and cleanup lifecycle | Closed lifecycle/resource/target cleanup enums: `constants.py:278-305`; tests: `test_constants.py:474-525`; docs preserve P0 non-activation. State transitions/results remain P3/P4. | PASS as a contract-only P0 deliverable. |

### `remote-runner-protocol-contracts`

| Requirement | Implementation / schema / test / fixture / documentation trace | P0 result |
| --- | --- | --- |
| Fixed binary framing | Exact constants/types: `constants.py:307-357`; read/write/preflight: `protocol.py:581-688`; request-header schema: `schemas.py:1029-1175`; malformed and boundary tests: `test_protocol.py:194-532`; binary fixtures under `tests/fixtures/engagement_v2/protocol/`. | PASS. |
| Canonical request binding | Header/run validators: `protocol.py:167-408`, `protocol.py:521-578`; exact execution projection recomputation: `protocol.py:405-408`; tests: `test_protocol.py:627-876`, `test_protocol.py:904-951`; frozen header/message fixture. | PASS, including the exact operator-ruling shape. |
| Replay resistance | Replay/nonce/lifetime constants: `constants.py:344-352`; response echo: `protocol.py:560-578`; response chain: `protocol.py:691-712`; tests: `test_protocol.py:691-901`; schema annotations include 600-second retention. Atomic reservation is intentionally P4. | PASS as a contract/primitive-only P0 deliverable. |
| Pinned SSH and helper trust root | Runner schema closes host/user/identity/key pin/helper/options: `schemas.py:857-905`, `schemas.py:906-1028`; generated `runner.schema.json`; schema tests: `test_schemas.py:559-615`. SSH invocation/helper verification are intentionally P4. | Capability contract is present, but its confirmation binding is **FAIL under Important I1**. |
| Executable identity and privilege permit | Executable digest/path schema and closed privilege enums; Ed25519 sizes/replay/lifetime constants and schema annotations; required privilege-signer fingerprint in runner schema. Descriptor execution, permit issuance/signature verification, and broker behavior remain P4. | Contract values pass; authority binding is **FAIL under Important I1**. |
| Runtime platform and privilege claims | Closed roles/platform/architecture/privileges: `constants.py:151-168`, `constants.py:359-362`; runner schema; `unverified-self-report` cleanup enum. Trusted preflight and scope checks remain P4. | PASS as a contract-only P0 deliverable. |
| Source identity and egress claims | Modes/60-second bound: `constants.py:364-372`; runner source/attestation schema: `schemas.py:906-1028`; remote-header annotations and exact tests: `test_schemas.py:559-615`. Signed observation/preflight remain P4. | Contract fields pass; complete authority binding is **FAIL under Important I1**. |
| Crash and cleanup reporting | Private mode constants and cleanup enums: `constants.py:272-305`, `constants.py:371-372`; exact tests: `test_constants.py:474-559`; P0 documentation explicitly says no helper/replay cache. Startup reconciliation and cleanup reporting remain P4. | PASS as a contract-only P0 deliverable. |

## Frozen operator decisions

- **Execution projection:** frozen and implemented exactly; PASS.
- **Dependency-free P0 / custom annotations enforced later:** standard-library
  package plus `x-hackbot-unique-by`, `hackbot-safe-fullmatch-v1`, and
  `x-hackbot-max-utf8-bytes` are present; PASS. No P1/P2/P4 runtime validator
  is demanded here.
- **Profiles are context/scaffolding defaults, not capability gates:** profile
  enum is closed, sensitive fields are materialized/normalized independently,
  and there is no `required_profile` action field; PASS.
- **Deny by absence:** sensitive booleans are not schema-required and the spec
  fixes absent values to false for the future P1 normalizer; PASS at the
  contract boundary.
- **No post-engagement/per-action human approval:** confirmation binds the
  engagement; the remote permit is specified as machine-issued only after
  policy `ALLOW`; no action approval field/runtime was added; PASS.
- **Secrets by reference and declared transport only in P0:** action schema
  contains only `reference` and closed `stdin|file` transport declarations,
  while retrieval/delivery is absent; PASS.
- **P0 non-activation:** v1 remains the only executing schema/path; PASS.

## Findings

### Critical

None.

### Important

#### I1 — Confirmed authority projection omits accepted runner trust roots

Paths:

- `openspec/changes/engagement-v2-security-contracts/specs/engagement-authority-contracts/spec.md:116`
- `openspec/changes/engagement-v2-security-contracts/specs/remote-runner-protocol-contracts/spec.md:96`
- `openspec/changes/engagement-v2-security-contracts/specs/remote-runner-protocol-contracts/spec.md:123`
- `schemas/engagement-v2/runner.schema.json:170`
- `schemas/engagement-v2/runner.schema.json:220`
- `schemas/engagement-v2/runner.schema.json:230`
- `schemas/engagement-v2/runner.schema.json:327`

Norm violated: the confirmed authority projection must bind every
security-relevant runner trust field so a change invalidates confirmation.
Remote-runner requirements accept a helper SHA-256 **or code-signing identity**
and require the permit signer public-key fingerprint in the confirmed runner
projection. The runner schema also requires a dedicated SSH `identity`, a
source-identity `address`, a complete egress-attestation trust tuple, and the
privilege signer fingerprint. The authority spec's exact included list names
only SSH host/port/user, helper digest, source mode, and
“egress-attestation identity”; it omits the SSH identity, the code-signing
alternative, source address, adapter binary/signer fingerprints, and privilege
signer fingerprint.

Impact: a P1 implementation following the authority capability literally can
either reject a runner that is valid under runner schema v2 (code-signing-only
helper) or omit a selected trust root from `hackbot-authority-v1`. In the latter
case, changing an SSH identity, helper code-signing identity, source address,
egress verifier key/binary, or privilege-permit signer need not produce
`DENY_AUTHORIZATION_STALE`.

Concrete correction: freeze a code-owned runner-security projection field
registry and golden vector which includes the configured SSH identity, helper
path/protocol plus the exact configured `sha256` and/or
`code_signing_identity`, OS/architecture/permitted privileges,
`source_identity` mode and address, the complete egress-attestation trust tuple,
and `privilege_signer_public_key_fingerprint`; explicitly enumerate only the
operational exclusions. Align the authority spec, constants/tests, fixture, and
P0 documentation without implementing the P1 loader.

#### I2 — Parameter/placeholder identifier norm conflicts with canonical mapping keys

Paths:

- `openspec/changes/engagement-v2-security-contracts/specs/action-execution-contracts/spec.md:8`
- `openspec/changes/engagement-v2-security-contracts/specs/action-execution-contracts/spec.md:73`
- `src/hackbot/engagement_v2/constants.py:69`
- `src/hackbot/engagement_v2/schemas.py:600`
- `schemas/engagement-v2/actions.schema.json:246`

Norm violated: the action spec allows parameter IDs up to 128 bytes matching
`[a-z0-9]+(?:[._-][a-z0-9]+)*`, and placeholders inherit that contract.
However, parameters/secrets/request parameters are JSON mapping keys and the
generated schemas restrict them to `[a-z][a-z0-9_]{0,63}`. Consequently a
normatively valid ID such as `1-target`, `target-name`, or `target.name` is
rejected by the schema and cannot enter `hackbot-canonical-json-v1`.

Impact: P1/P2 implementations cannot simultaneously honor the action ID
contract, the generated schemas, and the canonical primitive model. Manifests
that the OpenSpec says are valid will be rejected, while placeholder and target
binding schemas still advertise the broader grammar, creating cross-consumer
interoperability drift.

Concrete correction: freeze separate names for value identifiers and dynamic
mapping/binding keys. The least disruptive correction is to specify parameter,
secret-binding, action-request parameter, target-binding, and placeholder IDs
as ASCII snake-case `[a-z][a-z0-9_]{0,63}`, retaining the 128-byte general
identifier only for value fields such as action/node IDs and secret reference
values. Align `IDENTIFIER_PATTERN` use in argv/target bindings, generated
schemas, tests, and docs. Alternatively redesign dynamic collections as lists
with explicit `name` values, but do not leave both grammars normative.

#### I3 — Two mandatory failures name a reason absent from the closed registry

Paths:

- `openspec/changes/engagement-v2-security-contracts/specs/engagement-authority-contracts/spec.md:72`
- `openspec/changes/engagement-v2-security-contracts/specs/engagement-authority-contracts/spec.md:143`
- `openspec/changes/engagement-v2-security-contracts/specs/engagement-authority-contracts/spec.md:158`
- `src/hackbot/engagement_v2/errors.py:12`

Norm violated: non-boolean sensitive policy values and malformed confirmation
digests MUST return `INVALID_SCHEMA`, but `INVALID_SCHEMA` is absent from the
same spec's exact immutable reason registry and from `ReasonCode`.

Impact: a future P1 validator cannot comply with both requirements. It must
emit an unregistered value (which `ContractError` correctly rejects) or choose
a different reason, making externally visible denial behavior non-deterministic
across consumers.

Concrete correction: replace both `INVALID_SCHEMA` references with one exact
registered reason, preferably `INVALID_DOCUMENT_STRUCTURE` for schema type and
digest-shape failures, and add a spec-level regression assertion. Adding a new
reason instead would change the explicitly frozen registry and would require
constants/tests/docs updates.

### Minor

#### M1 — Checkbox 2.1 overstates set-like normalization test evidence

`openspec/changes/engagement-v2-security-contracts/tasks.md:8` claims tests for
“set-like normalization inputs”, but
`tests/engagement_v2/test_canonical.py:42-144` covers mapping ordering and
ordered-list preservation without a set-like normalization fixture/test. The
design correctly assigns semantic set-like normalization to later phase
normalizers, so no P1 runtime should be added in P0.

Impact: no current P0 runtime defect, but the checked task and prior evidence
audit imply proof that does not exist.

Correction: align the task/test wording with the frozen phase boundary and add
a narrow test/fixture that documents caller-normalized set-like input versus
ordered argv, without implementing a P1 loader.

#### M2 — Public interface documentation omits `FrameType`

`docs/engagement-v2-contracts.md:12-18` lists the protocol public interface but
omits `FrameType`, while `src/hackbot/engagement_v2/protocol.py:715` exports it
and callers need it to construct `Frame`.

Impact: the code is correct, but task 7.2's “document P0 public interfaces”
claim is incomplete.

Correction: add `FrameType` to the protocol row before publication.

## Deferred triage

| Deferred/parked ledger item | Triage | Justification |
| --- | --- | --- |
| Task 2 authority digest test uses `rstrip("\\n")` rather than exact one-newline assertion | **safe to defer** | The committed byte is correct and fixture regeneration/check compares the whole exact tree; this is redundant direct-test precision. |
| Task 4 write mode could preflight every expected schema entry before replacing any | **safe to defer** | Publication is intentionally per-file atomic, descriptor-pinned, no-follow, and manifest-last; a later failure can leave a detectable/repairable partial update without crossing the directory boundary. |
| Task 4 add a prohibited safe-pattern example to explain custom format enforcement | **safe to defer** | The generated schema publishes the custom format and the pattern suite already contains extensive prohibited examples. |
| Task 4 require `O_NONBLOCK` explicitly instead of `getattr(..., 0)` | **safe to defer** | Supported POSIX exporter environments expose the flag; FIFO tests demonstrate nonblocking behavior. Making the capability guard more explicit is clarity hardening. |
| Task 4 reject theoretical zero-byte `os.write` progress | **safe to defer** | A regular-file descriptor write of a non-empty buffer is expected to progress or raise; this is defensive liveness hardening, not a current contract mismatch. |
| External Task 4 residual: multi-file export is not globally transactional | **safe to defer** | The approved contract is per-file atomic publication with exact-byte `--check`, not a filesystem-wide transaction. |
| Task 5 `write_message` rejects legal partial writes | **safe to defer** | It fails closed with `EXEC_PROTOCOL_INVALID`; no silently accepted malformed request results. Supporting arbitrary partial-write streams is robustness, not a P0 wire-format violation. |
| Task 5 descriptor-vs-prefix mutation test rejects first on execution digest | **safe to defer** | The earlier rejection is a stronger binding control; descriptor/prefix mismatch is independently covered elsewhere. |
| Task 6 determinism regression does not monkeypatch every possible process-state source | **safe to defer** | Generator inputs are visibly fixed/code-owned, exact committed bytes are checked, and the existing test perturbs representative environment/time/random state. |
| Task 6 safety scan does not include Windows/backslash home spellings | **safe to defer** | Current generated corpus is byte-frozen and contains no such material; this is additional negative-test breadth. |
| Task 6 managed-parent checks do not close an actively concurrent directory swap | **safe to defer** | The fixture generator is repository developer tooling, not a hostile runtime publication boundary; the ledger explicitly accepted this threat model. |
| Task 6 unconditional `os.O_NOFOLLOW` portability | **safe to defer** | Current supported development/runtime targets are POSIX/macOS/Linux and fail-closed portability work does not change the published contract bytes. |
| Task 7 protocol interface table omits `FrameType` | **must fix before merge** | This is the delivered P0 public contract documentation and task 7.2 is checked. The one-word correction is required before publication; see M2. |
| Task 8 report labels `b0b8d49` as worktree state rather than dispatch base | **safe to defer** | The same report identifies verified HEAD `5e87d51`, and no code/gate/contract conclusion depends on the stale label. |

All Critical/Important findings recorded in the ledger before the deferred list
were inspected as resolved in the final range. The external review's
pre-hardening exporter findings describe superseded code and are not reopened.
The non-destructive ruling for unexpected publication entries is preserved.

## Checkbox audit

| Checkbox | Audit |
| --- | --- |
| 1.1 | Checked with registry coverage present, but I2 shows the tests do not reconcile the two simultaneously normative identifier grammars. |
| 1.2 | Checked; isolated constants/errors implementation exists. |
| 2.1 | Checked; canonical coverage exists, with Minor M1 on the set-like wording/evidence. |
| 2.2 | Checked; strict canonical/digest helpers exist. |
| 3.1 | Checked; accepted/prohibited grammar, boundaries, no-`re`, depth, and operation-budget tests exist. |
| 3.2 | Checked; bounded parser/matcher exists. |
| 4.1 | Checked; all seven schemas plus manifest have exact schema/export drift coverage. |
| 4.2 | Checked; code-owned Draft 2020-12 documents, annotations, exporter, generated bytes, and manifest exist. |
| 5.1 | Checked; framing, integer widths, caps, allocation preflight, hashes, EOF, run binding, projection, expiry, and echo coverage exists. |
| 5.2 | Checked; immutable framing/run-binding implementation exists. |
| 6.1 | Checked; synthetic canonical/pattern/protocol/digest corpus and generated malformed-length negative cases exist. |
| 6.2 | Checked; deterministic update/check tooling and exact-byte/hash tests exist. |
| 7.1 | Checked; AST and exercised-runtime isolation guards exist. |
| 7.2 | Checked, but public interface documentation requires M2 before merge. |
| 8.1 | Checked with an internally coherent historical report of focused/full pytest, schema/fixture drift, Ruff, mypy, strict OpenSpec, publication/secret, and whitespace gates. **⚠️ Cannot verify** freshness or raw execution without rerunning broad gates, which this review was instructed not to do. |
| 8.2 | Correctly remains open. Independent whole-change review/finding resolution, publication/Project updates, merge verification, and post-merge archive are not all complete. |

## Verification boundary

- The complete review diff, OpenSpec package, and progress ledger were read.
- Targeted read-only hash, prefix, file-size, import, and non-activation
  inspections were performed.
- **⚠️ Cannot verify:** the historical gate execution/freshness reported for
  8.1 was not rerun.
- **⚠️ Cannot verify:** live GitHub Issue #1, Project #2, PR, merge checks, and
  future archive state are external to this review. This is consistent with
  8.2 remaining open.
- P1 normalization/loading, P2 binding/policy, P3 execution/evidence/cleanup,
  and P4 SSH/replay/permit/preflight behavior are intentionally absent in P0
  and were not treated as missing P0 runtime.

## Verdicts

**Spec compliance: FAIL**

The P0 implementation has strong isolation, canonical/framing primitives,
schemas, annotations, fixtures, and non-activation evidence, but the three
Important contract inconsistencies must be resolved before the delta specs can
be published as an unambiguous dependency for P1/P2/P4.

**Ready for publication review: WITH FIXES**

Resolve I1-I3 and M2 before merge/publication; align M1's checkbox evidence.
Keep 8.2 open until independent finding resolution, GitHub/Project publication,
merge verification, and archive are actually complete.
