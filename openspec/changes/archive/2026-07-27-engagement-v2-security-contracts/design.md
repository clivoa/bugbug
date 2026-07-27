## Context

Hackbot currently uses standard-library `argparse`, frozen dataclasses, manual
strict validation, and a dependency-free core. Schema v1, its L2 approval
model, and the current SSH command-string runner remain active. The engagement
v2 umbrella design is approved, but three independent reviews found that its
security-critical constants and trust claims were not sufficiently normative
for implementation.

P0 creates a new isolated `hackbot.engagement_v2` contract package. It is
importable and testable but is not called by v1 CLI, policy, or runners. P1–P7
will consume it rather than duplicating constants or parsing rules.

The operator is trusted to declare engagement authority and arbitrary-tool
semantics. Files are untrusted until validation; targets, tools, remote output,
and target self-reports remain untrusted. P0 mechanically specifies data and
protocol boundaries without claiming it can prove external behavior.

## Goals / Non-Goals

**Goals:**

- Make every P0 enum, limit, grammar, projection, lifecycle state, reason code,
  and protocol byte rule exact and code-owned.
- Keep the core dependency-free and compatible with Python 3.11+.
- Generate machine-readable JSON Schema Draft 2020-12 documents from the same
  definitions used by Python validation.
- Provide canonicalization and binary-framing primitives with golden vectors.
- Prove schema drift, malformed-input rejection, and v1 non-integration through
  tests.

**Non-Goals:**

- No v2 file loader, filesystem snapshot, scope engine, action binder, policy
  decision, secret retrieval, subprocess execution, SSH connection, privilege
  broker, or migration.
- No change to schema v1 behavior or CLI surface.
- No P6 workflow schema beyond a null reserved slot in the authority
  projection.
- No per-action approval, profile gate, or independent proof of arbitrary
  executable semantics.

## Decisions

### 1. Isolated standard-library package

Create:

```text
src/hackbot/engagement_v2/
├── __init__.py       public contract exports only
├── errors.py         ReasonCode and ContractError
├── constants.py      versions, bounds, enums, identifiers, deny tables
├── canonical.py      strict primitive validation, canonical bytes, digests
├── patterns.py       bounded safe-fullmatch parser and linear matcher
├── schemas.py        code-owned Draft 2020-12 schema dictionaries
└── protocol.py       framed-message and run-binding primitives
```

The package MUST NOT import `hackbot.programs`, `hackbot.risk`,
`hackbot.tools`, or optional dependencies. Existing v1 modules MUST NOT import
the new package in P0.

Alternative considered: extend `programs/schema.py` and `risk/models.py`.
Rejected because that would mix v1 runtime behavior with incomplete v2
contracts and make accidental activation likely.

Alternative considered: Pydantic models. Rejected because the core is currently
dependency-free and the project has not approved a runtime dependency change.

### 2. Python definitions generate committed schemas

`schemas.py` owns immutable dictionaries for:

- program v2;
- scope v2;
- authorization v2;
- actions v1;
- action request v2;
- runner v2;
- remote protocol header v1.

`scripts/export_engagement_v2_schemas.py --check` serializes them as sorted,
indented UTF-8 JSON under `schemas/engagement-v2/` and compares exact bytes.
Without `--check`, it writes atomically through sibling temporary files and
`os.replace`. Schema documents are published first and `manifest.json` is
always published last. The manifest contains schema IDs, contract versions,
and file SHA-256 values.

Every root schema publishes
`x-hackbot-canonical-format: hackbot-canonical-json-v1`. Draft 2020-12
validation is necessary but not sufficient: P1/P2/P4 consumers must also apply
the strict primitive validator and code-owned custom annotations/formats.

Alternative considered: hand-maintained JSON schema files. Rejected because
constants would drift between Python and documentation.

### 3. Custom restricted canonical JSON

Use `hackbot-canonical-json-v1`, not a partial claim of RFC 8785 compliance.
Security projection keys are restricted to ASCII snake case, floats are
forbidden, strings are NFC and control-free, and integers are signed 64-bit.
`canonical_bytes(value)` recursively validates the strict primitive model and
uses compact, sorted-key, UTF-8 JSON. Semantic normalizers in later phases are
responsible for sorting set-like collections before calling it; argv and other
ordered lists remain order-sensitive.

`digest_value(value)` returns lowercase `sha256:<hex>`. Dedicated
`authority_digest()` and `execution_digest()` prepend the fixed projection tag
inside the value being hashed; domain separation never relies on a caller
remembering a prefix.

Binding names use the single code-owned ASCII snake-case grammar
`[a-z][a-z0-9_]{0,63}`. General 128-byte value identifiers remain separate for
action/node IDs and secret reference values. The confirmed runner-security
view likewise uses one code-owned leaf-field registry and a golden authority
digest vector; P0 does not implement the P1 projection loader.

Alternative considered: raw-file hashing. Rejected because comments and
formatting would invalidate confirmation while semantically equivalent data
would not be stable.

Alternative considered: a third-party canonical JSON package. Rejected to
preserve the dependency-free core and because the restricted model is smaller
than general JSON number/string semantics.

### 4. Safe patterns use a parser, not Python `re`

`patterns.py` tokenizes the exact `hackbot-safe-fullmatch-v1` grammar into
immutable atoms. Quantifiers are bounded, there is no grouping or alternation,
and each atom advances reachable positions through a sliding window over the
input. Runtime is `O(input_length * atom_count)`, independent of quantifier
width; there is no backtracking recursion. Matching rejects the first ASCII
input byte beyond the public 8,192-byte maximum before transitions begin.

The public interface consists of immutable `SafePattern(source, atoms)` values,
`compile_safe_pattern(source) -> SafePattern`, and
`safe_fullmatch(pattern, value) -> bool`.

Alternative considered: blacklist dangerous constructs before `re.fullmatch`.
Rejected because blacklist completeness and backtracking behavior are difficult
to make a stable security contract.

### 5. Reason codes are typed failures

`ReasonCode` is a string enum containing the exact P0 registry.
`ContractError` accepts only an exact reason code. Its public message is derived
deterministically from that code, so decoded input cannot enter the error.
Lower layers may chain a private exception, but `str(error)` and `as_dict()`
expose only the registered code and code-owned message.

This prevents later components from emitting typo variants or placing decoded
untrusted content in structured error fields.

### 6. Framing is stream-oriented and allocation-bounded

`protocol.py` defines immutable `FrameType`, `Frame`, and `FramedMessage`
values plus `write_message(stream, message) -> None` and
`read_message(stream, response=False) -> FramedMessage`.

`read_message` reads fixed headers first, rejects lengths before allocation,
uses exact-length reads, maintains a running total, hashes payload as it is
read, and requires EOF after the declared final frame. P0 does not open a
socket, reserve a replay tuple, or spawn a child.

Run-binding validators cover canonical UUIDv4, 32-byte nonce/base64url, UTC
timestamps, expiry/skew, digest syntax, and response echo fields. Replay cache,
SSH pinning, helper verification, and privilege permits are P4 consumers of
these contract values.

Execution projection v1 is exactly
`{"schema_version":1,"request":<request>}`. The request value retains every
canonical request-header field and nested value unchanged except for removing
the top-level `execution_digest`; request acceptance recomputes and compares
the domain-separated digest over that literal shape. Responses only echo and
compare the already validated request execution digest.

Alternative considered: newline-delimited JSON or shell-safe text. Rejected
because arbitrary artifact/secret bytes, exact length enforcement, and
truncation detection require binary framing.

### 7. Golden fixtures are small and deterministic

Commit:

```text
tests/fixtures/engagement_v2/
├── canonical/
│   ├── authority-input.json
│   ├── authority-canonical.json
│   ├── authority-digest.txt
│   ├── caller-normalized-collections.json
│   ├── runner-security-projection.json
│   └── runner-security-authority-digest.txt
├── patterns/
│   └── cases.json
└── protocol/
    ├── request-header.json
    ├── request-frame.bin
    └── request-message.bin
```

Fixtures contain synthetic example domains, hashes, and secret bytes that are
not credentials. Tests also generate over-limit headers without allocating the
claimed payload by writing only a forged fixed header.

### 8. P0 completion does not activate v2

A guard test searches imports and CLI registration to prove:

- existing `hackbot.programs`, `hackbot.risk`, `hackbot.tools`, and CLI modules
  do not import `hackbot.engagement_v2`;
- current schema constants remain v1;
- existing full tests remain unchanged and pass.

P1 explicitly chooses integration points after importing the P0 package.

## Canonical Data Flow

```text
strict decoded primitives
        │
        ├─> contract enums/bounds/grammar validation
        │
        ├─> normalized security projection
        │       └─> canonical_bytes ─> domain-separated SHA-256
        │
        └─> schema_documents ─> deterministic exporter ─> committed JSON schemas

protocol header + opaque frames
        └─> fixed-header bounds ─> canonical header validation
                └─> per-frame length/hash ─> exact EOF ─> FramedMessage
```

## Failure States

- Invalid schema, enum, identifier, bound, pattern, or primitive raises
  `ContractError` with the exact registered `INVALID_*` reason.
- Stale/unconfirmed authorization helpers return only their exact `DENY_*`
  reason; they perform no I/O.
- Protocol length, digest, ordering, EOF, or binding failure raises the exact
  `EXEC_*` reason before any runtime action exists.
- Errors contain no decoded secret payload, secret reference, raw frame, or
  target output.

## Risks / Trade-offs

- **Contract breadth could recreate the whole v2 runtime in P0** → Keep P0
  functions pure and I/O-free except schema export and caller-provided protocol
  streams; enforce the non-integration guard.
- **Generated schema could imply validation completeness not present in
  Python** → Publish the canonical-format prerequisite at every schema root,
  test every schema constant against Python constants, and compare exact
  generated bytes; P1 implements strict primitive validation and document
  loading.
- **Custom canonicalization can be misunderstood as general JSON
  canonicalization** → Give it a Hackbot-specific version name and reject all
  values outside the restricted model.
- **Safe-pattern matcher can still consume excessive CPU at maximum bounds** →
  Bound source to 256 bytes, repetitions to 1,024, ASCII input to 8,192 bytes,
  and assert deterministic `input_length * atom_count` transition counts.
- **Binary fixtures can be hard to review** → Provide a deterministic fixture
  builder used only by tests and assert committed fixture SHA-256 values.
- **P0 schemas can drift before dependent phases ship** → P1–P7 import the
  definitions; duplicated constants fail review and drift tests.

## Migration Plan

1. Add the isolated package, schemas, fixtures, and tests.
2. Verify no v1 module imports the package and no CLI output changes.
3. Publish and archive the P0 OpenSpec change after tests and review.
4. P1 consumes authority constants/canonicalization; P2 consumes action
   contracts; P4 consumes protocol contracts.

Rollback is deletion of the isolated package, generated schemas, fixtures, and
tests. Because P0 has no v1 imports or persisted runtime state, rollback does
not migrate engagement data.

## Open Questions

None. Exact values and boundaries are fixed by the three delta specifications
in this change. A later change MUST modify those requirements explicitly rather
than reinterpret them.
