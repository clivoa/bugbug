# Engagement v2 Security Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an isolated, dependency-free P0 contract package containing
the exact engagement v2 schemas, constants, canonical digests, safe-pattern
grammar, and bounded remote framing primitives without activating v2 runtime
behavior.

**Architecture:** Add a new `hackbot.engagement_v2` package that contains only
pure contract definitions and caller-provided stream primitives. Python
definitions generate committed JSON schemas and golden fixtures. Existing v1
CLI, program, risk, scope, tool, and remote modules do not import P0.

**Tech Stack:** Python 3.11+ standard library, frozen dataclasses, `Enum`/
`IntEnum`, `json`, `hashlib`, `struct`, `unicodedata`, pytest, Ruff, mypy,
OpenSpec 1.6.0.

## Global Constraints

- Core runtime remains dependency-free; do not add Pydantic, Typer, JSON Schema
  runtime validation, or cryptography dependencies.
- Artifact versions are exactly: program 2, scope 2, authorization 2, actions
  1, action request 2, runner 2, authority projection 1, execution projection
  1, remote protocol 1.
- Program/scope/authorization/runner documents are at most 1,048,576 encoded
  bytes; actions is at most 4,194,304 bytes; nesting depth is at most 32.
- Canonical values reject floats, bytes, non-NFC strings, surrogates, C0/C1
  controls, non-ASCII-snake-case mapping keys, and integers outside signed
  64-bit.
- Authority and execution digests use lowercase SHA-256 with explicit
  `hackbot-authority-v1` and `hackbot-execution-v1` domain values.
- Action argv is at most 128 tokens, 4,096 UTF-8 bytes per token, and 65,536
  UTF-8 bytes including one NUL terminator per token.
- Prepared input is at most 67,108,864 bytes; a secret is at most 1,048,576
  bytes and all secrets total at most 4,194,304 bytes.
- Remote framing uses eight-byte magic `b"HBV2RUN\x00"`, network byte order,
  header cap 1,048,576, frame count 256, frame cap 67,108,864, request cap
  75,497,472, and response cap 41,943,040 bytes.
- P0 does not import from or change behavior in `hackbot.programs`,
  `hackbot.risk`, `hackbot.scope`, `hackbot.tools`, or `hackbot.cli`.
- Every task starts with a failing focused test, ends with fresh focused
  verification, and receives its own commit.

---

## File Structure

```text
src/hackbot/engagement_v2/
├── __init__.py       stable public P0 imports
├── errors.py         typed, secret-free contract failures
├── constants.py      versions, bounds, enums, identifier/deny registries
├── canonical.py      strict canonical values and domain-separated digests
├── patterns.py       safe-fullmatch parser and bounded matcher
├── schemas.py        code-owned Draft 2020-12 schemas
└── protocol.py       immutable frames, bounded stream codec, run bindings

scripts/
└── export_engagement_v2_schemas.py

schemas/engagement-v2/
├── program.schema.json
├── scope.schema.json
├── authorization.schema.json
├── actions.schema.json
├── action-request.schema.json
├── runner.schema.json
├── remote-header.schema.json
└── manifest.json

tests/engagement_v2/
├── __init__.py
├── test_constants.py
├── test_canonical.py
├── test_patterns.py
├── test_schemas.py
├── test_protocol.py
└── test_v1_isolation.py

tests/fixtures/engagement_v2/
├── canonical/
├── patterns/
└── protocol/

docs/
└── engagement-v2-contracts.md
```

---

### Task 1: Typed failures and immutable contract registry

**Files:**

- Create: `src/hackbot/engagement_v2/__init__.py`
- Create: `src/hackbot/engagement_v2/errors.py`
- Create: `src/hackbot/engagement_v2/constants.py`
- Create: `tests/engagement_v2/__init__.py`
- Create: `tests/engagement_v2/test_constants.py`

**Interfaces:**

- Produces: `ReasonCode`, `ContractError`, all version/limit constants, and
  enums consumed by Tasks 2–5.
- `ContractError.as_dict() -> dict[str, str]` exposes only `reason_code` and a
  deterministic code-owned `message`.
- No module outside `hackbot.engagement_v2` consumes these values in P0.

- [ ] **Step 1: Write failing registry tests**

Create tests that assert the exact enum members and closed limits:

```python
from hackbot.engagement_v2.constants import (
    ACTIONS_SCHEMA_VERSION,
    MAX_ACTIONS,
    MAX_ARGV_BYTES,
    MAX_ARGV_TOKENS,
    MAX_FRAME_BYTES,
    MAX_REQUEST_BYTES,
    PROGRAM_SCHEMA_VERSION,
    Architecture,
    EvidenceMode,
    LifecycleState,
    Platform,
    Privilege,
    RateControlMode,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode


def test_contract_versions_and_limits_are_exact() -> None:
    assert PROGRAM_SCHEMA_VERSION == 2
    assert ACTIONS_SCHEMA_VERSION == 1
    assert MAX_ACTIONS == 256
    assert MAX_ARGV_TOKENS == 128
    assert MAX_ARGV_BYTES == 65_536
    assert MAX_FRAME_BYTES == 67_108_864
    assert MAX_REQUEST_BYTES == 75_497_472


def test_security_enums_are_closed() -> None:
    assert {item.value for item in Platform} == {"linux", "darwin", "windows"}
    assert {item.value for item in Architecture} == {"x86_64", "arm64"}
    assert {item.value for item in Privilege} == {
        "network-raw",
        "network-admin",
        "packet-capture",
        "filesystem-protected-read",
        "superuser",
    }
    assert {item.value for item in EvidenceMode} == {
        "metadata-only",
        "redacted-output",
        "structured",
    }
    assert {item.value for item in RateControlMode} == {
        "argv-placeholder",
        "native-adapter",
        "not-applicable",
    }
    assert LifecycleState.SPAWNED.value == "spawned"


def test_contract_error_is_typed_and_secret_free() -> None:
    error = ContractError(ReasonCode.INVALID_LIMIT)
    assert error.as_dict() == {
        "reason_code": "INVALID_LIMIT",
        "message": "invalid limit",
    }
```

- [ ] **Step 2: Run tests and confirm the missing-package failure**

Run:

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_constants.py -q
```

Expected: collection fails with
`ModuleNotFoundError: No module named 'hackbot.engagement_v2'`.

- [ ] **Step 3: Implement errors and constants**

Use string enums and immutable registries:

```python
# errors.py
from __future__ import annotations

from enum import Enum


class ReasonCode(str, Enum):
    INVALID_SCHEMA_VERSION = "INVALID_SCHEMA_VERSION"
    INVALID_DOCUMENT_SIZE = "INVALID_DOCUMENT_SIZE"
    INVALID_DOCUMENT_ENCODING = "INVALID_DOCUMENT_ENCODING"
    INVALID_DOCUMENT_STRUCTURE = "INVALID_DOCUMENT_STRUCTURE"
    INVALID_UNKNOWN_FIELD = "INVALID_UNKNOWN_FIELD"
    INVALID_DUPLICATE_KEY = "INVALID_DUPLICATE_KEY"
    INVALID_IDENTIFIER = "INVALID_IDENTIFIER"
    INVALID_LIMIT = "INVALID_LIMIT"
    INVALID_CANONICAL_VALUE = "INVALID_CANONICAL_VALUE"
    INVALID_ACTION_MANIFEST = "INVALID_ACTION_MANIFEST"
    INVALID_PLACEHOLDER = "INVALID_PLACEHOLDER"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_RUNNER = "INVALID_RUNNER"
    DENY_AUTHORIZATION_UNCONFIRMED = "DENY_AUTHORIZATION_UNCONFIRMED"
    DENY_AUTHORIZATION_STALE = "DENY_AUTHORIZATION_STALE"
    DENY_CAPABILITY_NOT_ALLOWED = "DENY_CAPABILITY_NOT_ALLOWED"
    DENY_POLICY_LIMIT = "DENY_POLICY_LIMIT"
    DENY_RATE_UNENFORCEABLE = "DENY_RATE_UNENFORCEABLE"
    EXEC_PROTOCOL_INVALID = "EXEC_PROTOCOL_INVALID"
    EXEC_PROTOCOL_EXPIRED = "EXEC_PROTOCOL_EXPIRED"
    EXEC_PROTOCOL_REPLAY = "EXEC_PROTOCOL_REPLAY"
    EXEC_TRUST_MISMATCH = "EXEC_TRUST_MISMATCH"
    EXEC_PRIVILEGE_MISMATCH = "EXEC_PRIVILEGE_MISMATCH"
    EVIDENCE_POLICY_DENIED = "EVIDENCE_POLICY_DENIED"
    CLEANUP_RESOURCE_INCOMPLETE = "CLEANUP_RESOURCE_INCOMPLETE"
    CLEANUP_TARGET_INCOMPLETE = "CLEANUP_TARGET_INCOMPLETE"


class ContractError(ValueError):
    def __init__(self, reason_code: ReasonCode) -> None:
        if type(reason_code) is not ReasonCode:
            raise TypeError("reason_code must be an exact ReasonCode")
        self.reason_code = reason_code
        self.message = reason_code.value.lower().replace("_", " ")
        super().__init__(f"{reason_code.value}: {self.message}")

    def as_dict(self) -> dict[str, str]:
        return {"reason_code": self.reason_code.value, "message": self.message}
```

In `constants.py`, define every exact value from the three OpenSpec capability
specs. Use `frozenset` for shell/elevation registries and `str, Enum` or
`IntEnum` for closed values. Compile only identifier/digest syntax with
`re.ASCII`; safe user patterns belong to Task 3.

- [ ] **Step 4: Export only the stable public surface**

`__init__.py` imports and lists in `__all__`:

```python
from .errors import ContractError, ReasonCode

__all__ = ["ContractError", "ReasonCode"]
```

Do not re-export all constants; consumers import them from
`engagement_v2.constants` so version changes stay explicit.

- [ ] **Step 5: Run focused verification**

Run:

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_constants.py -q
.venv/bin/ruff check src/hackbot/engagement_v2 tests/engagement_v2
.venv/bin/mypy src/hackbot/engagement_v2
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit Task 1**

```bash
git add src/hackbot/engagement_v2 tests/engagement_v2
git commit -m "feat: add engagement v2 contract registry"
```

---

### Task 2: Strict canonical values and domain-separated digests

**Files:**

- Create: `src/hackbot/engagement_v2/canonical.py`
- Create: `tests/engagement_v2/test_canonical.py`
- Create: `tests/fixtures/engagement_v2/canonical/authority-input.json`
- Create: `tests/fixtures/engagement_v2/canonical/authority-canonical.json`
- Create: `tests/fixtures/engagement_v2/canonical/authority-digest.txt`

**Interfaces:**

- Consumes: `ContractError`, `ReasonCode`, signed 64-bit constants.
- Produces:
  `canonical_bytes(value: object) -> bytes`,
  `digest_value(value: object) -> str`,
  `authority_digest(projection: object) -> str`,
  `execution_digest(projection: object) -> str`.

- [ ] **Step 1: Write failing canonicalization tests**

Cover primitive acceptance and every rejection:

```python
import json

import pytest

from hackbot.engagement_v2.canonical import (
    authority_digest,
    canonical_bytes,
    execution_digest,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode


def test_canonical_bytes_sort_keys_and_preserve_ordered_lists() -> None:
    value = {"z": ["second", "first"], "a": {"enabled": True, "count": 2}}
    assert canonical_bytes(value) == (
        b'{"a":{"count":2,"enabled":true},"z":["second","first"]}'
    )


@pytest.mark.parametrize(
    "value",
    [
        1.0,
        b"raw",
        2**63,
        {"Bad-Key": "value"},
        {"value": "e\u0301"},
        {"value": "\u0000"},
        {"value": "\ud800"},
    ],
)
def test_invalid_canonical_value_fails_closed(value: object) -> None:
    with pytest.raises(ContractError) as caught:
        canonical_bytes(value)
    assert caught.value.reason_code is ReasonCode.INVALID_CANONICAL_VALUE


def test_digest_domains_are_distinct() -> None:
    projection = {"schema_version": 1, "profile": "private-pentest"}
    assert authority_digest(projection) != execution_digest(projection)
```

Read the three canonical fixtures and assert exact bytes/digest rather than
recomputing expected values inside the assertion.

- [ ] **Step 2: Run tests and confirm missing canonical module**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_canonical.py -q
```

Expected: collection fails because `hackbot.engagement_v2.canonical` does not
exist.

- [ ] **Step 3: Implement recursive strict validation**

Use a single recursive function with a depth counter:

```python
def _validated(value: object, *, depth: int = 0) -> object:
    if depth > MAX_NESTING_DEPTH:
        raise ContractError(ReasonCode.INVALID_LIMIT)
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not INT64_MIN <= value <= INT64_MAX:
            raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)
        return value
    if type(value) is str:
        if unicodedata.normalize("NFC", value) != value:
            raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)
        if any(
            0xD800 <= ord(c) <= 0xDFFF
            or ord(c) <= 0x1F
            or 0x7F <= ord(c) <= 0x9F
            for c in value
        ):
            raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)
        return value
    if type(value) is list or type(value) is tuple:
        return [_validated(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or IDENTIFIER_RE.fullmatch(key) is None:
                raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)
            result[key] = _validated(item, depth=depth + 1)
        return result
    raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)
```

Serialize with:

```python
json.dumps(
    _validated(value),
    ensure_ascii=False,
    allow_nan=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
```

The domain helpers hash
`{"contract": "hackbot-authority-v1", "value": projection}` and
`{"contract": "hackbot-execution-v1", "value": projection}` respectively.

- [ ] **Step 4: Add deterministic golden fixtures**

Use only `example.invalid`, synthetic hashes, and no secret references. Write
the canonical file with no trailing newline; write the digest text with one
trailing newline. Compute the initial expected value once with the implemented
function, inspect it, then freeze it in the fixture.

- [ ] **Step 5: Run focused verification**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_canonical.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/canonical.py tests/engagement_v2/test_canonical.py
.venv/bin/mypy src/hackbot/engagement_v2/canonical.py
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/hackbot/engagement_v2/canonical.py tests/engagement_v2/test_canonical.py tests/fixtures/engagement_v2/canonical
git commit -m "feat: add canonical engagement digests"
```

---

### Task 3: Bounded safe-fullmatch grammar

**Files:**

- Create: `src/hackbot/engagement_v2/patterns.py`
- Create: `tests/engagement_v2/test_patterns.py`
- Create: `tests/fixtures/engagement_v2/patterns/cases.json`

**Interfaces:**

- Consumes: pattern size/repetition constants and `ContractError`.
- Produces:
  `compile_safe_pattern(source: str) -> SafePattern`,
  `safe_fullmatch(pattern: SafePattern, value: str) -> bool`.

- [ ] **Step 1: Write failing parser/matcher tests**

```python
import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.patterns import compile_safe_pattern, safe_fullmatch


@pytest.mark.parametrize(
    ("source", "value", "expected"),
    [
        (r"[A-Za-z0-9._\-]{1,64}", "dc01.corp", True),
        (r"[0-9]{1,5}", "65535", True),
        (r"[0-9]{1,5}", "65536x", False),
        (r"host\{1\}", "host{1}", True),
        (r"ab{0,2}c", "ac", True),
    ],
)
def test_safe_fullmatch_cases(source: str, value: str, expected: bool) -> None:
    assert safe_fullmatch(compile_safe_pattern(source), value) is expected


@pytest.mark.parametrize(
    "source",
    ["(a+)+", "a|b", ".*", "^a$", r"(?!a)", r"\1", "a+", "a?", "a{0,1025}"],
)
def test_unsafe_constructs_are_rejected(source: str) -> None:
    with pytest.raises(ContractError) as caught:
        compile_safe_pattern(source)
    assert caught.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST
```

Add 256-byte accepted and 257-byte rejected cases, class length 64/65, invalid
ranges, unclosed escapes/classes/quantifiers, non-ASCII input, and a test that
the matcher performs no recursive calls or `re` compilation.

- [ ] **Step 2: Run tests and confirm missing pattern module**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_patterns.py -q
```

Expected: collection fails because `hackbot.engagement_v2.patterns` does not
exist.

- [ ] **Step 3: Implement immutable atoms and parser**

Define:

```python
@dataclass(frozen=True, slots=True)
class CharacterSet:
    characters: frozenset[str]
    negated: bool = False

    def accepts(self, character: str) -> bool:
        present = character in self.characters
        return not present if self.negated else present


@dataclass(frozen=True, slots=True)
class PatternAtom:
    matcher: CharacterSet
    minimum: int
    maximum: int


@dataclass(frozen=True, slots=True)
class SafePattern:
    source: str
    atoms: tuple[PatternAtom, ...]
```

The parser advances an integer index, accepts only the exact grammar from the
OpenSpec action capability, expands only `A-Z`, `a-z`, and `0-9` ranges, and
attaches one optional bounded quantifier to the immediately preceding atom.
Any other punctuation raises `INVALID_ACTION_MANIFEST`.

- [ ] **Step 4: Implement non-backtracking matching**

Maintain reachable input positions for each atom:

```python
positions = {0}
for atom in pattern.atoms:
    next_positions: set[int] = set()
    for start in positions:
        end = start
        if atom.minimum == 0:
            next_positions.add(start)
        for count in range(1, atom.maximum + 1):
            if end >= len(value) or not atom.matcher.accepts(value[end]):
                break
            end += 1
            if count >= atom.minimum:
                next_positions.add(end)
    positions = next_positions
    if not positions:
        return False
return len(value) in positions
```

Reject non-ASCII/control input before matching. Add an internal operation
counter capped at `(len(value) + 1) * (len(atoms) + 1) * 1025`; exceeding it
raises `INVALID_LIMIT` instead of continuing.

- [ ] **Step 5: Freeze synthetic fixture cases and verify**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_patterns.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/patterns.py tests/engagement_v2/test_patterns.py
.venv/bin/mypy src/hackbot/engagement_v2/patterns.py
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit Task 3**

```bash
git add src/hackbot/engagement_v2/patterns.py tests/engagement_v2/test_patterns.py tests/fixtures/engagement_v2/patterns
git commit -m "feat: add bounded action pattern grammar"
```

---

### Task 4: Code-owned JSON schemas and drift-proof exporter

**Files:**

- Create: `src/hackbot/engagement_v2/schemas.py`
- Create: `scripts/export_engagement_v2_schemas.py`
- Create: `tests/engagement_v2/test_schemas.py`
- Create: `schemas/engagement-v2/*.schema.json`
- Create: `schemas/engagement-v2/manifest.json`

**Interfaces:**

- Consumes: exact constants/enums and `canonical_bytes`.
- Produces:
  `schema_documents() -> dict[str, dict[str, object]]`,
  `render_schema_files() -> dict[str, bytes]`.
- Exporter modes:
  default atomic write and `--check` exact-byte drift check.

- [ ] **Step 1: Write failing schema contract tests**

```python
from hackbot.engagement_v2.schemas import render_schema_files, schema_documents


EXPECTED = {
    "program.schema.json",
    "scope.schema.json",
    "authorization.schema.json",
    "actions.schema.json",
    "action-request.schema.json",
    "runner.schema.json",
    "remote-header.schema.json",
    "manifest.json",
}


def test_schema_set_and_draft_are_exact() -> None:
    docs = schema_documents()
    assert set(docs) == EXPECTED - {"manifest.json"}
    assert all(
        value["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        for value in docs.values()
    )
    assert all(value["additionalProperties"] is False for value in docs.values())


def test_schema_bytes_match_committed_files() -> None:
    rendered = render_schema_files()
    for name, expected in rendered.items():
        assert (SCHEMA_ROOT / name).read_bytes() == expected
```

Add assertions for every artifact version, required top-level key, profile and
security enum, numeric bound, identifier pattern, collection cap, and protocol
limit. Assert authorization requires the 71-character `sha256:` digest syntax.

- [ ] **Step 2: Run tests and confirm missing schema module**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_schemas.py -q
```

Expected: collection fails because `hackbot.engagement_v2.schemas` does not
exist.

- [ ] **Step 3: Implement strict schema helpers**

Use a helper that always closes objects:

```python
def _object(
    properties: dict[str, object],
    required: tuple[str, ...],
) -> dict[str, object]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }
```

Each schema has a stable URN such as
`urn:hackbot:schema:engagement-v2:program:2`. Use `$defs` for shared identifier,
digest, enum, target, and strict-boolean definitions. Do not encode defaults
that grant permission; sensitive missing-value normalization belongs to P1.

`render_schema_files()` uses sorted, indented JSON with a final newline. It
builds `manifest.json` last with:

```json
{
  "contract": "hackbot-engagement-v2-schemas-v1",
  "files": [
    {
      "name": "program.schema.json",
      "schema_id": "urn:hackbot:schema:engagement-v2:program:2",
      "sha256": "64 lowercase hexadecimal characters"
    }
  ]
}
```

Entries are sorted by filename.

- [ ] **Step 4: Implement atomic exporter**

The script imports `render_schema_files`, supports only optional `--check`,
creates `schemas/engagement-v2`, rejects symlink destinations, writes each file
to an exclusive sibling temporary file with mode `0600`, fsyncs, replaces, and
removes leftovers in `finally`. `--check` performs no writes and exits 1 with
the differing filenames.

- [ ] **Step 5: Generate, inspect, and verify schemas**

```bash
.venv/bin/python scripts/export_engagement_v2_schemas.py
.venv/bin/python scripts/export_engagement_v2_schemas.py --check
.venv/bin/python -m pytest tests/engagement_v2/test_schemas.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/schemas.py scripts/export_engagement_v2_schemas.py tests/engagement_v2/test_schemas.py
.venv/bin/mypy src/hackbot/engagement_v2/schemas.py
```

Expected: generated files are reviewable JSON and all commands exit 0.

- [ ] **Step 6: Commit Task 4**

```bash
git add src/hackbot/engagement_v2/schemas.py scripts/export_engagement_v2_schemas.py tests/engagement_v2/test_schemas.py schemas/engagement-v2
git commit -m "feat: publish engagement v2 schemas"
```

---

### Task 5: Allocation-bounded remote framing and run binding

**Files:**

- Create: `src/hackbot/engagement_v2/protocol.py`
- Create: `tests/engagement_v2/test_protocol.py`
- Create: `tests/fixtures/engagement_v2/protocol/request-header.json`
- Create: `tests/fixtures/engagement_v2/protocol/request-frame.bin`
- Create: `tests/fixtures/engagement_v2/protocol/request-message.bin`

**Interfaces:**

- Consumes: protocol constants, `canonical_bytes`, `execution_digest`,
  `ContractError`.
- Produces:
  `FrameType`, `Frame`, `FramedMessage`, `RunBinding`,
  `write_message(stream, message)`, `read_message(stream, response=False)`,
  `response_chain(execution_digest_value, frames)`.

- [ ] **Step 1: Write failing framing tests**

```python
import hashlib
import struct
from io import BytesIO

import pytest

from hackbot.engagement_v2.canonical import canonical_bytes
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.protocol import (
    Frame,
    FrameType,
    FramedMessage,
    read_message,
    write_message,
)


def _request_header(payload: bytes, *, declared_length: int | None = None) -> dict[str, object]:
    length = len(payload) if declared_length is None else declared_length
    payload_digest = hashlib.sha256(payload).hexdigest()
    return {
        "protocol_version": 1,
        "run_id": "123e4567-e89b-42d3-a456-426614174000",
        "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "issued_at": "2026-07-26T12:00:00Z",
        "expires_at": "2026-07-26T12:05:00Z",
        "authority_digest": "sha256:" + "1" * 64,
        "execution_digest": "sha256:" + "2" * 64,
        "action_id": "operator.fixture",
        "argv_projection": ["/usr/bin/true"],
        "executable_path": "/usr/bin/true",
        "executable_digest": "sha256:" + "3" * 64,
        "runner_identity": "runner.fixture",
        "operating_system": "linux",
        "architecture": "x86_64",
        "required_privileges": [],
        "frame_descriptors": [
            {
                "index": 0,
                "frame_type": 2,
                "length": length,
                "sha256": payload_digest,
            }
        ],
        "timeout_seconds": 60,
        "stdout_cap_bytes": 4096,
        "stderr_cap_bytes": 4096,
    }


def test_message_round_trip_is_byte_stable() -> None:
    payload = b"synthetic"
    message = FramedMessage(
        header=_request_header(payload),
        frames=(Frame(FrameType.ARTIFACT, payload),),
    )
    stream = BytesIO()
    write_message(stream, message)
    encoded = stream.getvalue()
    assert encoded.startswith(b"HBV2RUN\x00\x00\x01")
    assert read_message(BytesIO(encoded)) == message


def test_oversized_declared_frame_fails_before_payload_read() -> None:
    header = canonical_bytes(_request_header(b"", declared_length=67_108_865))
    forged = (
        struct.pack("!8sHIH", b"HBV2RUN\x00", 1, len(header), 1)
        + header
        + struct.pack("!HQ32s", 2, 67_108_865, b"\x00" * 32)
    )
    with pytest.raises(ContractError) as caught:
        read_message(BytesIO(forged))
    assert caught.value.reason_code is ReasonCode.EXEC_PROTOCOL_INVALID
```

Also test wrong magic/version, truncated fixed header/header/frame, header cap,
frame count, request/response direction, aggregate caps, payload digest,
trailing bytes, canonical header mismatch, UUIDv4, nonce, UTC seconds,
expiry 1/300/301, 30-second skew, digest syntax, response echoes, and exact
hash-chain bytes.

- [ ] **Step 2: Run tests and confirm missing protocol module**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_protocol.py -q
```

Expected: collection fails because `hackbot.engagement_v2.protocol` does not
exist.

- [ ] **Step 3: Implement immutable values and exact-length reads**

```python
_PREFIX = struct.Struct("!8sHIH")
_FRAME_PREFIX = struct.Struct("!HQ32s")


def _read_exact(stream: BinaryIO, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise ContractError(ReasonCode.EXEC_PROTOCOL_INVALID)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
```

Validate prefix lengths before calling `_read_exact`. Maintain `total_bytes`
starting at fixed-prefix size and reject the applicable request/response cap
before every read. Parse the header with strict duplicate-key JSON decoding,
then require `canonical_bytes(header) == raw_header`.

`Frame.__post_init__` requires exact `FrameType`, exact `bytes`, direction
checked by `FramedMessage`/codec, and a payload within the frame cap.

- [ ] **Step 4: Implement run binding and response chain**

`RunBinding` validates:

```python
@dataclass(frozen=True, slots=True)
class RunBinding:
    run_id: str
    nonce: str
    issued_at: datetime
    expires_at: datetime
    authority_digest: str
    execution_digest: str
```

Use `uuid.UUID(value, version=4)` plus exact canonical string comparison,
`base64.urlsafe_b64decode(nonce + "=")`, timezone-aware UTC seconds, and
`1 <= expires_at-issued_at <= 300`. The expiry helper receives `now` explicitly
for deterministic tests and accepts at most 30 seconds of skew.

For response frames:

```python
chain = bytes.fromhex(execution_digest_value.removeprefix("sha256:"))
for frame in frames:
    payload_digest = hashlib.sha256(frame.payload).digest()
    chain = hashlib.sha256(
        chain
        + struct.pack("!H", frame.frame_type)
        + struct.pack("!Q", len(frame.payload))
        + payload_digest
    ).digest()
return chain.hex()
```

- [ ] **Step 5: Freeze deterministic protocol fixtures**

Use a fixed synthetic UUID, zero nonce bytes, fixed UTC times, example.invalid
identity, and payload `b"synthetic-artifact"`. Inspect the binary fixture with:

```bash
xxd tests/fixtures/engagement_v2/protocol/request-message.bin
shasum -a 256 tests/fixtures/engagement_v2/protocol/*
```

Store expected fixture hashes in `test_protocol.py`.

- [ ] **Step 6: Run focused verification**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_protocol.py -q
.venv/bin/ruff check src/hackbot/engagement_v2/protocol.py tests/engagement_v2/test_protocol.py
.venv/bin/mypy src/hackbot/engagement_v2/protocol.py
```

Expected: all commands exit 0.

- [ ] **Step 7: Commit Task 5**

```bash
git add src/hackbot/engagement_v2/protocol.py tests/engagement_v2/test_protocol.py tests/fixtures/engagement_v2/protocol
git commit -m "feat: add bounded remote framing contract"
```

---

### Task 6: Fixture regeneration and reproducibility guard

**Files:**

- Create: `scripts/generate_engagement_v2_contract_fixtures.py`
- Modify: `tests/engagement_v2/test_canonical.py`
- Modify: `tests/engagement_v2/test_patterns.py`
- Modify: `tests/engagement_v2/test_protocol.py`
- Create: `tests/engagement_v2/test_fixture_generation.py`

**Interfaces:**

- Consumes: canonical, pattern, and protocol public P0 interfaces.
- Produces: deterministic `generate(root: Path, *, check: bool) -> tuple[str, ...]`.
- `--check` returns exit 1 and differing relative paths without writes.

- [ ] **Step 1: Write a failing no-write drift test**

```python
def test_fixture_check_detects_drift_without_writing(tmp_path: Path) -> None:
    copy_fixture_tree(tmp_path)
    changed = tmp_path / "canonical" / "authority-digest.txt"
    changed.write_text("sha256:" + "0" * 64 + "\n", encoding="ascii")
    before = changed.read_bytes()

    differing = generate(tmp_path, check=True)

    assert differing == ("canonical/authority-digest.txt",)
    assert changed.read_bytes() == before
```

Add a clean-tree test and assert generated fixture content contains none of:
`secret:`, `password`, `token`, private IP ranges, real domains, or user home
paths.

- [ ] **Step 2: Run test and confirm missing generator**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_fixture_generation.py -q
```

Expected: import or file-not-found failure for the generator.

- [ ] **Step 3: Implement deterministic generator**

The script builds all fixture bytes in memory, sorts relative paths, writes
atomically in update mode, and never uses current time, randomness, hostname,
username, current directory, or environment. CLI accepts only `--check`.

- [ ] **Step 4: Regenerate and verify exact stability**

```bash
.venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py
.venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py --check
.venv/bin/python -m pytest tests/engagement_v2/test_fixture_generation.py tests/engagement_v2/test_canonical.py tests/engagement_v2/test_patterns.py tests/engagement_v2/test_protocol.py -q
```

Expected: generator check and all tests exit 0.

- [ ] **Step 5: Commit Task 6**

```bash
git add scripts/generate_engagement_v2_contract_fixtures.py tests/engagement_v2 tests/fixtures/engagement_v2
git commit -m "test: make v2 contract fixtures reproducible"
```

---

### Task 7: Prove v1 isolation and document the P0 boundary

**Files:**

- Create: `tests/engagement_v2/test_v1_isolation.py`
- Create: `docs/engagement-v2-contracts.md`
- Modify: `docs/next-steps.md`
- Modify: `docs/openspec-and-github-project-workflow.md`

**Interfaces:**

- Consumes: P0 public interfaces and repository source tree.
- Produces: a guard against accidental v2 activation and operator-facing
  contract/export documentation.

- [ ] **Step 1: Write a failing isolation guard**

```python
from pathlib import Path


V1_ROOTS = (
    Path("src/hackbot/cli"),
    Path("src/hackbot/programs"),
    Path("src/hackbot/risk"),
    Path("src/hackbot/scope"),
    Path("src/hackbot/tools"),
)


def test_v1_runtime_does_not_import_engagement_v2() -> None:
    offenders = []
    for root in V1_ROOTS:
        for path in root.rglob("*.py"):
            if "hackbot.engagement_v2" in path.read_text(encoding="utf-8"):
                offenders.append(path.as_posix())
    assert offenders == []


def test_current_runtime_schema_remains_v1() -> None:
    from hackbot.programs.schema import SCHEMA_VERSION

    assert SCHEMA_VERSION == 1
```

Initially make the documentation-presence assertion fail:

```python
def test_contract_document_declares_v2_unavailable() -> None:
    text = Path("docs/engagement-v2-contracts.md").read_text(encoding="utf-8")
    assert "P0 does not enable engagement v2 execution" in text
```

- [ ] **Step 2: Run guard and confirm only documentation is missing**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_v1_isolation.py -q
```

Expected: import/schema guards pass; documentation assertion fails with
`FileNotFoundError`.

- [ ] **Step 3: Write contract documentation**

Document:

- P0 purpose and exact non-activation statement;
- module/interface map;
- canonical value restrictions and digest domain separation;
- safe-pattern grammar summary;
- schema generation/check commands;
- fixture generation/check commands;
- protocol caps and the fact that no SSH/helper/replay cache exists in P0;
- mapping from P0 to P1/P2/P4 consumers;
- links to the OpenSpec change and Issue #1.

Update `docs/next-steps.md` so P0 is current/Ready and P1–P7 remain dependent.
Update the workflow inventory with the active OpenSpec path
`openspec/changes/engagement-v2-security-contracts/`.

- [ ] **Step 4: Run focused documentation/isolation verification**

```bash
.venv/bin/python -m pytest tests/engagement_v2/test_v1_isolation.py -q
git diff --check
```

Expected: both commands exit 0.

- [ ] **Step 5: Commit Task 7**

```bash
git add tests/engagement_v2/test_v1_isolation.py docs/engagement-v2-contracts.md docs/next-steps.md docs/openspec-and-github-project-workflow.md
git commit -m "docs: define engagement v2 contract boundary"
```

---

### Task 8: Full verification, review, OpenSpec, and Project handoff

**Files:**

- Modify: `openspec/changes/engagement-v2-security-contracts/tasks.md`
- Modify only if evidence requires correction:
  `openspec/changes/engagement-v2-security-contracts/**/*.md`
- External: GitHub Issue #1 and Project #2 fields

**Interfaces:**

- Consumes: every P0 deliverable.
- Produces: fresh verification evidence and a reviewed change ready for archive
  only after merge.

- [ ] **Step 1: Run all P0-focused gates**

```bash
.venv/bin/python -m pytest tests/engagement_v2 -q
.venv/bin/python scripts/export_engagement_v2_schemas.py --check
.venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py --check
```

Expected: all exit 0.

- [ ] **Step 2: Run repository-wide gates**

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
OPENSPEC_TELEMETRY=0 openspec validate engagement-v2-security-contracts --type change --strict --no-interactive
git diff --check
```

Expected: all exit 0; record the fresh pytest pass/skip counts.

- [ ] **Step 3: Run publication and secret guards**

```bash
.venv/bin/python -m pytest tests/publication_guard -q
! rg -n '(gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9]{32,})' src/hackbot/engagement_v2 schemas/engagement-v2 tests/fixtures/engagement_v2 docs/engagement-v2-contracts.md
```

Expected: publication tests pass and the secret scan produces no match.

- [ ] **Step 4: Request two-stage review**

Use `superpowers:requesting-code-review` for:

1. spec compliance against all three OpenSpec capability specs;
2. code quality/security review of canonicalization, pattern complexity,
   schema drift, framing allocation, error secrecy, and v1 isolation.

Resolve every Critical/Important finding through the same task implementer,
rerun the focused and full gates, and document any rejected suggestion with
technical evidence.

- [ ] **Step 5: Complete OpenSpec task checkboxes**

Change each OpenSpec task from `[ ]` to `[x]` only after its stated verification
has passed. Then run:

```bash
OPENSPEC_TELEMETRY=0 openspec status --change engagement-v2-security-contracts --json
OPENSPEC_TELEMETRY=0 openspec validate engagement-v2-security-contracts --type change --strict --no-interactive --json
```

Expected: artifacts complete, task progress complete, strict validation valid.

- [ ] **Step 6: Commit final verification adjustments**

```bash
git add openspec/changes/engagement-v2-security-contracts
git commit -m "test: verify engagement v2 security contracts"
```

Skip this commit only when the OpenSpec task file was already committed with
the final implementation commit and no review adjustment exists.

- [ ] **Step 7: Publish through review workflow**

Push the implementation branch, open a draft PR linked to Issue #1, set Project
`Delivery Status=In Review` and built-in `Status=In Progress`, and include exact
gate outputs in the PR body. Do not archive the OpenSpec change before merge.

- [ ] **Step 8: Archive after merge**

After merge to `main`, verify the remote merge SHA and all required checks, then
run the OpenSpec archive workflow so the three delta specs become current
specs. Set Issue #1 and Project item to Done only after archive is committed and
pushed. Move P1 from Backlog to Ready.
