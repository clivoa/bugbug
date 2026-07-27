"""Tests for allocation-bounded engagement-v2 protocol primitives."""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import tracemalloc
from datetime import UTC, datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

import pytest

import hackbot.engagement_v2.protocol as protocol
from hackbot.engagement_v2.canonical import canonical_bytes, execution_digest
from hackbot.engagement_v2.constants import (
    MAX_CLOCK_SKEW_SECONDS,
    MAX_FRAME_BYTES,
    MAX_FRAME_COUNT,
    MAX_PROTOCOL_HEADER_BYTES,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.protocol import (
    Frame,
    FramedMessage,
    FrameType,
    RunBinding,
    read_message,
    response_chain,
    write_message,
)

_PREFIX = struct.Struct("!8sHIH")
_FRAME_PREFIX = struct.Struct("!HQ32s")
_RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
_NONCE = base64.urlsafe_b64encode(b"\x00" * 32).decode("ascii").rstrip("=")
_AUTHORITY_DIGEST = "sha256:" + "1" * 64
_FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "engagement_v2" / "protocol"
_FIXTURE_HASHES = {
    "request-frame.bin": "4bb15f8f8b9731fe3169e4f948263c5c3ce8b33b3106d828adbae091b0e4064b",
    "request-header.json": "50ec1ad9750fdc919b0ce8358d0bfe47425dacf417ec5271fbf21de9f4b7e096",
    "request-message.bin": "332d44b38bb1730f4ce6fe11f671b62f95b0309e16fd0f7b98e90c9c1080fdd9",
}


class _ShortReadStream(BytesIO):
    """A stream which returns short non-empty chunks before EOF."""

    def __init__(self, value: bytes, *, chunk_size: int = 3) -> None:
        super().__init__(value)
        self.chunk_size = chunk_size
        self.read_sizes: list[int] = []

    def read(self, size: int = -1, /) -> bytes:
        self.read_sizes.append(size)
        if size < 0:
            return super().read(size)
        return super().read(min(size, self.chunk_size))


class _OneByteReadStream:
    """A bounded stream returning one byte per exact-read call."""

    def __init__(self, size: int) -> None:
        self.remaining = size
        self.calls = 0

    def read(self, size: int = -1, /) -> bytes:
        self.calls += 1
        if self.remaining == 0:
            return b""
        assert size > 0
        self.remaining -= 1
        return b"x"


class _GuardedReadStream:
    """A deterministic stream that fails if reading reaches a forbidden offset."""

    def __init__(self, value: bytes, *, forbidden_offset: int) -> None:
        self._value = value
        self._offset = 0
        self.forbidden_offset = forbidden_offset
        self.reads: list[tuple[int, int]] = []

    def read(self, size: int = -1, /) -> bytes:
        self.reads.append((self._offset, size))
        if self._offset >= self.forbidden_offset:
            raise AssertionError("decoder read past the validated prefix")
        if size < 0:
            size = len(self._value) - self._offset
        end = min(self._offset + size, len(self._value))
        chunk = self._value[self._offset : end]
        self._offset = end
        return chunk


class _BytesSubclass(bytes):
    """A bytes subclass which exact frame payloads must reject."""


class _DictSubclass(dict[str, object]):
    """A dict subclass which exact message headers must reject."""


def _descriptor(index: int, frame_type: FrameType, payload: bytes) -> dict[str, object]:
    return {
        "index": index,
        "frame_type": frame_type.value,
        "length": len(payload),
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }


def _bind_request_header(header: dict[str, object]) -> None:
    request = {key: value for key, value in header.items() if key != "execution_digest"}
    header["execution_digest"] = execution_digest({"schema_version": 1, "request": request})


def _request_header(
    frames: tuple[tuple[FrameType, bytes], ...] = (),
    *,
    issued_at: str = "2026-07-26T12:00:00Z",
    expires_at: str = "2026-07-26T12:05:00Z",
) -> dict[str, object]:
    header: dict[str, object] = {
        "protocol_version": PROTOCOL_VERSION,
        "run_id": _RUN_ID,
        "nonce": _NONCE,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "authority_digest": _AUTHORITY_DIGEST,
        "action_id": "operator.fixture",
        "argv": ["/usr/bin/true"],
        "executable": {
            "path": "/usr/bin/true",
            "sha256": "sha256:" + "3" * 64,
        },
        "runner_identity": "runner.example.invalid",
        "operating_system": "linux",
        "architecture": "x86_64",
        "required_privileges": [],
        "frames": [
            _descriptor(index, frame_type, payload)
            for index, (frame_type, payload) in enumerate(frames)
        ],
        "timeout_seconds": 60,
        "stdout_cap_bytes": 4096,
        "stderr_cap_bytes": 4096,
    }
    _bind_request_header(header)
    return header


def _response_header(
    frames: tuple[tuple[FrameType, bytes], ...] = (),
) -> dict[str, object]:
    execution_digest_value = _request_header()["execution_digest"]
    return {
        "protocol_version": PROTOCOL_VERSION,
        "run_id": _RUN_ID,
        "nonce": _NONCE,
        "authority_digest": _AUTHORITY_DIGEST,
        "execution_digest": execution_digest_value,
        "frames": [
            _descriptor(index, frame_type, payload)
            for index, (frame_type, payload) in enumerate(frames)
        ],
    }


def _wire_bytes(
    header: dict[str, object],
    frames: tuple[tuple[int, bytes], ...] = (),
    *,
    magic: bytes = PROTOCOL_MAGIC,
    version: int = PROTOCOL_VERSION,
    raw_header: bytes | None = None,
    frame_count: int | None = None,
) -> bytes:
    encoded_header = canonical_bytes(header) if raw_header is None else raw_header
    encoded_frames = b"".join(
        _FRAME_PREFIX.pack(frame_type, len(payload), hashlib.sha256(payload).digest()) + payload
        for frame_type, payload in frames
    )
    return (
        _PREFIX.pack(
            magic,
            version,
            len(encoded_header),
            len(frames) if frame_count is None else frame_count,
        )
        + encoded_header
        + encoded_frames
    )


def _assert_reason(reason_code: ReasonCode, operation: object) -> None:
    assert callable(operation)
    with pytest.raises(ContractError) as caught:
        operation()
    assert caught.value.reason_code is reason_code


def test_message_round_trip_is_byte_stable_with_short_reads() -> None:
    payload = b"synthetic"
    message = FramedMessage(
        header=_request_header(((FrameType.ARTIFACT, payload),)),
        frames=(Frame(FrameType.ARTIFACT, payload),),
    )
    stream = BytesIO()

    write_message(stream, message)

    encoded = stream.getvalue()
    assert encoded.startswith(b"HBV2RUN\x00\x00\x01")
    short_stream = _ShortReadStream(encoded)
    assert read_message(short_stream) == message
    assert len(short_stream.read_sizes) > 6


def test_exact_read_does_not_retain_one_object_per_one_byte_read() -> None:
    stream = _OneByteReadStream(MAX_PROTOCOL_HEADER_BYTES)

    tracemalloc.start()
    try:
        value = protocol._read_exact(stream, MAX_PROTOCOL_HEADER_BYTES)
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert value == b"x" * MAX_PROTOCOL_HEADER_BYTES
    assert stream.calls == MAX_PROTOCOL_HEADER_BYTES
    assert peak_bytes < MAX_PROTOCOL_HEADER_BYTES * 4


@pytest.mark.parametrize(
    ("offset", "description"),
    [
        (0, "empty"),
        (_PREFIX.size - 1, "fixed prefix"),
    ],
)
def test_truncated_fixed_prefix_fails(offset: int, description: str) -> None:
    del description
    encoded = _wire_bytes(_request_header())

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: read_message(BytesIO(encoded[:offset])),
    )


@pytest.mark.parametrize(
    ("magic", "version"),
    [
        (b"HBV1RUN\x00", PROTOCOL_VERSION),
        (PROTOCOL_MAGIC, 0),
        (PROTOCOL_MAGIC, PROTOCOL_VERSION + 1),
    ],
)
def test_wrong_magic_or_version_fails(magic: bytes, version: int) -> None:
    encoded = _wire_bytes(_request_header(), magic=magic, version=version)

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: read_message(BytesIO(encoded)),
    )


def test_header_cap_fails_before_header_read() -> None:
    prefix = _PREFIX.pack(PROTOCOL_MAGIC, PROTOCOL_VERSION, MAX_PROTOCOL_HEADER_BYTES + 1, 0)
    stream = _GuardedReadStream(prefix, forbidden_offset=_PREFIX.size)

    _assert_reason(ReasonCode.EXEC_PROTOCOL_INVALID, lambda: read_message(stream))

    assert stream.reads == [(0, _PREFIX.size)]


def test_frame_count_cap_fails_before_header_read() -> None:
    prefix = _PREFIX.pack(PROTOCOL_MAGIC, PROTOCOL_VERSION, 1, MAX_FRAME_COUNT + 1)
    stream = _GuardedReadStream(prefix, forbidden_offset=_PREFIX.size)

    _assert_reason(ReasonCode.EXEC_PROTOCOL_INVALID, lambda: read_message(stream))

    assert stream.reads == [(0, _PREFIX.size)]


def test_request_aggregate_cap_fails_before_header_read() -> None:
    prefix = _PREFIX.pack(PROTOCOL_MAGIC, PROTOCOL_VERSION, MAX_REQUEST_BYTES, 0)
    stream = _GuardedReadStream(prefix, forbidden_offset=_PREFIX.size)

    _assert_reason(ReasonCode.EXEC_PROTOCOL_INVALID, lambda: read_message(stream))

    assert stream.reads == [(0, _PREFIX.size)]


def test_truncated_header_fails_with_exact_length_read() -> None:
    header = canonical_bytes(_request_header())
    encoded = _PREFIX.pack(PROTOCOL_MAGIC, PROTOCOL_VERSION, len(header), 0) + header[:-1]

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: read_message(_ShortReadStream(encoded)),
    )


def test_invalid_utf8_duplicate_keys_and_noncanonical_header_fail() -> None:
    valid_header = _request_header()
    duplicate_header = canonical_bytes(valid_header)
    duplicate_header = duplicate_header[:-1] + b',"protocol_version":1}'
    spaced_header = json.dumps(valid_header, sort_keys=True).encode("utf-8")

    for raw_header in (b"\xff", duplicate_header, spaced_header):
        encoded = _wire_bytes(valid_header, raw_header=raw_header)
        _assert_reason(
            ReasonCode.EXEC_PROTOCOL_INVALID,
            lambda encoded=encoded: read_message(BytesIO(encoded)),
        )


def test_oversized_declared_frame_fails_before_frame_payload_read() -> None:
    header = _request_header()
    header["frames"] = [
        {
            "index": 0,
            "frame_type": FrameType.ARTIFACT.value,
            "length": MAX_FRAME_BYTES + 1,
            "sha256": "sha256:" + "0" * 64,
        }
    ]
    raw_header = canonical_bytes(header)
    fixed = _PREFIX.pack(PROTOCOL_MAGIC, PROTOCOL_VERSION, len(raw_header), 1) + raw_header
    frame_prefix = _FRAME_PREFIX.pack(
        FrameType.ARTIFACT.value,
        MAX_FRAME_BYTES + 1,
        b"\x00" * 32,
    )
    stream = _GuardedReadStream(
        fixed + frame_prefix,
        forbidden_offset=len(fixed) + len(frame_prefix),
    )

    _assert_reason(ReasonCode.EXEC_PROTOCOL_INVALID, lambda: read_message(stream))

    assert all(offset < stream.forbidden_offset for offset, _ in stream.reads)


def test_response_aggregate_cap_fails_before_any_frame_read() -> None:
    declared_length = MAX_RESPONSE_BYTES
    header = _response_header()
    header["frames"] = [
        {
            "index": 0,
            "frame_type": FrameType.STDOUT.value,
            "length": declared_length,
            "sha256": "sha256:" + "0" * 64,
        }
    ]
    raw_header = canonical_bytes(header)
    fixed = _PREFIX.pack(PROTOCOL_MAGIC, PROTOCOL_VERSION, len(raw_header), 1) + raw_header
    stream = _GuardedReadStream(fixed, forbidden_offset=len(fixed))

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: read_message(stream, response=True),
    )

    assert all(offset < stream.forbidden_offset for offset, _ in stream.reads)


def test_request_aggregate_cap_fails_before_any_frame_read() -> None:
    zero_digest = bytes.fromhex("3b6a07d0d404fab4e23b6d34bc6696a6a312dd92821332385e5af7c01c421351")
    header = _request_header()
    header["frames"] = [
        {
            "index": 0,
            "frame_type": FrameType.ARTIFACT.value,
            "length": MAX_FRAME_BYTES,
            "sha256": "sha256:" + zero_digest.hex(),
        },
        {
            "index": 1,
            "frame_type": FrameType.SECRET.value,
            "length": MAX_FRAME_BYTES,
            "sha256": "sha256:" + zero_digest.hex(),
        },
    ]
    _bind_request_header(header)
    raw_header = canonical_bytes(header)
    fixed = _PREFIX.pack(PROTOCOL_MAGIC, PROTOCOL_VERSION, len(raw_header), 2) + raw_header
    stream = _GuardedReadStream(fixed, forbidden_offset=len(fixed))

    _assert_reason(ReasonCode.EXEC_PROTOCOL_INVALID, lambda: read_message(stream))

    assert all(offset < stream.forbidden_offset for offset, _ in stream.reads)


def test_truncated_frame_prefix_and_payload_fail() -> None:
    payload = b"synthetic"
    header = _request_header(((FrameType.ARTIFACT, payload),))
    raw_header = canonical_bytes(header)
    fixed = _PREFIX.pack(PROTOCOL_MAGIC, PROTOCOL_VERSION, len(raw_header), 1) + raw_header
    frame_prefix = _FRAME_PREFIX.pack(
        FrameType.ARTIFACT.value,
        len(payload),
        hashlib.sha256(payload).digest(),
    )

    for encoded in (fixed + frame_prefix[:-1], fixed + frame_prefix + payload[:-1]):
        _assert_reason(
            ReasonCode.EXEC_PROTOCOL_INVALID,
            lambda encoded=encoded: read_message(_ShortReadStream(encoded)),
        )


def test_unknown_frame_type_wrong_direction_and_mixed_direction_fail() -> None:
    request_payload = b"request"
    response_payload = b"response"
    request_header = _request_header(((FrameType.ARTIFACT, request_payload),))
    response_header = _response_header(((FrameType.STDOUT, response_payload),))

    unknown = _wire_bytes(
        request_header,
        ((99, request_payload),),
    )
    request_as_response = _wire_bytes(
        request_header,
        ((FrameType.ARTIFACT.value, request_payload),),
    )
    response_as_request = _wire_bytes(
        response_header,
        ((FrameType.STDOUT.value, response_payload),),
    )

    for encoded, response in (
        (unknown, False),
        (request_as_response, True),
        (response_as_request, False),
    ):
        _assert_reason(
            ReasonCode.EXEC_PROTOCOL_INVALID,
            lambda encoded=encoded, response=response: read_message(
                BytesIO(encoded), response=response
            ),
        )

    mixed_header = _response_header(
        (
            (FrameType.STDOUT, response_payload),
            (FrameType.ARTIFACT, request_payload),
        )
    )
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: FramedMessage(
            header=mixed_header,
            frames=(
                Frame(FrameType.STDOUT, response_payload),
                Frame(FrameType.ARTIFACT, request_payload),
            ),
        ),
    )


def test_payload_digest_descriptor_mismatch_and_trailing_bytes_fail() -> None:
    payload = b"synthetic"
    header = _request_header(((FrameType.ARTIFACT, payload),))
    valid = _wire_bytes(header, ((FrameType.ARTIFACT.value, payload),))
    raw_header = canonical_bytes(header)
    fixed_length = _PREFIX.size + len(raw_header)
    digest_offset = fixed_length + 2 + 8
    corrupt_digest = valid[:digest_offset] + b"\xff" * 32 + valid[digest_offset + 32 :]

    mismatched_descriptor = _request_header(((FrameType.ARTIFACT, payload),))
    descriptors = mismatched_descriptor["frames"]
    assert type(descriptors) is list
    descriptor = descriptors[0]
    assert type(descriptor) is dict
    descriptor["length"] = len(payload) + 1
    mismatched_wire = _wire_bytes(
        mismatched_descriptor,
        ((FrameType.ARTIFACT.value, payload),),
    )

    for encoded in (corrupt_digest, mismatched_wire, valid + b"\x00"):
        _assert_reason(
            ReasonCode.EXEC_PROTOCOL_INVALID,
            lambda encoded=encoded: read_message(BytesIO(encoded)),
        )


def test_consistent_frame_substitution_retaining_execution_digest_fails() -> None:
    original_payload = b"original-artifact"
    substituted_payload = b"substitute-artifact"
    header = _request_header(((FrameType.ARTIFACT, original_payload),))
    original_execution_digest = header["execution_digest"]
    header["frames"] = [_descriptor(0, FrameType.ARTIFACT, substituted_payload)]
    assert original_execution_digest != execution_digest(
        {
            "schema_version": 1,
            "request": {key: value for key, value in header.items() if key != "execution_digest"},
        }
    )

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: FramedMessage(
            header=header,
            frames=(Frame(FrameType.ARTIFACT, substituted_payload),),
        ),
    )

    forged = _wire_bytes(
        header,
        ((FrameType.ARTIFACT.value, substituted_payload),),
    )
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: read_message(BytesIO(forged)),
    )


def test_frame_descriptors_require_exact_order_unique_indexes_and_hashes() -> None:
    first = b"first"
    second = b"second"
    frames = (
        Frame(FrameType.ARTIFACT, first),
        Frame(FrameType.SECRET, second),
    )
    header = _request_header(
        (
            (FrameType.ARTIFACT, first),
            (FrameType.SECRET, second),
        )
    )
    descriptors = header["frames"]
    assert type(descriptors) is list
    second_descriptor = descriptors[1]
    assert type(second_descriptor) is dict
    second_descriptor["index"] = 0

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: FramedMessage(header=header, frames=frames),
    )

    missing = _request_header(((FrameType.ARTIFACT, first),))
    missing["frames"] = []
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: FramedMessage(
            header=missing,
            frames=(Frame(FrameType.ARTIFACT, first),),
        ),
    )


def test_frame_and_message_values_are_exact_and_immutable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"synthetic"
    frame = Frame(FrameType.ARTIFACT, payload)
    message = FramedMessage(
        header=_request_header(((FrameType.ARTIFACT, payload),)),
        frames=(frame,),
    )

    with pytest.raises((AttributeError, TypeError)):
        frame.payload = b"changed"  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        message.header["protocol_version"] = 2  # type: ignore[index]

    monkeypatch.setattr(protocol, "MAX_FRAME_BYTES", 8)
    for operation in (
        lambda: Frame(2, b"x"),  # type: ignore[arg-type]
        lambda: Frame(FrameType.ARTIFACT, _BytesSubclass(b"x")),
        lambda: Frame(FrameType.ARTIFACT, b"\x00" * 9),
        lambda: FramedMessage(  # type: ignore[arg-type]
            header=_DictSubclass(_request_header()),
            frames=(),
        ),
        lambda: FramedMessage(header=_request_header(), frames=[]),  # type: ignore[arg-type]
    ):
        _assert_reason(ReasonCode.EXEC_PROTOCOL_INVALID, operation)


def test_write_rejects_short_write_and_aggregate_overflow_without_partial_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ShortWriteStream(BytesIO):
        def write(self, value: bytes, /) -> int:
            return max(0, len(value) - 1)

    payload = b"synthetic"
    message = FramedMessage(
        header=_request_header(((FrameType.ARTIFACT, payload),)),
        frames=(Frame(FrameType.ARTIFACT, payload),),
    )

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: write_message(ShortWriteStream(), message),
    )

    response_payload = b"response"
    response = FramedMessage(
        header=_response_header(((FrameType.STDOUT, response_payload),)),
        frames=(Frame(FrameType.STDOUT, response_payload),),
    )
    response_header_bytes = canonical_bytes(
        _response_header(((FrameType.STDOUT, response_payload),))
    )
    encoded_size = (
        _PREFIX.size + len(response_header_bytes) + _FRAME_PREFIX.size + len(response_payload)
    )
    monkeypatch.setattr(protocol, "MAX_RESPONSE_BYTES", encoded_size - 1)
    output = BytesIO()

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: write_message(output, response),
    )
    assert output.getvalue() == b""


def test_empty_request_is_deterministic_and_response_round_trip_uses_response_direction() -> None:
    request = FramedMessage(header=_request_header(), frames=())
    request_stream = BytesIO()
    write_message(request_stream, request)
    assert read_message(BytesIO(request_stream.getvalue())) == request

    payload = b"stdout"
    response = FramedMessage(
        header=_response_header(((FrameType.STDOUT, payload),)),
        frames=(Frame(FrameType.STDOUT, payload),),
    )
    response_stream = BytesIO()
    write_message(response_stream, response)

    assert read_message(BytesIO(response_stream.getvalue()), response=True) == response


def test_empty_response_direction_is_inferred_from_its_echo_header() -> None:
    response = FramedMessage(header=_response_header(), frames=())
    stream = BytesIO()

    write_message(stream, response)

    assert read_message(BytesIO(stream.getvalue()), response=True) == response


def test_request_argv_accepts_only_generated_schema_placeholder_grammar() -> None:
    valid_header = _request_header()
    valid_header["argv"] = ["/usr/bin/tool", "{target:primary}"]
    _bind_request_header(valid_header)
    message = FramedMessage(header=valid_header, frames=())
    stream = BytesIO()
    write_message(stream, message)
    assert read_message(BytesIO(stream.getvalue())) == message

    for invalid_token in (
        "prefix{target:primary}",
        "{unknown:primary}",
        "{target:Bad}",
        "{target:1-target}",
        "{target:target-name}",
        "{target:target.name}",
    ):
        invalid_header = _request_header()
        invalid_header["argv"] = [invalid_token]
        _bind_request_header(invalid_header)
        _assert_reason(
            ReasonCode.EXEC_PROTOCOL_INVALID,
            lambda invalid_header=invalid_header: FramedMessage(
                header=invalid_header,
                frames=(),
            ),
        )


def test_request_header_uses_exact_generated_schema_keys() -> None:
    unknown = _request_header()
    unknown["unexpected"] = True
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: FramedMessage(header=unknown, frames=()),
    )

    stale_illustration = _request_header()
    argv = stale_illustration.pop("argv")
    executable = stale_illustration.pop("executable")
    frames = stale_illustration.pop("frames")
    assert type(executable) is dict
    stale_illustration.update(
        {
            "argv_projection": argv,
            "executable_path": executable["path"],
            "executable_digest": executable["sha256"],
            "frame_descriptors": frames,
        }
    )
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: FramedMessage(header=stale_illustration, frames=()),
    )


def test_read_message_requires_an_exact_direction_flag() -> None:
    encoded = _wire_bytes(_request_header())

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: read_message(BytesIO(encoded), response=1),  # type: ignore[arg-type]
    )


def _binding_header(**changes: object) -> dict[str, object]:
    header = _request_header()
    header.update(changes)
    return header


def test_run_binding_parses_exact_header_values() -> None:
    header = _request_header()
    binding = RunBinding.from_header(header)
    execution_digest_value = header["execution_digest"]
    assert type(execution_digest_value) is str

    assert binding == RunBinding(
        run_id=_RUN_ID,
        nonce=_NONCE,
        issued_at=datetime(2026, 7, 26, 12, tzinfo=UTC),
        expires_at=datetime(2026, 7, 26, 12, 5, tzinfo=UTC),
        authority_digest=_AUTHORITY_DIGEST,
        execution_digest=execution_digest_value,
    )


@pytest.mark.parametrize(
    "run_id",
    [
        "123E4567-E89B-42D3-A456-426614174000",
        "123e4567-e89b-12d3-a456-426614174000",
        "123e4567e89b42d3a456426614174000",
        "not-a-uuid",
    ],
)
def test_run_binding_rejects_noncanonical_uuid_v4(run_id: str) -> None:
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: RunBinding.from_header(_binding_header(run_id=run_id)),
    )


@pytest.mark.parametrize(
    "nonce",
    [
        "A" * 42,
        "A" * 44,
        "A" * 42 + "B",
        "A" * 42 + "_",
        "+" + "A" * 42,
    ],
)
def test_run_binding_rejects_noncanonical_32_byte_nonce(nonce: str) -> None:
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: RunBinding.from_header(_binding_header(nonce=nonce)),
    )


@pytest.mark.parametrize(
    ("issued_at", "expires_at"),
    [
        ("2026-07-26T12:00:00.000Z", "2026-07-26T12:05:00Z"),
        ("2026-07-26T12:00:00+00:00", "2026-07-26T12:05:00Z"),
        ("2026-07-26T12:00:00Z", "2026-07-26T12:05:00.000Z"),
        ("2026-07-26 12:00:00Z", "2026-07-26T12:05:00Z"),
    ],
)
def test_run_binding_rejects_noncanonical_utc_second_timestamps(
    issued_at: str,
    expires_at: str,
) -> None:
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: RunBinding.from_header(_binding_header(issued_at=issued_at, expires_at=expires_at)),
    )


@pytest.mark.parametrize("lifetime", [1, 300])
def test_run_binding_accepts_lifetime_boundaries(lifetime: int) -> None:
    issued = datetime(2026, 7, 26, 12, tzinfo=UTC)
    expires = issued + timedelta(seconds=lifetime)

    binding = RunBinding.from_header(
        _binding_header(
            issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    )

    assert binding.expires_at - binding.issued_at == timedelta(seconds=lifetime)


@pytest.mark.parametrize("lifetime", [0, 301])
def test_run_binding_rejects_lifetime_outside_contract(lifetime: int) -> None:
    issued = datetime(2026, 7, 26, 12, tzinfo=UTC)
    expires = issued + timedelta(seconds=lifetime)

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: RunBinding.from_header(
            _binding_header(
                issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
                expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        ),
    )


@pytest.mark.parametrize(
    "digest",
    [
        "2" * 64,
        "sha256:" + "2" * 63,
        "sha256:" + "2" * 65,
        "sha256:" + "A" * 64,
        "sha512:" + "2" * 64,
    ],
)
def test_run_binding_rejects_noncanonical_digest_syntax(digest: str) -> None:
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: RunBinding.from_header(_binding_header(execution_digest=digest)),
    )


@pytest.mark.parametrize(
    ("now", "accepted"),
    [
        (datetime(2026, 7, 26, 11, 59, 30, tzinfo=UTC), True),
        (datetime(2026, 7, 26, 11, 59, 29, tzinfo=UTC), False),
        (datetime(2026, 7, 26, 12, 5, 30, tzinfo=UTC), True),
        (datetime(2026, 7, 26, 12, 5, 31, tzinfo=UTC), False),
    ],
)
def test_run_binding_expiry_allows_exactly_thirty_seconds_skew(
    now: datetime,
    accepted: bool,
) -> None:
    binding = RunBinding.from_header(_request_header())

    if accepted:
        binding.validate_expiry(now)
    else:
        _assert_reason(
            ReasonCode.EXEC_PROTOCOL_EXPIRED,
            lambda: binding.validate_expiry(now),
        )

    assert MAX_CLOCK_SKEW_SECONDS == 30


def test_run_binding_expiry_rejects_non_utc_or_fractional_now() -> None:
    binding = RunBinding.from_header(_request_header())

    for now in (
        datetime(2026, 7, 26, 12),
        datetime(2026, 7, 26, 12, tzinfo=timezone(timedelta(hours=1))),
        datetime(2026, 7, 26, 12, 0, 0, 1, tzinfo=UTC),
    ):
        _assert_reason(
            ReasonCode.EXEC_PROTOCOL_INVALID,
            lambda now=now: binding.validate_expiry(now),
        )


@pytest.mark.parametrize(
    "field",
    ["run_id", "nonce", "authority_digest", "execution_digest"],
)
def test_response_echo_must_match_request_binding(field: str) -> None:
    binding = RunBinding.from_header(_request_header())
    valid = _response_header()
    binding.validate_response_echo(valid)
    mismatched = _response_header()
    mismatched[field] = "different"

    _assert_reason(
        ReasonCode.EXEC_TRUST_MISMATCH,
        lambda: binding.validate_response_echo(mismatched),
    )


def test_response_execution_digest_is_echo_only_not_a_request_projection() -> None:
    response_payload = b"stdout"
    header = _response_header(((FrameType.STDOUT, response_payload),))
    header["execution_digest"] = "sha256:" + "4" * 64

    message = FramedMessage(
        header=header,
        frames=(Frame(FrameType.STDOUT, response_payload),),
    )

    assert message.header["execution_digest"] == "sha256:" + "4" * 64


def test_response_chain_uses_exact_network_order_bytes() -> None:
    frames = (
        Frame(FrameType.STDOUT, b"out"),
        Frame(FrameType.STDERR, b"err"),
    )

    assert response_chain("sha256:" + "2" * 64, frames) == (
        "42b00ddbd663cb83b8e064e93a10e171d5c1dc9ebfe123f242d17e44c2804e4c"
    )

    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: response_chain("sha256:" + "2" * 64, (Frame(FrameType.ARTIFACT, b"x"),)),
    )


def test_response_chain_rejects_invalid_digest_and_non_tuple_frames() -> None:
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: response_chain("2" * 64, ()),
    )
    _assert_reason(
        ReasonCode.EXEC_PROTOCOL_INVALID,
        lambda: response_chain("sha256:" + "2" * 64, []),  # type: ignore[arg-type]
    )


def test_deterministic_protocol_fixtures_have_exact_bytes_and_hashes() -> None:
    fixture_bytes = {path.name: path.read_bytes() for path in sorted(_FIXTURE_DIRECTORY.iterdir())}
    assert set(fixture_bytes) == set(_FIXTURE_HASHES)
    assert {
        name: hashlib.sha256(value).hexdigest() for name, value in fixture_bytes.items()
    } == _FIXTURE_HASHES

    raw_header = fixture_bytes["request-header.json"]
    header = json.loads(raw_header)
    assert canonical_bytes(header) == raw_header
    assert header["run_id"] == _RUN_ID
    assert header["nonce"] == _NONCE
    assert header["execution_digest"] == (
        "sha256:02e262e0114492b8078130e3b9f8c18244cb8d12c7f05224ff4b1012b411ac7c"
    )
    request = {key: value for key, value in header.items() if key != "execution_digest"}
    assert set(request) == {
        "protocol_version",
        "run_id",
        "nonce",
        "issued_at",
        "expires_at",
        "authority_digest",
        "action_id",
        "argv",
        "executable",
        "runner_identity",
        "operating_system",
        "architecture",
        "required_privileges",
        "frames",
        "timeout_seconds",
        "stdout_cap_bytes",
        "stderr_cap_bytes",
    }
    assert header["execution_digest"] == execution_digest({"schema_version": 1, "request": request})

    payload = b"synthetic-artifact"
    message = FramedMessage(
        header=header,
        frames=(Frame(FrameType.ARTIFACT, payload),),
    )
    stream = BytesIO()
    write_message(stream, message)

    encoded = stream.getvalue()
    frame_offset = _PREFIX.size + len(canonical_bytes(header))
    assert fixture_bytes["request-frame.bin"] == encoded[frame_offset:]
    assert encoded == fixture_bytes["request-message.bin"]
    assert read_message(BytesIO(fixture_bytes["request-message.bin"])) == message


def test_protocol_caps_are_exercised_as_exact_contract_values() -> None:
    assert (
        _PREFIX.size,
        _FRAME_PREFIX.size,
        MAX_PROTOCOL_HEADER_BYTES,
        MAX_FRAME_COUNT,
        MAX_FRAME_BYTES,
        MAX_REQUEST_BYTES,
        MAX_RESPONSE_BYTES,
    ) == (16, 42, 1_048_576, 256, 67_108_864, 75_497_472, 41_943_040)
