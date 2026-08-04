"""Allocation-bounded remote framing and run-binding primitives."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import BinaryIO, cast

from hackbot.engagement_v2.canonical import canonical_bytes, execution_digest
from hackbot.engagement_v2.constants import (
    AUTHORITY_DIGEST_PATTERN,
    BINDING_NAME_PATTERN,
    ED25519_SIGNATURE_BYTES,
    FRAME_TYPE_BY_DIRECTION,
    IDENTIFIER_PATTERN,
    MAX_ARGV_TOKEN_BYTES,
    MAX_ARGV_TOKENS,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_FRAME_BYTES,
    MAX_FRAME_COUNT,
    MAX_IDENTIFIER_BYTES,
    MAX_OUTPUT_CAP_BYTES,
    MAX_PROTOCOL_HEADER_BYTES,
    MAX_REQUEST_BYTES,
    MAX_REQUEST_LIFETIME_SECONDS,
    MAX_RESPONSE_BYTES,
    MAX_SCALAR_OR_TARGET_BYTES,
    MAX_TIMEOUT_SECONDS,
    MIN_OUTPUT_CAP_BYTES,
    MIN_REQUEST_LIFETIME_SECONDS,
    MIN_TIMEOUT_SECONDS,
    NONCE_BASE64URL_LENGTH,
    NONCE_BYTES,
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    Architecture,
    FrameType,
    PlaceholderKind,
    Platform,
    Privilege,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode

_PREFIX = struct.Struct("!8sHIH")
_FRAME_PREFIX = struct.Struct("!HQ32s")
_PAYLOAD_READ_CHUNK_BYTES = 65_536
_TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z",
    re.ASCII,
)
_ABSOLUTE_PATH_PATTERN = re.compile(r"(?:/|[A-Za-z]:[\\/]).+", re.ASCII)
_PLACEHOLDER_KINDS_PATTERN = "|".join(member.value for member in PlaceholderKind)
_ARGV_TOKEN_PATTERN = re.compile(
    rf"(?:[^{{}}]+|\{{(?:{_PLACEHOLDER_KINDS_PATTERN}):"
    rf"{BINDING_NAME_PATTERN.pattern}\}})",
    re.ASCII,
)
_DIGEST_PATTERN = AUTHORITY_DIGEST_PATTERN
_REQUEST_HEADER_FIELDS = frozenset(
    {
        "protocol_version",
        "run_id",
        "nonce",
        "issued_at",
        "expires_at",
        "authority_digest",
        "execution_digest",
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
)
_RESPONSE_HEADER_FIELDS = frozenset(
    {
        "protocol_version",
        "run_id",
        "nonce",
        "authority_digest",
        "execution_digest",
        "frames",
    }
)


def _invalid() -> ContractError:
    return ContractError(ReasonCode.EXEC_PROTOCOL_INVALID)


def _is_exact_int(value: object) -> bool:
    return type(value) is int


def _valid_digest(value: object) -> bool:
    return type(value) is str and _DIGEST_PATTERN.fullmatch(value) is not None


def _freeze_json(value: object) -> object:
    if type(value) is dict:
        mapping = cast(dict[str, object], value)
        return MappingProxyType({key: _freeze_json(item) for key, item in mapping.items()})
    if type(value) is list:
        return tuple(_freeze_json(item) for item in cast(list[object], value))
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_json(item) for item in cast(tuple[object, ...], value)]
    return value


def _header_dict(header: Mapping[str, object]) -> dict[str, object]:
    value = _thaw_json(header)
    if type(value) is not dict:
        raise _invalid()
    return cast(dict[str, object], value)


def _read_exact(stream: BinaryIO, count: int) -> bytes:
    value = bytearray(count)
    offset = 0
    while offset < count:
        chunk = stream.read(count - offset)
        if type(chunk) is not bytes or not chunk or len(chunk) > count - offset:
            raise _invalid()
        next_offset = offset + len(chunk)
        value[offset:next_offset] = chunk
        offset = next_offset
    return bytes(value)


def _read_payload(stream: BinaryIO, count: int) -> tuple[bytes, bytes]:
    payload = bytearray()
    digest = hashlib.sha256()
    remaining = count
    while remaining:
        chunk = stream.read(min(remaining, _PAYLOAD_READ_CHUNK_BYTES))
        if type(chunk) is not bytes or not chunk or len(chunk) > remaining:
            raise _invalid()
        digest.update(chunk)
        payload.extend(chunk)
        remaining -= len(chunk)
    return bytes(payload), digest.digest()


def _write_exact(stream: BinaryIO, value: bytes) -> None:
    try:
        written = stream.write(value)
    except (OSError, ValueError) as error:
        raise _invalid() from error
    if type(written) is not int or written != len(value):
        raise _invalid()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _invalid()
        result[key] = value
    return result


def _reject_nonstandard_constant(_value: str) -> object:
    raise _invalid()


def _decode_header(raw_header: bytes) -> dict[str, object]:
    try:
        decoded = raw_header.decode("utf-8", errors="strict")
        header = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise _invalid() from error
    if type(header) is not dict:
        raise _invalid()
    typed_header = cast(dict[str, object], header)
    try:
        encoded = canonical_bytes(typed_header)
    except ContractError as error:
        raise _invalid() from error
    if encoded != raw_header:
        raise _invalid()
    return typed_header


def _validated_uuid(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    try:
        parsed = uuid.UUID(value, version=4)
    except (AttributeError, ValueError) as error:
        raise _invalid() from error
    if str(parsed) != value:
        raise _invalid()
    return value


def _validated_nonce(value: object) -> str:
    if type(value) is not str or len(value) != NONCE_BASE64URL_LENGTH or not value.isascii():
        raise _invalid()
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (binascii.Error, ValueError) as error:
        raise _invalid() from error
    if (
        len(decoded) != NONCE_BYTES
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
    ):
        raise _invalid()
    return value


def _validated_utc_second(value: object) -> datetime:
    if type(value) is not datetime:
        raise _invalid()
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond != 0:
        raise _invalid()
    return value


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise _invalid()
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise _invalid() from error


def _validated_descriptor_list(
    header: dict[str, object],
    *,
    expected_count: int,
    response: bool,
) -> list[dict[str, object]]:
    descriptors = header.get("frames")
    if type(descriptors) is not list or len(descriptors) != expected_count:
        raise _invalid()
    allowed = FRAME_TYPE_BY_DIRECTION["response" if response else "request"]
    result: list[dict[str, object]] = []
    for index, value in enumerate(descriptors):
        if type(value) is not dict:
            raise _invalid()
        descriptor = cast(dict[str, object], value)
        if set(descriptor) != {"index", "frame_type", "length", "sha256"}:
            raise _invalid()
        descriptor_index = descriptor["index"]
        frame_type_value = descriptor["frame_type"]
        length = descriptor["length"]
        if (
            not _is_exact_int(descriptor_index)
            or not _is_exact_int(frame_type_value)
            or not _is_exact_int(length)
            or not _valid_digest(descriptor["sha256"])
        ):
            raise _invalid()
        descriptor_index_value = cast(int, descriptor_index)
        raw_frame_type = cast(int, frame_type_value)
        payload_length = cast(int, length)
        if descriptor_index_value != index or not 0 <= payload_length <= MAX_FRAME_BYTES:
            raise _invalid()
        try:
            frame_type = FrameType(raw_frame_type)
        except ValueError as error:
            raise _invalid() from error
        if frame_type not in allowed:
            raise _invalid()
        result.append(descriptor)
    if not response:
        permit_count = sum(
            descriptor["frame_type"] == FrameType.EXECUTION_PERMIT.value for descriptor in result
        )
        if permit_count > 1:
            raise _invalid()
    return result


def _validate_identifier(value: object) -> None:
    if (
        type(value) is not str
        or len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES
        or IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise _invalid()


def _validate_bounded_int(value: object, minimum: int, maximum: int) -> None:
    if not _is_exact_int(value):
        raise _invalid()
    integer = cast(int, value)
    if not minimum <= integer <= maximum:
        raise _invalid()


def _validate_request_header(
    header: dict[str, object],
    *,
    expected_count: int,
) -> list[dict[str, object]]:
    if set(header) != _REQUEST_HEADER_FIELDS:
        raise _invalid()
    if type(header.get("protocol_version")) is not int:
        raise _invalid()
    if header["protocol_version"] != PROTOCOL_VERSION:
        raise _invalid()
    RunBinding.from_header(header)
    _validate_identifier(header["action_id"])
    _validate_identifier(header["runner_identity"])

    argv = header["argv"]
    if type(argv) is not list or not 1 <= len(argv) <= MAX_ARGV_TOKENS:
        raise _invalid()
    for token in argv:
        if type(token) is not str:
            raise _invalid()
        token_length = len(token.encode("utf-8"))
        if not 1 <= token_length <= MAX_ARGV_TOKEN_BYTES:
            raise _invalid()
        if _ARGV_TOKEN_PATTERN.fullmatch(token) is None:
            raise _invalid()

    executable = header["executable"]
    if type(executable) is not dict or set(executable) != {"path", "sha256"}:
        raise _invalid()
    executable_mapping = cast(dict[str, object], executable)
    path = executable_mapping["path"]
    if (
        type(path) is not str
        or not 2 <= len(path.encode("utf-8")) <= MAX_SCALAR_OR_TARGET_BYTES
        or _ABSOLUTE_PATH_PATTERN.fullmatch(path) is None
        or not _valid_digest(executable_mapping["sha256"])
    ):
        raise _invalid()

    operating_system = header["operating_system"]
    architecture = header["architecture"]
    if type(operating_system) is not str or operating_system not in {
        member.value for member in Platform
    }:
        raise _invalid()
    if type(architecture) is not str or architecture not in {
        member.value for member in Architecture
    }:
        raise _invalid()

    privileges = header["required_privileges"]
    if type(privileges) is not list or len(privileges) > len(Privilege):
        raise _invalid()
    allowed_privileges = {member.value for member in Privilege}
    if any(type(item) is not str or item not in allowed_privileges for item in privileges):
        raise _invalid()
    if len(set(cast(list[str], privileges))) != len(privileges):
        raise _invalid()

    _validate_bounded_int(
        header["timeout_seconds"],
        MIN_TIMEOUT_SECONDS,
        MAX_TIMEOUT_SECONDS,
    )
    _validate_bounded_int(
        header["stdout_cap_bytes"],
        MIN_OUTPUT_CAP_BYTES,
        MAX_OUTPUT_CAP_BYTES,
    )
    _validate_bounded_int(
        header["stderr_cap_bytes"],
        MIN_OUTPUT_CAP_BYTES,
        MAX_OUTPUT_CAP_BYTES,
    )
    descriptors = _validated_descriptor_list(
        header,
        expected_count=expected_count,
        response=False,
    )
    request = {key: value for key, value in header.items() if key != "execution_digest"}
    expected_execution_digest = execution_digest({"schema_version": 1, "request": request})
    if header["execution_digest"] != expected_execution_digest:
        raise _invalid()
    return descriptors


def _validate_response_header(
    header: dict[str, object],
    *,
    expected_count: int,
) -> list[dict[str, object]]:
    if set(header) != _RESPONSE_HEADER_FIELDS:
        raise _invalid()
    if type(header.get("protocol_version")) is not int:
        raise _invalid()
    if header["protocol_version"] != PROTOCOL_VERSION:
        raise _invalid()
    _validated_uuid(header["run_id"])
    _validated_nonce(header["nonce"])
    if not _valid_digest(header["authority_digest"]) or not _valid_digest(
        header["execution_digest"]
    ):
        raise _invalid()
    return _validated_descriptor_list(
        header,
        expected_count=expected_count,
        response=True,
    )


def _validate_header(
    header: dict[str, object],
    *,
    expected_count: int,
    response: bool,
) -> list[dict[str, object]]:
    if response:
        return _validate_response_header(header, expected_count=expected_count)
    return _validate_request_header(header, expected_count=expected_count)


def _frames_are_response(
    frames: tuple[Frame, ...],
    header: dict[str, object] | None = None,
) -> bool:
    if not frames:
        return header is not None and set(header) == _RESPONSE_HEADER_FIELDS
    request_types = FRAME_TYPE_BY_DIRECTION["request"]
    response_types = FRAME_TYPE_BY_DIRECTION["response"]
    if all(frame.frame_type in request_types for frame in frames):
        return False
    if all(frame.frame_type in response_types for frame in frames):
        return True
    raise _invalid()


@dataclass(frozen=True, slots=True)
class Frame:
    """An immutable exact frame payload bounded by the protocol cap."""

    frame_type: FrameType
    payload: bytes

    def __post_init__(self) -> None:
        if (
            type(self.frame_type) is not FrameType
            or type(self.payload) is not bytes
            or len(self.payload) > MAX_FRAME_BYTES
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class SignedExecutionPermit:
    """One exact decoded permit envelope carried only in a request frame."""

    permit: Mapping[str, object]
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.permit) is not dict or type(self.signature) is not bytes:
            raise _invalid()
        if len(self.signature) != ED25519_SIGNATURE_BYTES:
            raise _invalid()
        permit = cast(dict[str, object], self.permit)
        try:
            canonical_bytes(permit)
        except ContractError as error:
            raise _invalid() from error
        object.__setattr__(self, "permit", _freeze_json(permit))


def decode_execution_permit_frame(frame: Frame) -> SignedExecutionPermit:
    """Decode one canonical request-only ExecutionPermitV2 envelope."""

    if type(frame) is not Frame or frame.frame_type is not FrameType.EXECUTION_PERMIT:
        raise _invalid()
    envelope = _decode_header(frame.payload)
    if set(envelope) != {"permit", "signature"}:
        raise _invalid()
    permit = envelope["permit"]
    encoded_signature = envelope["signature"]
    if type(permit) is not dict or type(encoded_signature) is not str:
        raise _invalid()
    if not encoded_signature.isascii() or "=" in encoded_signature:
        raise _invalid()
    try:
        signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
    except (binascii.Error, ValueError) as error:
        raise _invalid() from error
    canonical_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    if len(signature) != ED25519_SIGNATURE_BYTES or canonical_signature != encoded_signature:
        raise _invalid()
    return SignedExecutionPermit(permit=permit, signature=signature)


@dataclass(frozen=True, slots=True)
class FramedMessage:
    """An immutable canonical header and ordered frame tuple."""

    header: Mapping[str, object]
    frames: tuple[Frame, ...]

    def __post_init__(self) -> None:
        if type(self.header) is not dict or type(self.frames) is not tuple:
            raise _invalid()
        if len(self.frames) > MAX_FRAME_COUNT:
            raise _invalid()
        if any(type(frame) is not Frame for frame in self.frames):
            raise _invalid()
        header = cast(dict[str, object], self.header)
        response = _frames_are_response(self.frames, header)
        try:
            canonical_bytes(header)
        except ContractError as error:
            raise _invalid() from error
        _validate_header(header, expected_count=len(self.frames), response=response)
        for descriptor, frame in zip(
            cast(list[dict[str, object]], header["frames"]),
            self.frames,
            strict=True,
        ):
            expected_digest = "sha256:" + hashlib.sha256(frame.payload).hexdigest()
            if (
                descriptor["frame_type"] != frame.frame_type.value
                or descriptor["length"] != len(frame.payload)
                or descriptor["sha256"] != expected_digest
            ):
                raise _invalid()
        object.__setattr__(self, "header", _freeze_json(header))


@dataclass(frozen=True, slots=True)
class RunBinding:
    """Canonical identifiers and validity window which bind one remote run."""

    run_id: str
    nonce: str
    issued_at: datetime
    expires_at: datetime
    authority_digest: str
    execution_digest: str

    def __post_init__(self) -> None:
        _validated_uuid(self.run_id)
        _validated_nonce(self.nonce)
        _validated_utc_second(self.issued_at)
        _validated_utc_second(self.expires_at)
        if not _valid_digest(self.authority_digest) or not _valid_digest(self.execution_digest):
            raise _invalid()
        lifetime = self.expires_at - self.issued_at
        if not (
            timedelta(seconds=MIN_REQUEST_LIFETIME_SECONDS)
            <= lifetime
            <= timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS)
        ):
            raise _invalid()

    @classmethod
    def from_header(cls, header: Mapping[str, object]) -> RunBinding:
        """Parse and validate binding fields from a canonical request header."""

        if not isinstance(header, Mapping):
            raise _invalid()
        try:
            run_id = header["run_id"]
            nonce = header["nonce"]
            issued_at = header["issued_at"]
            expires_at = header["expires_at"]
            authority_digest = header["authority_digest"]
            execution_digest_value = header["execution_digest"]
        except (KeyError, TypeError) as error:
            raise _invalid() from error
        if (
            type(run_id) is not str
            or type(nonce) is not str
            or type(authority_digest) is not str
            or type(execution_digest_value) is not str
        ):
            raise _invalid()
        return cls(
            run_id=run_id,
            nonce=nonce,
            issued_at=_parse_timestamp(issued_at),
            expires_at=_parse_timestamp(expires_at),
            authority_digest=authority_digest,
            execution_digest=execution_digest_value,
        )

    def validate_expiry(self, now: datetime) -> None:
        """Reject a trusted UTC-second time outside the exact skew window."""

        validated_now = _validated_utc_second(now)
        skew = timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)
        if validated_now < self.issued_at - skew or validated_now > self.expires_at + skew:
            raise ContractError(ReasonCode.EXEC_PROTOCOL_EXPIRED)

    def validate_response_echo(self, header: Mapping[str, object]) -> None:
        """Require a response to echo the four request-binding identifiers."""

        if not isinstance(header, Mapping):
            raise ContractError(ReasonCode.EXEC_TRUST_MISMATCH)
        expected = {
            "run_id": self.run_id,
            "nonce": self.nonce,
            "authority_digest": self.authority_digest,
            "execution_digest": self.execution_digest,
        }
        if any(header.get(key) != value for key, value in expected.items()):
            raise ContractError(ReasonCode.EXEC_TRUST_MISMATCH)


def write_message(stream: BinaryIO, message: FramedMessage) -> None:
    """Write one canonical framed message after validating every aggregate bound."""

    if type(message) is not FramedMessage:
        raise _invalid()
    header = _header_dict(message.header)
    response = _frames_are_response(message.frames, header)
    _validate_header(header, expected_count=len(message.frames), response=response)
    raw_header = canonical_bytes(header)
    cap = MAX_RESPONSE_BYTES if response else MAX_REQUEST_BYTES
    if len(raw_header) > MAX_PROTOCOL_HEADER_BYTES:
        raise _invalid()
    total_bytes = _PREFIX.size + len(raw_header)
    if total_bytes > cap:
        raise _invalid()
    for frame in message.frames:
        frame_bytes = _FRAME_PREFIX.size + len(frame.payload)
        if total_bytes + frame_bytes > cap:
            raise _invalid()
        total_bytes += frame_bytes

    _write_exact(
        stream,
        _PREFIX.pack(
            PROTOCOL_MAGIC,
            PROTOCOL_VERSION,
            len(raw_header),
            len(message.frames),
        ),
    )
    _write_exact(stream, raw_header)
    for frame in message.frames:
        digest = hashlib.sha256(frame.payload).digest()
        _write_exact(
            stream,
            _FRAME_PREFIX.pack(frame.frame_type.value, len(frame.payload), digest),
        )
        _write_exact(stream, frame.payload)


def read_message(stream: BinaryIO, response: bool = False) -> FramedMessage:
    """Read exactly one bounded request or response and require immediate EOF."""

    if type(response) is not bool:
        raise _invalid()
    cap = MAX_RESPONSE_BYTES if response else MAX_REQUEST_BYTES
    raw_prefix = _read_exact(stream, _PREFIX.size)
    magic, version, header_length, frame_count = _PREFIX.unpack(raw_prefix)
    if (
        magic != PROTOCOL_MAGIC
        or version != PROTOCOL_VERSION
        or header_length > MAX_PROTOCOL_HEADER_BYTES
        or frame_count > MAX_FRAME_COUNT
    ):
        raise _invalid()
    total_bytes = _PREFIX.size
    if total_bytes + header_length > cap:
        raise _invalid()
    raw_header = _read_exact(stream, header_length)
    total_bytes += header_length
    header = _decode_header(raw_header)
    descriptors = _validate_header(
        header,
        expected_count=frame_count,
        response=response,
    )
    declared_message_bytes = (
        _PREFIX.size
        + header_length
        + frame_count * _FRAME_PREFIX.size
        + sum(cast(int, descriptor["length"]) for descriptor in descriptors)
    )
    if declared_message_bytes > cap:
        raise _invalid()

    frames: list[Frame] = []
    allowed = FRAME_TYPE_BY_DIRECTION["response" if response else "request"]
    for index in range(frame_count):
        if total_bytes + _FRAME_PREFIX.size > cap:
            raise _invalid()
        raw_frame_prefix = _read_exact(stream, _FRAME_PREFIX.size)
        total_bytes += _FRAME_PREFIX.size
        frame_type_value, payload_length, declared_digest = _FRAME_PREFIX.unpack(raw_frame_prefix)
        if payload_length > MAX_FRAME_BYTES or total_bytes + payload_length > cap:
            raise _invalid()
        try:
            frame_type = FrameType(frame_type_value)
        except ValueError as error:
            raise _invalid() from error
        if frame_type not in allowed:
            raise _invalid()
        descriptor = descriptors[index]
        if (
            descriptor["frame_type"] != frame_type.value
            or descriptor["length"] != payload_length
            or descriptor["sha256"] != "sha256:" + declared_digest.hex()
        ):
            raise _invalid()
        payload, computed_digest = _read_payload(stream, payload_length)
        total_bytes += payload_length
        if computed_digest != declared_digest:
            raise _invalid()
        frames.append(Frame(frame_type, payload))

    trailing = stream.read(1)
    if type(trailing) is not bytes or trailing:
        raise _invalid()
    return FramedMessage(header=header, frames=tuple(frames))


def response_chain(
    execution_digest_value: str,
    frames: tuple[Frame, ...],
) -> str:
    """Return the exact lowercase response-frame hash chain."""

    if not _valid_digest(execution_digest_value) or type(frames) is not tuple:
        raise _invalid()
    if any(type(frame) is not Frame for frame in frames):
        raise _invalid()
    response_types = FRAME_TYPE_BY_DIRECTION["response"]
    if any(frame.frame_type not in response_types for frame in frames):
        raise _invalid()
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


__all__ = [
    "Frame",
    "FrameType",
    "FramedMessage",
    "RunBinding",
    "SignedExecutionPermit",
    "decode_execution_permit_frame",
    "read_message",
    "response_chain",
    "write_message",
]
