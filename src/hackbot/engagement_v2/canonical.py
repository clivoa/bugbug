"""Strict canonical values and domain-separated engagement-v2 digests."""

from __future__ import annotations

import hashlib
import json
import unicodedata

from hackbot.engagement_v2.constants import (
    AUTHORITY_PROJECTION_FORMAT,
    EXECUTION_PROJECTION_FORMAT,
    MAPPING_KEY_PATTERN,
    MAX_DOCUMENT_NESTING_DEPTH,
    MAX_SIGNED_INT64,
    MIN_SIGNED_INT64,
    SHA256_PREFIX,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode


def _validated(value: object, *, depth: int = 0) -> object:
    """Return a recursively validated JSON-compatible canonical value."""

    if depth > MAX_DOCUMENT_NESTING_DEPTH:
        raise ContractError(ReasonCode.INVALID_LIMIT)
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not MIN_SIGNED_INT64 <= value <= MAX_SIGNED_INT64:
            raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)
        return value
    if type(value) is str:
        if unicodedata.normalize("NFC", value) != value:
            raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)
        if any(
            0xD800 <= ord(character) <= 0xDFFF
            or ord(character) <= 0x1F
            or 0x7F <= ord(character) <= 0x9F
            for character in value
        ):
            raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)
        return value
    if type(value) is list or type(value) is tuple:
        return [_validated(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or MAPPING_KEY_PATTERN.fullmatch(key) is None:
                raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)
            result[key] = _validated(item, depth=depth + 1)
        return result
    raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)


def canonical_bytes(value: object) -> bytes:
    """Encode an exact, validated canonical JSON value as UTF-8 bytes."""

    return json.dumps(
        _validated(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest_value(value: object) -> str:
    """Return the lower-case SHA-256 digest of a canonical value."""

    digest = hashlib.sha256(canonical_bytes(value)).hexdigest()
    return f"{SHA256_PREFIX}{digest}"


def authority_digest(projection: object) -> str:
    """Return the digest of an authority projection in its dedicated domain."""

    return digest_value({"contract": AUTHORITY_PROJECTION_FORMAT, "value": projection})


def execution_digest(projection: object) -> str:
    """Return the digest of an execution projection in its dedicated domain."""

    return digest_value({"contract": EXECUTION_PROJECTION_FORMAT, "value": projection})
