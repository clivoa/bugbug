"""Fail-closed atomic loader for engagement v2 authority snapshots.

The loader reads ``program``, ``scope``, ``authorization``, and optional
``runner`` documents through bounded, symlink-refusing, inode-rechecked
descriptors, validates each through the P0 contract layer, binds the coherent
snapshot to its confirmed-authority digest, and derives a stable engagement
namespace identity. Any failure produces no snapshot: a partially read, mixed,
or mid-write set of files never becomes usable authority.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from hackbot.engagement_v2.canonical import canonical_bytes
from hackbot.engagement_v2.constants import (
    AUTHORIZATION_SCHEMA_VERSION,
    MAX_AUTHORIZATION_DOCUMENT_BYTES,
    MAX_PROGRAM_DOCUMENT_BYTES,
    MAX_RUNNER_DOCUMENT_BYTES,
    MAX_SCOPE_DOCUMENT_BYTES,
    POLICY_BOOLEAN_FIELDS,
    PROGRAM_SCHEMA_VERSION,
    RUNNER_SCHEMA_VERSION,
    SCOPE_SCHEMA_VERSION,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.projection import (
    engagement_identity,
    projection_digest,
    security_projection,
)

_PROGRAM_FIELDS = frozenset({"schema_version", "program", "profile", "testing_rules", "reporting"})
_SCOPE_FIELDS = frozenset({"schema_version", "in_scope", "out_of_scope"})
_AUTHORIZATION_FIELDS = frozenset(
    {
        "schema_version",
        "confirmed",
        "confirmation_timestamp",
        "confirmed_by",
        "confirmed_authority_digest",
        "note",
    }
)
_AUTHORIZATION_REQUIRED_CONFIRMATION_FIELDS = (
    "confirmation_timestamp",
    "confirmed_by",
    "confirmed_authority_digest",
)
_RUNNER_FIELDS = frozenset(
    {
        "schema_version",
        "role",
        "node_identity",
        "ssh",
        "helper",
        "operating_system",
        "architecture",
        "permitted_privileges",
        "source_identity",
        "egress_attestation",
        "privilege_signer_public_key_fingerprint",
    }
)

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True)
class EngagementSnapshot:
    """An immutable, confirmed engagement v2 authority snapshot."""

    program: Mapping[str, object]
    scope: Mapping[str, object]
    authorization: Mapping[str, object]
    runner: Mapping[str, object] | None
    profile: str
    authority_digest: str
    identity: str


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    """Read all bytes of a regular file through one stable, symlink-free fd."""

    try:
        descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    except OSError as exc:
        # ELOOP (symlink under O_NOFOLLOW), ENOENT, EISDIR, and friends all
        # fail closed as an invalid document structure.
        raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
        if before.st_size > max_bytes:
            raise ContractError(ReasonCode.INVALID_DOCUMENT_SIZE)
        data = _read_exact(descriptor, before.st_size)
        if os.read(descriptor, 1):
            # The file grew while we read it: not a coherent snapshot.
            raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
        return data
    finally:
        os.close(descriptor)


def _read_exact(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            # File shrank mid-read: fail closed.
            raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(ReasonCode.INVALID_DOCUMENT_ENCODING) from exc


def _strict_json(text: str) -> object:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(ReasonCode.INVALID_DUPLICATE_KEY)
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=object_pairs)
    except ContractError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE) from exc


def _strict_yaml(text: str) -> object:
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - config extra
        raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE) from exc

    _reject_aliases_and_explicit_tags(text, yaml)

    mapping_tag = yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG
    merge_tag = "tag:yaml.org,2002:merge"

    class _StrictSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[str, object]:
        result: dict[str, object] = {}
        for key_node, value_node in node.value:
            if key_node.tag == merge_tag:
                raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
            key = loader.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
            if key in result:
                raise ContractError(ReasonCode.INVALID_DUPLICATE_KEY)
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    _StrictSafeLoader.add_constructor(mapping_tag, construct_mapping)
    try:
        # _StrictSafeLoader is a SafeLoader subclass (no arbitrary object
        # construction) that additionally rejects duplicate keys; aliases,
        # merge keys, and explicit tags are already rejected above.
        return yaml.load(text, Loader=_StrictSafeLoader)  # noqa: S506
    except ContractError:
        raise
    except (yaml.YAMLError, RecursionError) as exc:
        raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE) from exc


def _reject_aliases_and_explicit_tags(text: str, yaml: Any) -> None:
    try:
        events = list(yaml.parse(text, Loader=yaml.SafeLoader))
    except (yaml.YAMLError, RecursionError) as exc:
        raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE) from exc
    for event in events:
        if isinstance(event, yaml.AliasEvent):
            raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
        tag = getattr(event, "tag", None)
        if tag is None:
            continue
        implicit = getattr(event, "implicit", None)
        if isinstance(event, yaml.ScalarEvent):
            plain, quoted = implicit if isinstance(implicit, tuple) else (False, False)
            if not plain and not quoted:
                raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
        elif isinstance(event, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
            if implicit is False:
                raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)


def _decode(path: Path, data: bytes) -> dict[str, object]:
    text = _decode_text(data)
    if path.suffix.lower() == ".json":
        value = _strict_json(text)
    else:
        value = _strict_yaml(text)
    if not isinstance(value, dict):
        raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
    # Enforce the P0 strict primitive model (NFC, no float, control-free,
    # snake_case keys, bounded nesting) over the whole document. The bytes are
    # discarded; only the raised reason matters here.
    canonical_bytes(value)
    return value


def read_hardened_document(path: str | os.PathLike[str], max_bytes: int) -> dict[str, object]:
    """Read a bounded, symlink-free document through the hardened decode path.

    Public entry for other v2 consumers (e.g. the action manifest) that need the
    same descriptor safety and P0 strict-primitive model as the engagement loader.
    """

    resolved = Path(path)
    data = _read_bounded(resolved, max_bytes)
    return _decode(resolved, data)


def _require_version(document: Mapping[str, object], expected: int) -> None:
    version = document.get("schema_version")
    if type(version) is not int or version != expected:
        raise ContractError(ReasonCode.INVALID_SCHEMA_VERSION)


def _reject_unknown_fields(document: Mapping[str, object], allowed: frozenset[str]) -> None:
    for key in document:
        if key not in allowed:
            raise ContractError(ReasonCode.INVALID_UNKNOWN_FIELD)


_SCOPE_KINDS = frozenset(
    {
        "domains",
        "wildcard_domains",
        "urls",
        "hosts",
        "cidrs",
        "network_endpoints",
        "mobile_apps",
        "repositories",
        "contracts",
    }
)
_TESTING_RULES_FIELDS = frozenset(
    POLICY_BOOLEAN_FIELDS
    | {
        "max_requests_per_second",
        "concurrency",
        "timeout_seconds",
        "output_cap_bytes",
        "max_targets_per_action",
        "excluded_impacts",
        "prohibited_tools",
        "prohibited_vulnerability_types",
        "required_headers",
        "source_ip_requirements",
        "restricted_hours",
    }
)


def _validate_nested_fields(program: Mapping[str, object], scope: Mapping[str, object]) -> None:
    """Reject unknown nested keys and non-mapping sections with exact codes."""

    testing_rules = program.get("testing_rules")
    if not isinstance(testing_rules, Mapping):
        raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
    for key in testing_rules:
        if key not in _TESTING_RULES_FIELDS:
            raise ContractError(ReasonCode.INVALID_UNKNOWN_FIELD)
    for section_key in ("in_scope", "out_of_scope"):
        section = scope.get(section_key)
        if not isinstance(section, Mapping):
            raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
        for key in section:
            if key not in _SCOPE_KINDS:
                raise ContractError(ReasonCode.INVALID_UNKNOWN_FIELD)


def _resolve(engagement_dir: Path, stem: str, suffixes: tuple[str, ...]) -> Path | None:
    for suffix in suffixes:
        candidate = engagement_dir / f"{stem}{suffix}"
        if candidate.exists() or candidate.is_symlink():
            return candidate
    return None


def _load_document(
    engagement_dir: Path,
    stem: str,
    suffixes: tuple[str, ...],
    max_bytes: int,
    version: int,
    allowed: frozenset[str],
    *,
    required: bool,
) -> dict[str, object] | None:
    path = _resolve(engagement_dir, stem, suffixes)
    if path is None:
        if required:
            raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE)
        return None
    data = _read_bounded(path, max_bytes)
    document = _decode(path, data)
    _require_version(document, version)
    _reject_unknown_fields(document, allowed)
    return document


def _verify_confirmation(authorization: Mapping[str, object], computed_digest: str) -> None:
    if authorization.get("confirmed") is not True:
        raise ContractError(ReasonCode.DENY_AUTHORIZATION_UNCONFIRMED)
    for field in _AUTHORIZATION_REQUIRED_CONFIRMATION_FIELDS:
        value = authorization.get(field)
        if not isinstance(value, str) or not value:
            raise ContractError(ReasonCode.DENY_AUTHORIZATION_UNCONFIRMED)
    stored = authorization["confirmed_authority_digest"]
    if stored != computed_digest:
        raise ContractError(ReasonCode.DENY_AUTHORIZATION_STALE)


def load_engagement(engagement_dir: str | os.PathLike[str]) -> EngagementSnapshot:
    """Load one coherent, confirmed engagement v2 snapshot or fail closed."""

    directory = Path(engagement_dir)

    program = _load_document(
        directory,
        "program",
        (".yaml", ".yml", ".json"),
        MAX_PROGRAM_DOCUMENT_BYTES,
        PROGRAM_SCHEMA_VERSION,
        _PROGRAM_FIELDS,
        required=True,
    )
    scope = _load_document(
        directory,
        "scope",
        (".yaml", ".yml", ".json"),
        MAX_SCOPE_DOCUMENT_BYTES,
        SCOPE_SCHEMA_VERSION,
        _SCOPE_FIELDS,
        required=True,
    )
    authorization = _load_document(
        directory,
        "authorization",
        (".json", ".yaml", ".yml"),
        MAX_AUTHORIZATION_DOCUMENT_BYTES,
        AUTHORIZATION_SCHEMA_VERSION,
        _AUTHORIZATION_FIELDS,
        required=True,
    )
    runner = _load_document(
        directory,
        "runner",
        (".json", ".yaml", ".yml"),
        MAX_RUNNER_DOCUMENT_BYTES,
        RUNNER_SCHEMA_VERSION,
        _RUNNER_FIELDS,
        required=False,
    )
    assert program is not None and scope is not None and authorization is not None

    _validate_nested_fields(program, scope)
    try:
        projection = security_projection(program=program, scope=scope, runner=runner)
        computed_digest = projection_digest(projection)
    except ContractError:
        raise
    except (TypeError, ValueError) as exc:
        # A structurally malformed authority value (e.g. a scalar where a scope
        # kind expects a list) stays inside the closed reason-code contract.
        raise ContractError(ReasonCode.INVALID_DOCUMENT_STRUCTURE) from exc
    _verify_confirmation(authorization, computed_digest)

    identity = engagement_identity(computed_digest)
    profile = program["profile"]
    if not isinstance(profile, str):
        raise ContractError(ReasonCode.INVALID_CANONICAL_VALUE)

    return EngagementSnapshot(
        program=MappingProxyType(dict(program)),
        scope=MappingProxyType(dict(scope)),
        authorization=MappingProxyType(dict(authorization)),
        runner=MappingProxyType(dict(runner)) if runner is not None else None,
        profile=profile,
        authority_digest=computed_digest,
        identity=identity,
    )
