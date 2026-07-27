"""Strict operator action manifest (actions.yaml) loading and validation.

The manifest is validated against the archived P0 action-execution contracts and
fails closed with the exact P0 reason on any violation. Loading produces an
immutable action registry; it executes nothing and resolves no secret.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from hackbot.engagement_v2.constants import (
    ACTIONS_SCHEMA_VERSION,
    ELEVATION_BASENAMES,
    INLINE_MODE_FLAGS_BY_BASENAME,
    INTERPRETER_BASENAMES,
    MAX_ACTION_CAPABILITIES,
    MAX_ACTION_MANIFEST_BYTES,
    MAX_ACTION_PARAMETERS,
    MAX_ACTION_SECRETS,
    MAX_ACTIONS,
    MAX_ARGV_TOKENS,
    MAX_ENUM_VALUES,
    MAX_IDENTIFIER_BYTES,
    MAX_SIGNED_INT64,
    MAX_TARGET_BINDINGS,
    MAX_UTF8_STRING_BYTES,
    MIN_ENUM_VALUES,
    MIN_SIGNED_INT64,
    MIN_UTF8_STRING_BYTES,
    OPERATOR_ACTION_ID_PREFIX,
    SAFE_FULLMATCH_FORMAT,
    SHELL_BASENAMES,
    Architecture,
    EvidenceMode,
    ParameterType,
    Platform,
    Privilege,
    RateControlMode,
    RiskLevel,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.loader import read_hardened_document
from hackbot.engagement_v2.patterns import SafePattern, compile_safe_pattern

# Canonical action-capability -> testing_rules field mapping (P2 consumes it).
CAPABILITY_TO_FIELD: Mapping[str, str] = MappingProxyType(
    {
        "automated-scanning": "automated_scanning_allowed",
        "authenticated-testing": "authenticated_testing_allowed",
        "exploit-execution": "exploit_execution_allowed",
        "payload-execution": "payload_execution_allowed",
        "credential-access": "credential_access_allowed",
        "credential-capture": "credential_capture_allowed",
        "state-changing": "state_changing_allowed",
        "privileged-execution": "privileged_execution_allowed",
        "lateral-movement": "lateral_movement_allowed",
        "persistence": "persistence_allowed",
        "sensitive-data-access": "sensitive_data_access_allowed",
        "data-exfiltration": "data_exfiltration_allowed",
        "account-creation": "account_creation_allowed",
        "multiple-accounts": "multiple_accounts_allowed",
        "out-of-band": "out_of_band_testing_allowed",
        "autonomous-progression": "autonomous_progression_allowed",
        "social-engineering": "social_engineering_allowed",
        "denial-of-service": "denial_of_service_allowed",
        "destructive-testing": "destructive_testing_allowed",
    }
)

_BINDING_ID = re.compile(r"[a-z][a-z0-9_]{0,63}", re.ASCII)
_PLACEHOLDER = re.compile(
    r"\{(value|target|targets_file|artifact_file|secret_file):([a-z][a-z0-9_]{0,63})\}",
    re.ASCII,
)
_ACTION_ID = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", re.ASCII)
_PARAMETER_TYPES = frozenset(member.value for member in ParameterType)
# Target-shaped parameter types must be supplied through scope-checked target
# bindings, never as inline {value:...} tokens (which bypass scope).
_TARGET_PARAMETER_TYPES = frozenset(
    {
        ParameterType.DOMAIN.value,
        ParameterType.HOST.value,
        ParameterType.IP.value,
        ParameterType.CIDR.value,
        ParameterType.URL.value,
        ParameterType.NETWORK_ENDPOINT.value,
        ParameterType.TARGET_LIST.value,
    }
)
_ACTION_FIELDS = frozenset(
    {
        "id",
        "title",
        "risk",
        "platforms",
        "architectures",
        "executables",
        "executable_digests",
        "required_privileges",
        "parameters",
        "secrets",
        "targets",
        "characteristics",
        "rate_control",
        "capabilities",
        "vulnerability_types",
        "impacts",
        "evidence_policy",
        "retained_outputs",
        "argv",
    }
)


def _fail() -> ContractError:
    return ContractError(ReasonCode.INVALID_ACTION_MANIFEST)


@dataclass(frozen=True)
class ParameterDef:
    name: str
    type: str
    required: bool
    enum_values: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    max_length: int | None = None
    pattern: SafePattern | None = None


@dataclass(frozen=True)
class RateControl:
    kind: str
    rate_parameter: str | None
    concurrency_parameter: str | None
    adapter_id: str | None


@dataclass(frozen=True)
class ActionDefinition:
    id: str
    risk: str
    platforms: frozenset[str]
    executables: Mapping[str, str]
    executable_basenames: frozenset[str]
    required_privileges: frozenset[str]
    parameters: Mapping[str, ParameterDef]
    target_bindings: frozenset[str]
    secret_bindings: frozenset[str]
    artifact_bindings: frozenset[str]
    capabilities: frozenset[str]
    vulnerability_types: frozenset[str]
    impacts: frozenset[str]
    rate_control: RateControl
    evidence_mode: str
    argv_template: tuple[str, ...]


def _require(condition: bool) -> None:
    if not condition:
        raise _fail()


def _str(value: object) -> str:
    _require(isinstance(value, str))
    assert isinstance(value, str)
    return value


def _mapping(value: object) -> Mapping[str, object]:
    _require(isinstance(value, Mapping))
    assert isinstance(value, Mapping)
    return value


def _list(value: object) -> Sequence[object]:
    _require(isinstance(value, Sequence) and not isinstance(value, str | bytes))
    assert isinstance(value, Sequence)
    return value


def _basename(path: str) -> str:
    return posixpath.basename(path.replace("\\", "/")).lower()


def _validate_executables(
    raw: object, platforms: frozenset[str], risk: str
) -> tuple[dict[str, str], frozenset[str]]:
    executables = _mapping(raw)
    resolved: dict[str, str] = {}
    basenames: set[str] = set()
    _require(bool(executables))
    for platform, path in executables.items():
        _require(platform in platforms)
        path_str = _str(path)
        _require(path_str.startswith("/") or bool(re.match(r"[A-Za-z]:\\", path_str)))
        basename = _basename(path_str)
        _require(basename not in ELEVATION_BASENAMES)
        if basename in SHELL_BASENAMES or basename in INTERPRETER_BASENAMES:
            # Shells/interpreters are only acceptable for a declared L3 action.
            _require(risk == RiskLevel.L3.value)
        resolved[platform] = path_str
        basenames.add(basename)
    return resolved, frozenset(basenames)


def _validate_parameters(raw: object) -> dict[str, ParameterDef]:
    parameters = _mapping(raw)
    _require(len(parameters) <= MAX_ACTION_PARAMETERS)
    resolved: dict[str, ParameterDef] = {}
    for name, definition in parameters.items():
        _require(bool(_BINDING_ID.fullmatch(name)))
        body = _mapping(definition)
        type_value = _str(body.get("type"))
        _require(type_value in _PARAMETER_TYPES)
        required = body.get("required")
        _require(type(required) is bool)
        assert isinstance(required, bool)
        enum_values: tuple[str, ...] = ()
        if type_value == ParameterType.ENUM.value:
            raw_values = _list(body.get("enum_values"))
            _require(MIN_ENUM_VALUES <= len(raw_values) <= MAX_ENUM_VALUES)
            enum_values = tuple(_str(value) for value in raw_values)
            _require(len(set(enum_values)) == len(enum_values))
        minimum = _int_or_none(body.get("minimum"))
        maximum = _int_or_none(body.get("maximum"))
        max_length = _int_or_none(body.get("max_length"))
        if minimum is not None:
            _require(MIN_SIGNED_INT64 <= minimum <= MAX_SIGNED_INT64)
        if maximum is not None:
            _require(MIN_SIGNED_INT64 <= maximum <= MAX_SIGNED_INT64)
        if minimum is not None and maximum is not None:
            _require(minimum <= maximum)
        if max_length is not None:
            _require(MIN_UTF8_STRING_BYTES <= max_length <= MAX_UTF8_STRING_BYTES)
        pattern = None
        if "pattern" in body:
            _require(_str(body.get("pattern_format")) == SAFE_FULLMATCH_FORMAT)
            try:
                pattern = compile_safe_pattern(_str(body.get("pattern")))
            except ContractError as exc:
                raise _fail() from exc
        resolved[name] = ParameterDef(
            name=name,
            type=type_value,
            required=required,
            enum_values=enum_values,
            minimum=minimum,
            maximum=maximum,
            max_length=max_length,
            pattern=pattern,
        )
    return resolved


def _int_or_none(value: object) -> int | None:
    if value is None:
        return None
    _require(type(value) is int)
    assert isinstance(value, int)
    return value


def _validate_rate_control(raw: object, parameters: Mapping[str, ParameterDef]) -> RateControl:
    body = _mapping(raw)
    kind = _str(body.get("kind"))
    _require(kind in {member.value for member in RateControlMode})
    rate_parameter = concurrency_parameter = adapter_id = None
    if kind == RateControlMode.ARGV_PLACEHOLDER.value:
        rate_parameter = _str(body.get("rate_parameter"))
        concurrency_parameter = _str(body.get("concurrency_parameter"))
        _require(rate_parameter in parameters and concurrency_parameter in parameters)
    elif kind == RateControlMode.NATIVE_ADAPTER.value:
        adapter_id = _str(body.get("adapter_id"))
        _require(bool(_ACTION_ID.fullmatch(adapter_id)))
    return RateControl(kind, rate_parameter, concurrency_parameter, adapter_id)


def _inline_flags_for(basenames: frozenset[str]) -> frozenset[str]:
    flags: set[str] = set()
    for basename in basenames:
        flags |= {flag.lower() for flag in INLINE_MODE_FLAGS_BY_BASENAME.get(basename, frozenset())}
    return frozenset(flags)


def _validate_argv(
    raw: object,
    parameters: Mapping[str, ParameterDef],
    target_bindings: frozenset[str],
    secret_bindings: frozenset[str],
    artifact_bindings: frozenset[str],
    executable_basenames: frozenset[str],
) -> tuple[str, ...]:
    tokens = _list(raw)
    _require(1 <= len(tokens) <= MAX_ARGV_TOKENS)
    inline_flags = _inline_flags_for(executable_basenames)
    rendered: list[str] = []
    for token in tokens:
        text = _str(token)
        _require(1 <= len(text.encode("utf-8")) <= 4096)
        match = _PLACEHOLDER.fullmatch(text)
        if match is None:
            # A literal token must contain no placeholder-looking fragment,
            # no inline-eval flag for a shell/interpreter executable, and no
            # elevation basename.
            if "{" in text or "}" in text:
                raise ContractError(ReasonCode.INVALID_PLACEHOLDER)
            _require(text.lower() not in inline_flags)
            _require(_basename(text) not in ELEVATION_BASENAMES)
            rendered.append(text)
            continue
        kind, name = match.group(1), match.group(2)
        if kind == "value":
            param = parameters.get(name)
            _require(param is not None)
            assert param is not None
            # Target-shaped values must go through scope-checked target bindings.
            _require(param.type not in _TARGET_PARAMETER_TYPES)
        elif kind in {"target", "targets_file"}:
            _require(name in target_bindings)
        elif kind == "artifact_file":
            _require(name in artifact_bindings)
        else:  # secret_file
            _require(name in secret_bindings)
        rendered.append(text)
    return tuple(rendered)


def _validate_action(raw: object, seen_ids: set[str]) -> ActionDefinition:
    action = _mapping(raw)
    for key in action:
        _require(key in _ACTION_FIELDS)

    action_id = _str(action.get("id"))
    _require(action_id.startswith(OPERATOR_ACTION_ID_PREFIX))
    _require(bool(_ACTION_ID.fullmatch(action_id)))
    _require(len(action_id.encode("utf-8")) <= MAX_IDENTIFIER_BYTES)
    _require(action_id not in seen_ids)

    risk = _str(action.get("risk"))
    _require(risk in {member.value for member in RiskLevel})

    platforms = frozenset(_str(p) for p in _list(action.get("platforms")))
    _require(bool(platforms) and platforms <= {member.value for member in Platform})
    architectures = frozenset(_str(a) for a in _list(action.get("architectures")))
    _require(architectures <= {member.value for member in Architecture})
    privileges = frozenset(_str(p) for p in _list(action.get("required_privileges")))
    _require(privileges <= {member.value for member in Privilege})

    parameters = _validate_parameters(action.get("parameters"))
    artifact_bindings = frozenset(
        name for name, param in parameters.items() if param.type == ParameterType.ARTIFACT_REF.value
    )
    target_bindings = frozenset(_str(t) for t in _list(action.get("targets")))
    _require(len(target_bindings) <= MAX_TARGET_BINDINGS)
    for name in target_bindings:
        _require(bool(_BINDING_ID.fullmatch(name)))
    secrets = _mapping(action.get("secrets"))
    _require(len(secrets) <= MAX_ACTION_SECRETS)
    secret_bindings = frozenset(secrets.keys())

    capabilities = frozenset(_str(c) for c in _list(action.get("capabilities")))
    _require(len(capabilities) <= MAX_ACTION_CAPABILITIES)
    _require(capabilities <= set(CAPABILITY_TO_FIELD))
    vulnerability_types = frozenset(_str(v) for v in _list(action.get("vulnerability_types")))
    impacts = frozenset(_str(i) for i in _list(action.get("impacts")))

    evidence_policy = _mapping(action.get("evidence_policy"))
    evidence_mode = _str(evidence_policy.get("mode"))
    _require(evidence_mode in {member.value for member in EvidenceMode})

    executables, basenames = _validate_executables(action.get("executables"), platforms, risk)
    rate_control = _validate_rate_control(action.get("rate_control"), parameters)
    argv_template = _validate_argv(
        action.get("argv"),
        parameters,
        target_bindings,
        secret_bindings,
        artifact_bindings,
        basenames,
    )

    seen_ids.add(action_id)
    return ActionDefinition(
        id=action_id,
        risk=risk,
        platforms=platforms,
        executables=MappingProxyType(executables),
        executable_basenames=basenames,
        required_privileges=privileges,
        parameters=MappingProxyType(parameters),
        target_bindings=target_bindings,
        secret_bindings=secret_bindings,
        artifact_bindings=artifact_bindings,
        capabilities=capabilities,
        vulnerability_types=vulnerability_types,
        impacts=impacts,
        rate_control=rate_control,
        evidence_mode=evidence_mode,
        argv_template=argv_template,
    )


def validate_manifest(document: Mapping[str, object]) -> Mapping[str, ActionDefinition]:
    """Validate a decoded actions manifest and return an immutable registry."""

    version = document.get("schema_version")
    if type(version) is not int or version != ACTIONS_SCHEMA_VERSION:
        raise ContractError(ReasonCode.INVALID_SCHEMA_VERSION)
    for key in document:
        if key not in {"schema_version", "actions"}:
            raise ContractError(ReasonCode.INVALID_UNKNOWN_FIELD)
    actions = _list(document.get("actions"))
    _require(len(actions) <= MAX_ACTIONS)
    registry: dict[str, ActionDefinition] = {}
    seen_ids: set[str] = set()
    for raw in actions:
        action = _validate_action(raw, seen_ids)
        registry[action.id] = action
    return MappingProxyType(registry)


def load_manifest(path: str) -> Mapping[str, ActionDefinition]:
    """Load and validate an actions.yaml manifest into an immutable registry."""

    document = read_hardened_document(path, MAX_ACTION_MANIFEST_BYTES)
    return validate_manifest(document)
