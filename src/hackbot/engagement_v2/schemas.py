"""Code-owned JSON Schema documents for the isolated engagement-v2 contracts."""

from __future__ import annotations

import hashlib
import json
from enum import Enum

from hackbot.engagement_v2.canonical import canonical_bytes
from hackbot.engagement_v2.constants import (
    ACTION_REQUEST_SCHEMA_VERSION,
    ACTIONS_SCHEMA_VERSION,
    ARGV_TOKEN_TERMINATOR_BYTES,
    AUTHORIZATION_SCHEMA_VERSION,
    ED25519_PUBLIC_KEY_BYTES,
    ED25519_SIGNATURE_BYTES,
    IDENTIFIER_PATTERN,
    MAPPING_KEY_PATTERN,
    MAX_ACTION_CAPABILITIES,
    MAX_ACTION_IMPACTS,
    MAX_ACTION_MANIFEST_BYTES,
    MAX_ACTION_PARAMETERS,
    MAX_ACTION_SECRETS,
    MAX_ACTION_VULNERABILITY_TYPES,
    MAX_ACTIONS,
    MAX_ARGV_BYTES,
    MAX_ARGV_TOKEN_BYTES,
    MAX_ARGV_TOKENS,
    MAX_AUTHORIZATION_DOCUMENT_BYTES,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_DOCUMENT_NESTING_DEPTH,
    MAX_EGRESS_OBSERVATION_AGE_SECONDS,
    MAX_ENUM_VALUES,
    MAX_FRAME_BYTES,
    MAX_FRAME_COUNT,
    MAX_IDENTIFIER_BYTES,
    MAX_OUTPUT_CAP_BYTES,
    MAX_PORT,
    MAX_PREPARED_INPUT_BYTES,
    MAX_PROGRAM_DOCUMENT_BYTES,
    MAX_PROTOCOL_HEADER_BYTES,
    MAX_REQUEST_BYTES,
    MAX_REQUEST_LIFETIME_SECONDS,
    MAX_REQUESTS_PER_SECOND,
    MAX_RESPONSE_BYTES,
    MAX_RETAINED_OUTPUT_BYTES,
    MAX_RETAINED_OUTPUT_ITEM_BYTES,
    MAX_RETAINED_OUTPUT_ITEM_COUNT,
    MAX_RUNNER_CONCURRENCY,
    MAX_RUNNER_DOCUMENT_BYTES,
    MAX_SAFE_PATTERN_BYTES,
    MAX_SCALAR_OR_TARGET_BYTES,
    MAX_SCOPE_DOCUMENT_BYTES,
    MAX_SECRET_BYTES,
    MAX_SECRETS_BYTES,
    MAX_SIGNED_INT64,
    MAX_TARGET_BINDINGS,
    MAX_TARGET_LIST_LENGTH,
    MAX_TARGETS_PER_ACTION,
    MAX_TIMEOUT_SECONDS,
    MAX_UTF8_STRING_BYTES,
    MIN_ENUM_VALUES,
    MIN_OUTPUT_CAP_BYTES,
    MIN_PORT,
    MIN_REQUEST_LIFETIME_SECONDS,
    MIN_REQUESTS_PER_SECOND,
    MIN_RETAINED_OUTPUT_ITEM_BYTES,
    MIN_RETAINED_OUTPUT_ITEM_COUNT,
    MIN_RUNNER_CONCURRENCY,
    MIN_SIGNED_INT64,
    MIN_TARGETS_PER_ACTION,
    MIN_TIMEOUT_SECONDS,
    MIN_UTF8_STRING_BYTES,
    NONCE_BASE64URL_LENGTH,
    NONCE_BYTES,
    OPERATOR_ACTION_ID_PREFIX,
    POLICY_BOOLEAN_FIELDS,
    PROGRAM_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    REPLAY_RESERVATION_SECONDS,
    REQUEST_FRAME_TYPES,
    RUN_ID_PATTERN,
    RUNNER_SCHEMA_VERSION,
    SAFE_FULLMATCH_FORMAT,
    SCOPE_SCHEMA_VERSION,
    SECRET_REFERENCE_PATTERN,
    SHA256_HEX_LENGTH,
    SHA256_PREFIX,
    Architecture,
    EvidenceMode,
    FrameType,
    ParameterType,
    PlaceholderKind,
    Platform,
    Privilege,
    Profile,
    RateControlMode,
    RetainedOutputType,
    RiskLevel,
    RunnerRole,
    SecretTransport,
    SourceIdentityMode,
)

_DRAFT = "https://json-schema.org/draft/2020-12/schema"
_CONTRACT = "hackbot-engagement-v2-schemas-v1"
_TIMESTAMP_PATTERN = (
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_ABSOLUTE_PATH_PATTERN = r"^(?:/|[A-Za-z]:[\\/]).+$"
_RELATIVE_OUTPUT_PATTERN = r"^(?!/)(?!.*\\)(?!.*(?:^|/)(?:\.|\.\.)(?:/|$))(?!.*//).+$"
_OPERATOR_ACTION_PREFIX_PATTERN = OPERATOR_ACTION_ID_PREFIX[:-1] + r"\."
_PLACEHOLDER_KINDS_PATTERN = "|".join(member.value for member in PlaceholderKind)
_ARGV_TOKEN_PATTERN = (
    rf"^(?:[^{{}}]+|\{{(?:{_PLACEHOLDER_KINDS_PATTERN}):"
    rf"{IDENTIFIER_PATTERN.pattern}\}})$"
)


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


def _mapping(
    value_schema: dict[str, object],
    *,
    key_pattern: str,
    maximum: int,
) -> dict[str, object]:
    return {
        "type": "object",
        "patternProperties": {key_pattern: value_schema},
        "maxProperties": maximum,
        "additionalProperties": False,
    }


def _enum(enum_type: type[Enum]) -> dict[str, object]:
    return {"type": "string", "enum": [member.value for member in enum_type]}


def _integer(minimum: int, maximum: int) -> dict[str, object]:
    return {"type": "integer", "minimum": minimum, "maximum": maximum}


def _string(*, minimum: int = 1, maximum: int = MAX_UTF8_STRING_BYTES) -> dict[str, object]:
    return {"type": "string", "minLength": minimum, "maxLength": maximum}


def _array(
    items: dict[str, object],
    *,
    minimum: int = 0,
    maximum: int | None = None,
    unique: bool = False,
    unique_by: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {"type": "array", "items": items, "minItems": minimum}
    if maximum is not None:
        result["maxItems"] = maximum
    if unique:
        result["uniqueItems"] = True
    if unique_by is not None:
        result["x-hackbot-unique-by"] = unique_by
    return result


def _ref(name: str) -> dict[str, object]:
    return {"$ref": f"#/$defs/{name}"}


def _anchored(pattern: str) -> str:
    return f"^{pattern}$"


def _identifier() -> dict[str, object]:
    return {
        "type": "string",
        "pattern": _anchored(IDENTIFIER_PATTERN.pattern),
        "maxLength": MAX_IDENTIFIER_BYTES,
    }


def _mapping_identifier_pattern() -> str:
    return _anchored(MAPPING_KEY_PATTERN.pattern)


def _digest() -> dict[str, object]:
    length = len(SHA256_PREFIX) + SHA256_HEX_LENGTH
    return {
        "type": "string",
        "pattern": rf"^{SHA256_PREFIX}[0-9a-f]{{{SHA256_HEX_LENGTH}}}$",
        "minLength": length,
        "maxLength": length,
    }


def _document(
    *,
    schema_id: str,
    properties: dict[str, object],
    required: tuple[str, ...],
    definitions: dict[str, object],
    annotations: dict[str, object] | None = None,
) -> dict[str, object]:
    document = {
        "$schema": _DRAFT,
        "$id": schema_id,
        "$defs": definitions,
        **_object(properties, required),
    }
    if annotations is not None:
        document.update(annotations)
    document["x-hackbot-max-document-nesting-depth"] = MAX_DOCUMENT_NESTING_DEPTH
    _annotate_utf8_string_limits(document)
    return document


def _annotate_utf8_string_limits(value: object) -> None:
    if isinstance(value, dict):
        if value.get("type") == "string" and "maxLength" in value:
            value["x-hackbot-max-utf8-bytes"] = value["maxLength"]
        for child in value.values():
            _annotate_utf8_string_limits(child)
    elif isinstance(value, list):
        for child in value:
            _annotate_utf8_string_limits(child)


def _common_definitions() -> dict[str, object]:
    return {
        "identifier": _identifier(),
        "digest": _digest(),
        "strict_boolean": {"type": "boolean"},
        "target": {
            "type": "string",
            "minLength": MIN_UTF8_STRING_BYTES,
            "maxLength": MAX_SCALAR_OR_TARGET_BYTES,
        },
    }


def _program_schema() -> dict[str, object]:
    definitions = {
        **_common_definitions(),
        "profile": _enum(Profile),
    }
    numeric_rules = {
        "max_requests_per_second": _integer(MIN_REQUESTS_PER_SECOND, MAX_REQUESTS_PER_SECOND),
        "concurrency": _integer(MIN_RUNNER_CONCURRENCY, MAX_RUNNER_CONCURRENCY),
        "timeout_seconds": _integer(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS),
        "output_cap_bytes": _integer(MIN_OUTPUT_CAP_BYTES, MAX_OUTPUT_CAP_BYTES),
        "max_targets_per_action": _integer(MIN_TARGETS_PER_ACTION, MAX_TARGETS_PER_ACTION),
    }
    policy_properties: dict[str, object] = {
        **numeric_rules,
        **{name: _ref("strict_boolean") for name in sorted(POLICY_BOOLEAN_FIELDS)},
        "source_ip_requirements": _array(_ref("target"), unique=True),
        "required_headers": _array(_string(maximum=MAX_SCALAR_OR_TARGET_BYTES), unique=True),
        "restricted_hours": {
            "oneOf": [
                {"type": "null"},
                _object(
                    {
                        "timezone": _string(maximum=MAX_SCALAR_OR_TARGET_BYTES),
                        "windows": _array(
                            {
                                "type": "string",
                                "pattern": (
                                    r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]-"
                                    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]$"
                                ),
                            },
                            minimum=1,
                            unique=True,
                        ),
                    },
                    ("timezone", "windows"),
                ),
            ]
        },
        "prohibited_tools": _array(_ref("identifier"), unique=True),
        "prohibited_vulnerability_types": _array(_ref("identifier"), unique=True),
        "excluded_impacts": _array(_ref("identifier"), unique=True),
    }
    return _document(
        schema_id=f"urn:hackbot:schema:engagement-v2:program:{PROGRAM_SCHEMA_VERSION}",
        properties={
            "schema_version": {"type": "integer", "const": PROGRAM_SCHEMA_VERSION},
            "program": _object(
                {
                    "name": _ref("identifier"),
                    "platform": _ref("identifier"),
                    "source": _ref("identifier"),
                },
                ("name", "platform", "source"),
            ),
            "profile": _ref("profile"),
            "testing_rules": _object(
                policy_properties,
                (
                    "max_requests_per_second",
                    "concurrency",
                    "timeout_seconds",
                    "output_cap_bytes",
                    "max_targets_per_action",
                ),
            ),
            "reporting": _object(
                {"duplicate_policy": _ref("identifier")},
                ("duplicate_policy",),
            ),
        },
        required=("schema_version", "program", "profile", "testing_rules", "reporting"),
        definitions=definitions,
        annotations={
            "x-hackbot-max-document-bytes": MAX_PROGRAM_DOCUMENT_BYTES,
        },
    )


def _scope_schema() -> dict[str, object]:
    scope_properties: dict[str, object] = {
        name: _array(_ref("target"), unique=True)
        for name in (
            "domains",
            "wildcard_domains",
            "urls",
            "hosts",
            "cidrs",
            "network_endpoints",
            "mobile_apps",
            "repositories",
            "contracts",
        )
    }
    scope_section = _object(scope_properties, ())
    scope_section["maxProperties"] = len(scope_properties)
    definitions = {
        **_common_definitions(),
        "scope_section": scope_section,
    }
    return _document(
        schema_id=f"urn:hackbot:schema:engagement-v2:scope:{SCOPE_SCHEMA_VERSION}",
        properties={
            "schema_version": {"type": "integer", "const": SCOPE_SCHEMA_VERSION},
            "in_scope": {
                "allOf": [
                    _ref("scope_section"),
                    {"minProperties": 1},
                ]
            },
            "out_of_scope": _ref("scope_section"),
        },
        required=("schema_version", "in_scope", "out_of_scope"),
        definitions=definitions,
        annotations={
            "x-hackbot-max-document-bytes": MAX_SCOPE_DOCUMENT_BYTES,
        },
    )


def _authorization_schema() -> dict[str, object]:
    definitions = _common_definitions()
    return _document(
        schema_id=(
            f"urn:hackbot:schema:engagement-v2:authorization:{AUTHORIZATION_SCHEMA_VERSION}"
        ),
        properties={
            "schema_version": {
                "type": "integer",
                "const": AUTHORIZATION_SCHEMA_VERSION,
            },
            "confirmed": _ref("strict_boolean"),
            "confirmation_timestamp": {
                "type": "string",
                "format": "date-time",
                "pattern": _TIMESTAMP_PATTERN,
            },
            "confirmed_by": _ref("identifier"),
            "confirmed_authority_digest": _ref("digest"),
            "note": _string(),
        },
        required=(
            "schema_version",
            "confirmed",
            "confirmation_timestamp",
            "confirmed_by",
            "confirmed_authority_digest",
            "note",
        ),
        definitions=definitions,
        annotations={
            "x-hackbot-max-document-bytes": MAX_AUTHORIZATION_DOCUMENT_BYTES,
        },
    )


def _parameter_schema() -> dict[str, object]:
    default_value = {
        "oneOf": [
            {"type": "string", "maxLength": MAX_UTF8_STRING_BYTES},
            _integer(MIN_SIGNED_INT64, MAX_SIGNED_INT64),
            {"type": "boolean"},
            _ref("target_list"),
        ]
    }
    result = _object(
        {
            "type": _ref("parameter_type"),
            "required": _ref("strict_boolean"),
            "max_length": _integer(MIN_UTF8_STRING_BYTES, MAX_UTF8_STRING_BYTES),
            "pattern_format": {"type": "string", "const": SAFE_FULLMATCH_FORMAT},
            "pattern": {
                "type": "string",
                "format": SAFE_FULLMATCH_FORMAT,
                "minLength": 1,
                "maxLength": MAX_SAFE_PATTERN_BYTES,
            },
            "minimum": _integer(MIN_SIGNED_INT64, MAX_SIGNED_INT64),
            "maximum": _integer(MIN_SIGNED_INT64, MAX_SIGNED_INT64),
            "enum_values": _array(
                _string(maximum=MAX_SCALAR_OR_TARGET_BYTES),
                minimum=MIN_ENUM_VALUES,
                maximum=MAX_ENUM_VALUES,
                unique=True,
            ),
            "item_type": _ref("target_kind"),
            "default": default_value,
            "artifact_sha256": _ref("digest"),
        },
        ("type", "required"),
    )
    result["allOf"] = [
        {
            "if": {"properties": {"type": {"const": "string"}}, "required": ["type"]},
            "then": {"required": ["max_length"]},
        },
        {
            "if": {"properties": {"type": {"const": "enum"}}, "required": ["type"]},
            "then": {"required": ["enum_values"]},
        },
        {
            "if": {"properties": {"type": {"const": "target-list"}}, "required": ["type"]},
            "then": {"required": ["item_type"]},
        },
        {
            "if": {"properties": {"type": {"const": "artifact-ref"}}, "required": ["type"]},
            "then": {"required": ["artifact_sha256"]},
        },
        {
            "if": {"required": ["pattern"]},
            "then": {"required": ["pattern_format"]},
        },
    ]
    return result


def _characteristics_schema() -> dict[str, object]:
    fields = (
        "network_access",
        "high_volume",
        "touches_third_party",
        "follows_redirects",
        "recursive_discovery",
        "state_changing",
        "creates_account",
        "uses_multiple_accounts",
        "out_of_band",
        "honors_required_headers",
    )
    return _object({name: _ref("strict_boolean") for name in fields}, fields)


def _rate_control_schema() -> dict[str, object]:
    result = _object(
        {
            "kind": _ref("rate_control_mode"),
            "rate_parameter": _ref("identifier"),
            "concurrency_parameter": _ref("identifier"),
            "adapter_id": _ref("identifier"),
        },
        ("kind",),
    )
    result["allOf"] = [
        {
            "if": {
                "properties": {"kind": {"const": RateControlMode.ARGV_PLACEHOLDER.value}},
                "required": ["kind"],
            },
            "then": {"required": ["rate_parameter", "concurrency_parameter"]},
        },
        {
            "if": {
                "properties": {"kind": {"const": RateControlMode.NATIVE_ADAPTER.value}},
                "required": ["kind"],
            },
            "then": {"required": ["adapter_id"]},
        },
    ]
    return result


def _retained_output_schema() -> dict[str, object]:
    return _object(
        {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_SCALAR_OR_TARGET_BYTES,
                "pattern": _RELATIVE_OUTPUT_PATTERN,
            },
            "type": _ref("retained_output_type"),
            "max_items": _integer(
                MIN_RETAINED_OUTPUT_ITEM_COUNT,
                MAX_RETAINED_OUTPUT_ITEM_COUNT,
            ),
            "max_item_bytes": _integer(
                MIN_RETAINED_OUTPUT_ITEM_BYTES,
                MAX_RETAINED_OUTPUT_ITEM_BYTES,
            ),
            "evidence_mode": _ref("evidence_mode"),
        },
        ("path", "type", "max_items", "max_item_bytes", "evidence_mode"),
    )


def _action_schema() -> dict[str, object]:
    absolute_path = {
        "type": "string",
        "minLength": 2,
        "maxLength": MAX_SCALAR_OR_TARGET_BYTES,
        "pattern": _ABSOLUTE_PATH_PATTERN,
    }
    executable_paths = _object(
        {"local": absolute_path, "remote": absolute_path},
        (),
    )
    executable_paths["anyOf"] = [{"required": ["local"]}, {"required": ["remote"]}]
    executable_digests = _object(
        {"local": _ref("digest"), "remote": _ref("digest")},
        (),
    )
    executable_digests["anyOf"] = [{"required": ["local"]}, {"required": ["remote"]}]
    target_binding = _object(
        {
            "parameter": _ref("identifier"),
            "kind": _ref("target_kind"),
        },
        ("parameter", "kind"),
    )
    secret = _object(
        {
            "reference": _ref("secret_reference"),
            "transport": _ref("secret_transport"),
        },
        ("reference", "transport"),
    )
    evidence_policy = _object(
        {
            "mode": _ref("evidence_mode"),
            "sensitivity": _ref("identifier"),
        },
        ("mode", "sensitivity"),
    )
    result = _object(
        {
            "id": _ref("operator_action_id"),
            "title": _string(maximum=MAX_SCALAR_OR_TARGET_BYTES),
            "risk": _ref("risk_level"),
            "platforms": _array(
                _ref("platform"),
                minimum=1,
                maximum=len(Platform),
                unique=True,
            ),
            "architectures": _array(
                _ref("architecture"),
                minimum=1,
                maximum=len(Architecture),
                unique=True,
            ),
            "executables": executable_paths,
            "executable_digests": executable_digests,
            "required_privileges": _array(
                _ref("privilege"),
                maximum=len(Privilege),
                unique=True,
            ),
            "parameters": _mapping(
                _ref("parameter"),
                key_pattern=_mapping_identifier_pattern(),
                maximum=MAX_ACTION_PARAMETERS,
            ),
            "secrets": _mapping(
                secret,
                key_pattern=_mapping_identifier_pattern(),
                maximum=MAX_ACTION_SECRETS,
            ),
            "targets": _array(
                target_binding,
                maximum=MAX_TARGET_BINDINGS,
                unique=True,
            ),
            "characteristics": _characteristics_schema(),
            "rate_control": _rate_control_schema(),
            "capabilities": _array(
                _ref("identifier"),
                maximum=MAX_ACTION_CAPABILITIES,
                unique=True,
            ),
            "vulnerability_types": _array(
                _ref("identifier"),
                maximum=MAX_ACTION_VULNERABILITY_TYPES,
                unique=True,
            ),
            "impacts": _array(
                _ref("identifier"),
                maximum=MAX_ACTION_IMPACTS,
                unique=True,
            ),
            "evidence_policy": evidence_policy,
            "retained_outputs": _array(_ref("retained_output"), unique=True),
            "argv": _array(
                {
                    **_ref("argv_token"),
                    "minLength": MIN_UTF8_STRING_BYTES,
                    "maxLength": MAX_ARGV_TOKEN_BYTES,
                },
                minimum=1,
                maximum=MAX_ARGV_TOKENS,
            ),
        },
        (
            "id",
            "title",
            "risk",
            "platforms",
            "architectures",
            "executables",
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
            "argv",
        ),
    )
    result["allOf"] = [
        {
            "if": {
                "properties": {
                    "required_privileges": {"contains": {"const": Privilege.SUPERUSER.value}}
                },
                "required": ["required_privileges"],
            },
            "then": {
                "x-hackbot-derived-minimum-risk": RiskLevel.L3.value,
                "x-hackbot-required-policy-field": "privileged_execution_allowed",
            },
        },
        {
            "if": {
                "properties": {
                    "evidence_policy": {
                        "properties": {"mode": {"const": EvidenceMode.STRUCTURED.value}},
                        "required": ["mode"],
                    }
                },
                "required": ["evidence_policy"],
            },
            "then": False,
        },
        {
            "if": {
                "properties": {
                    "rate_control": {
                        "properties": {"kind": {"const": RateControlMode.NOT_APPLICABLE.value}},
                        "required": ["kind"],
                    }
                },
                "required": ["rate_control"],
            },
            "then": {
                "properties": {
                    "characteristics": {
                        "properties": {
                            "high_volume": {"const": False},
                            "recursive_discovery": {"const": False},
                        }
                    },
                    "targets": {"maxItems": 1, "minItems": 1},
                },
                "x-hackbot-requires-no-fan-out": True,
            },
        },
    ]
    return result


def _actions_schema() -> dict[str, object]:
    target_kinds = tuple(
        parameter_type
        for parameter_type in ParameterType
        if parameter_type
        in {
            ParameterType.DOMAIN,
            ParameterType.HOST,
            ParameterType.IP,
            ParameterType.CIDR,
            ParameterType.URL,
            ParameterType.NETWORK_ENDPOINT,
            ParameterType.REPOSITORY,
            ParameterType.CONTRACT,
        }
    )
    definitions = {
        **_common_definitions(),
        "operator_action_id": {
            "type": "string",
            "pattern": (f"^{_OPERATOR_ACTION_PREFIX_PATTERN}{IDENTIFIER_PATTERN.pattern}$"),
            "maxLength": MAX_IDENTIFIER_BYTES,
        },
        "secret_reference": {
            "type": "string",
            "pattern": _anchored(SECRET_REFERENCE_PATTERN.pattern),
            "maxLength": len("secret:") + MAX_IDENTIFIER_BYTES,
        },
        "profile": _enum(Profile),
        "parameter_type": _enum(ParameterType),
        "placeholder_kind": _enum(PlaceholderKind),
        "platform": _enum(Platform),
        "architecture": _enum(Architecture),
        "privilege": _enum(Privilege),
        "risk_level": _enum(RiskLevel),
        "evidence_mode": _enum(EvidenceMode),
        "rate_control_mode": _enum(RateControlMode),
        "secret_transport": _enum(SecretTransport),
        "retained_output_type": _enum(RetainedOutputType),
        "argv_token": {
            "type": "string",
            "pattern": _ARGV_TOKEN_PATTERN,
            "minLength": MIN_UTF8_STRING_BYTES,
            "maxLength": MAX_ARGV_TOKEN_BYTES,
        },
        "target_kind": {
            "type": "string",
            "enum": [member.value for member in target_kinds],
        },
        "port": _integer(MIN_PORT, MAX_PORT),
        "target_list": _array(
            _ref("target"),
            minimum=1,
            maximum=MAX_TARGET_LIST_LENGTH,
            unique=True,
        ),
    }
    definitions["parameter"] = _parameter_schema()
    definitions["retained_output"] = _retained_output_schema()
    definitions["action"] = _action_schema()
    return _document(
        schema_id=f"urn:hackbot:schema:engagement-v2:actions:{ACTIONS_SCHEMA_VERSION}",
        properties={
            "schema_version": {"type": "integer", "const": ACTIONS_SCHEMA_VERSION},
            "actions": _array(
                _ref("action"),
                maximum=MAX_ACTIONS,
                unique=True,
                unique_by="id",
            ),
        },
        required=("schema_version", "actions"),
        definitions=definitions,
        annotations={
            "x-hackbot-max-document-bytes": MAX_ACTION_MANIFEST_BYTES,
            "x-hackbot-max-secret-bytes": MAX_SECRET_BYTES,
            "x-hackbot-max-secrets-bytes": MAX_SECRETS_BYTES,
            "x-hackbot-max-prepared-input-bytes": MAX_PREPARED_INPUT_BYTES,
            "x-hackbot-max-argv-bytes": MAX_ARGV_BYTES,
            "x-hackbot-argv-token-terminator-bytes": ARGV_TOKEN_TERMINATOR_BYTES,
            "x-hackbot-max-retained-output-bytes": MAX_RETAINED_OUTPUT_BYTES,
        },
    )


def _action_request_schema() -> dict[str, object]:
    definitions = {
        **_common_definitions(),
        "risk_level": _enum(RiskLevel),
        "target_list": _array(
            _ref("target"),
            minimum=1,
            maximum=MAX_TARGET_LIST_LENGTH,
            unique=True,
        ),
        "parameter_value": {
            "oneOf": [
                {"type": "string", "maxLength": MAX_UTF8_STRING_BYTES},
                _integer(MIN_SIGNED_INT64, MAX_SIGNED_INT64),
                {"type": "boolean"},
                _ref("target_list"),
            ]
        },
    }
    narrative = _string()
    return _document(
        schema_id=(
            f"urn:hackbot:schema:engagement-v2:action-request:{ACTION_REQUEST_SCHEMA_VERSION}"
        ),
        properties={
            "schema_version": {
                "type": "integer",
                "const": ACTION_REQUEST_SCHEMA_VERSION,
            },
            "action_id": _ref("identifier"),
            "parameters": _mapping(
                _ref("parameter_value"),
                key_pattern=_mapping_identifier_pattern(),
                maximum=MAX_ACTION_PARAMETERS,
            ),
            "requested_risk": _ref("risk_level"),
            "hypothesis_id": _ref("identifier"),
            "rationale": narrative,
            "expected_impact": narrative,
            "stop_condition": narrative,
            "cleanup_plan": narrative,
        },
        required=(
            "schema_version",
            "action_id",
            "parameters",
            "hypothesis_id",
            "rationale",
            "expected_impact",
            "stop_condition",
            "cleanup_plan",
        ),
        definitions=definitions,
    )


def _ssh_schema() -> dict[str, object]:
    ssh_options = _object(
        {
            "batch_mode": {"type": "boolean", "const": True},
            "identities_only": {"type": "boolean", "const": True},
            "strict_host_key_checking": {"type": "boolean", "const": True},
            "agent_forwarding": {"type": "boolean", "const": False},
            "x11_forwarding": {"type": "boolean", "const": False},
            "port_forwarding": {"type": "boolean", "const": False},
            "tty": {"type": "boolean", "const": False},
        },
        (
            "batch_mode",
            "identities_only",
            "strict_host_key_checking",
            "agent_forwarding",
            "x11_forwarding",
            "port_forwarding",
            "tty",
        ),
    )
    return _object(
        {
            "host": _ref("target"),
            "port": _integer(MIN_PORT, MAX_PORT),
            "user": _ref("identifier"),
            "identity": _ref("identifier"),
            "private_key_path": _ref("absolute_path"),
            "known_hosts_path": _ref("absolute_path"),
            "host_key_sha256": _ref("digest"),
            "connection_timeout_seconds": {
                "type": "integer",
                "minimum": MIN_TIMEOUT_SECONDS,
            },
            "options": ssh_options,
        },
        (
            "host",
            "port",
            "user",
            "identity",
            "private_key_path",
            "known_hosts_path",
            "host_key_sha256",
            "connection_timeout_seconds",
            "options",
        ),
    )


def _runner_schema() -> dict[str, object]:
    egress_attestation = {
        "oneOf": [
            {"type": "null"},
            _object(
                {
                    "adapter_identity": _ref("identifier"),
                    "adapter_sha256": _ref("digest"),
                    "signer_public_key_sha256": _ref("digest"),
                },
                (
                    "adapter_identity",
                    "adapter_sha256",
                    "signer_public_key_sha256",
                ),
            ),
        ]
    }
    helper = _object(
        {
            "path": _ref("absolute_path"),
            "protocol_version": {"type": "integer", "const": PROTOCOL_VERSION},
            "sha256": _ref("digest"),
            "code_signing_identity": _ref("identifier"),
        },
        ("path", "protocol_version"),
    )
    helper["anyOf"] = [{"required": ["sha256"]}, {"required": ["code_signing_identity"]}]
    source_identity = _object(
        {
            "mode": _ref("source_identity_mode"),
            "address": {
                "oneOf": [
                    {"type": "null"},
                    _ref("target"),
                ]
            },
        },
        ("mode", "address"),
    )
    definitions = {
        **_common_definitions(),
        "runner_role": _enum(RunnerRole),
        "platform": _enum(Platform),
        "architecture": _enum(Architecture),
        "privilege": _enum(Privilege),
        "source_identity_mode": _enum(SourceIdentityMode),
        "absolute_path": {
            "type": "string",
            "minLength": 2,
            "maxLength": MAX_SCALAR_OR_TARGET_BYTES,
            "pattern": _ABSOLUTE_PATH_PATTERN,
        },
    }
    document = _document(
        schema_id=f"urn:hackbot:schema:engagement-v2:runner:{RUNNER_SCHEMA_VERSION}",
        properties={
            "schema_version": {"type": "integer", "const": RUNNER_SCHEMA_VERSION},
            "role": _ref("runner_role"),
            "node_identity": _ref("identifier"),
            "ssh": _ssh_schema(),
            "helper": helper,
            "operating_system": _ref("platform"),
            "architecture": _ref("architecture"),
            "permitted_privileges": _array(
                _ref("privilege"),
                maximum=len(Privilege),
                unique=True,
            ),
            "source_identity": source_identity,
            "egress_attestation": egress_attestation,
            "privilege_signer_public_key_fingerprint": _ref("digest"),
        },
        required=(
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
        ),
        definitions=definitions,
        annotations={
            "x-hackbot-max-document-bytes": MAX_RUNNER_DOCUMENT_BYTES,
        },
    )
    document["allOf"] = [
        {
            "if": {
                "properties": {
                    "source_identity": {
                        "properties": {
                            "mode": {"const": SourceIdentityMode.DIRECT_INTERFACE.value}
                        },
                        "required": ["mode"],
                    }
                },
                "required": ["source_identity"],
            },
            "then": {
                "properties": {
                    "source_identity": {
                        "properties": {"address": {"type": "string"}},
                        "required": ["address"],
                    }
                }
            },
        },
        {
            "if": {
                "properties": {
                    "source_identity": {
                        "properties": {"mode": {"const": SourceIdentityMode.ATTESTED_EGRESS.value}},
                        "required": ["mode"],
                    }
                },
                "required": ["source_identity"],
            },
            "then": {
                "properties": {
                    "egress_attestation": {"not": {"type": "null"}},
                }
            },
        },
    ]
    return document


def _remote_header_schema() -> dict[str, object]:
    request_frame_types = [
        frame_type.value for frame_type in FrameType if frame_type in REQUEST_FRAME_TYPES
    ]
    definitions = {
        **_common_definitions(),
        "run_id": {
            "type": "string",
            "pattern": _anchored(RUN_ID_PATTERN.pattern),
        },
        "nonce": {
            "type": "string",
            "pattern": rf"^[A-Za-z0-9_-]{{{NONCE_BASE64URL_LENGTH - 1}}}[AQgw]$",
            "minLength": NONCE_BASE64URL_LENGTH,
            "maxLength": NONCE_BASE64URL_LENGTH,
        },
        "timestamp": {
            "type": "string",
            "format": "date-time",
            "pattern": _TIMESTAMP_PATTERN,
        },
        "platform": _enum(Platform),
        "architecture": _enum(Architecture),
        "privilege": _enum(Privilege),
        "argv_token": {
            "type": "string",
            "pattern": _ARGV_TOKEN_PATTERN,
            "minLength": MIN_UTF8_STRING_BYTES,
            "maxLength": MAX_ARGV_TOKEN_BYTES,
        },
    }
    definitions["frame_descriptor"] = _object(
        {
            "index": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_FRAME_COUNT - 1,
            },
            "frame_type": {"type": "integer", "enum": request_frame_types},
            "length": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_FRAME_BYTES,
            },
            "sha256": _ref("digest"),
        },
        ("index", "frame_type", "length", "sha256"),
    )
    definitions["executable"] = _object(
        {
            "path": {
                "type": "string",
                "minLength": 2,
                "maxLength": MAX_SCALAR_OR_TARGET_BYTES,
                "pattern": _ABSOLUTE_PATH_PATTERN,
            },
            "sha256": _ref("digest"),
        },
        ("path", "sha256"),
    )
    return _document(
        schema_id=f"urn:hackbot:schema:engagement-v2:remote-header:{PROTOCOL_VERSION}",
        properties={
            "protocol_version": {"type": "integer", "const": PROTOCOL_VERSION},
            "run_id": _ref("run_id"),
            "nonce": _ref("nonce"),
            "issued_at": _ref("timestamp"),
            "expires_at": _ref("timestamp"),
            "authority_digest": _ref("digest"),
            "execution_digest": _ref("digest"),
            "action_id": _ref("identifier"),
            "argv": _array(
                {
                    **_ref("argv_token"),
                    "minLength": MIN_UTF8_STRING_BYTES,
                    "maxLength": MAX_ARGV_TOKEN_BYTES,
                },
                minimum=1,
                maximum=MAX_ARGV_TOKENS,
            ),
            "executable": _ref("executable"),
            "runner_identity": _ref("identifier"),
            "operating_system": _ref("platform"),
            "architecture": _ref("architecture"),
            "required_privileges": _array(
                _ref("privilege"),
                maximum=len(Privilege),
                unique=True,
            ),
            "frames": _array(
                _ref("frame_descriptor"),
                maximum=MAX_FRAME_COUNT,
                unique=True,
                unique_by="index",
            ),
            "timeout_seconds": _integer(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS),
            "stdout_cap_bytes": _integer(MIN_OUTPUT_CAP_BYTES, MAX_OUTPUT_CAP_BYTES),
            "stderr_cap_bytes": _integer(MIN_OUTPUT_CAP_BYTES, MAX_OUTPUT_CAP_BYTES),
        },
        required=(
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
        ),
        definitions=definitions,
        annotations={
            "x-hackbot-max-header-bytes": MAX_PROTOCOL_HEADER_BYTES,
            "x-hackbot-max-frame-count": MAX_FRAME_COUNT,
            "x-hackbot-max-frame-bytes": MAX_FRAME_BYTES,
            "x-hackbot-max-request-bytes": MAX_REQUEST_BYTES,
            "x-hackbot-max-response-bytes": MAX_RESPONSE_BYTES,
            "x-hackbot-min-request-lifetime-seconds": MIN_REQUEST_LIFETIME_SECONDS,
            "x-hackbot-max-request-lifetime-seconds": MAX_REQUEST_LIFETIME_SECONDS,
            "x-hackbot-max-clock-skew-seconds": MAX_CLOCK_SKEW_SECONDS,
            "x-hackbot-replay-reservation-seconds": REPLAY_RESERVATION_SECONDS,
            "x-hackbot-ed25519-public-key-bytes": ED25519_PUBLIC_KEY_BYTES,
            "x-hackbot-ed25519-signature-bytes": ED25519_SIGNATURE_BYTES,
            "x-hackbot-nonce-bytes": NONCE_BYTES,
            "x-hackbot-max-egress-observation-age-seconds": (MAX_EGRESS_OBSERVATION_AGE_SECONDS),
        },
    )


def schema_documents() -> dict[str, dict[str, object]]:
    """Return fresh, closed Draft 2020-12 schema documents keyed by filename."""

    return {
        "program.schema.json": _program_schema(),
        "scope.schema.json": _scope_schema(),
        "authorization.schema.json": _authorization_schema(),
        "actions.schema.json": _actions_schema(),
        "action-request.schema.json": _action_request_schema(),
        "runner.schema.json": _runner_schema(),
        "remote-header.schema.json": _remote_header_schema(),
    }


def _render_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def render_schema_files() -> dict[str, bytes]:
    """Render schema files and their hash manifest with deterministic bytes."""

    documents = schema_documents()
    rendered = {name: _render_json(document) for name, document in sorted(documents.items())}
    manifest: dict[str, object] = {
        "contract": _CONTRACT,
        "files": [
            {
                "name": name,
                "schema_id": documents[name]["$id"],
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in rendered.items()
        ],
    }
    canonical_bytes(manifest)
    rendered["manifest.json"] = _render_json(manifest)
    return rendered
