from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

import hackbot.engagement_v2 as engagement_v2
import hackbot.engagement_v2.constants as contract
from hackbot.engagement_v2.constants import (
    ACTION_REQUEST_SCHEMA_VERSION,
    ACTIONS_SCHEMA_VERSION,
    AUTHORITY_DIGEST_PATTERN,
    AUTHORITY_PROJECTION_VERSION,
    AUTHORIZATION_SCHEMA_VERSION,
    CANONICAL_JSON_FORMAT,
    ELEVATION_BASENAMES,
    EXECUTION_PROJECTION_VERSION,
    FRAME_TYPE_BY_DIRECTION,
    HELPER_FILE_MODE,
    HELPER_RUN_DIRECTORY_MODE,
    IDENTIFIER_PATTERN,
    INLINE_MODE_FLAGS,
    INTERPRETER_BASENAMES,
    MAX_ACTION_CAPABILITIES,
    MAX_ACTION_IMPACTS,
    MAX_ACTION_MANIFEST_BYTES,
    MAX_ACTION_PARAMETERS,
    MAX_ACTION_SECRETS,
    MAX_ACTION_VULNERABILITY_TYPES,
    MAX_ACTIONS,
    MAX_ARGV_BYTES,
    MAX_ARGV_TOKENS,
    MAX_AUTHORIZATION_DOCUMENT_BYTES,
    MAX_DOCUMENT_NESTING_DEPTH,
    MAX_ENUM_VALUES,
    MAX_FRAME_BYTES,
    MAX_FRAME_COUNT,
    MAX_OUTPUT_CAP_BYTES,
    MAX_PREPARED_INPUT_BYTES,
    MAX_PROGRAM_DOCUMENT_BYTES,
    MAX_REQUEST_BYTES,
    MAX_REQUESTS_PER_SECOND,
    MAX_RESPONSE_BYTES,
    MAX_RUNNER_CONCURRENCY,
    MAX_RUNNER_DOCUMENT_BYTES,
    MAX_SAFE_PATTERN_BYTES,
    MAX_SAFE_PATTERN_CLASS_LITERALS,
    MAX_SAFE_PATTERN_QUANTIFIER,
    MAX_SCALAR_OR_TARGET_BYTES,
    MAX_SECRET_BYTES,
    MAX_SECRETS_BYTES,
    MAX_TARGET_BINDINGS,
    MAX_TARGET_LIST_LENGTH,
    MAX_TARGETS_PER_ACTION,
    MAX_TIMEOUT_SECONDS,
    MAX_UTF8_STRING_BYTES,
    MIN_ENUM_VALUES,
    MIN_OUTPUT_CAP_BYTES,
    MIN_REQUESTS_PER_SECOND,
    MIN_RUNNER_CONCURRENCY,
    MIN_SAFE_PATTERN_CLASS_LITERALS,
    MIN_SAFE_PATTERN_QUANTIFIER,
    MIN_TARGETS_PER_ACTION,
    MIN_TIMEOUT_SECONDS,
    MIN_UTF8_STRING_BYTES,
    PROGRAM_SCHEMA_VERSION,
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    RUNNER_SCHEMA_VERSION,
    SCOPE_SCHEMA_VERSION,
    SHELL_BASENAMES,
    Architecture,
    EvidenceMode,
    FrameType,
    LifecycleState,
    ParameterType,
    Platform,
    Privilege,
    Profile,
    RateControlMode,
    ResourceCleanupState,
    RiskLevel,
    RunnerRole,
    SecretTransport,
    SourceIdentityMode,
    TargetCleanupState,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode


def test_package_exports_only_stable_failure_types() -> None:
    assert engagement_v2.__all__ == ["ContractError", "ReasonCode"]
    assert engagement_v2.ContractError is ContractError
    assert engagement_v2.ReasonCode is ReasonCode


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


def test_contract_error_is_immutable_and_ignores_arbitrary_metadata() -> None:
    error = ContractError(ReasonCode.INVALID_LIMIT)

    with pytest.raises(AttributeError, match="immutable"):
        error.reason_code = ReasonCode.INVALID_REQUEST  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        error.message = "attacker-controlled"  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        error.metadata = {"secret": "attacker-controlled"}  # type: ignore[attr-defined]
    with pytest.raises(AttributeError, match="immutable"):
        error.args = (ReasonCode.INVALID_REQUEST,)

    error.__dict__["reason_code"] = ReasonCode.INVALID_REQUEST
    error.__dict__["message"] = "attacker-controlled"
    error.__dict__["metadata"] = {"secret": "attacker-controlled"}
    assert error.as_dict() == {
        "reason_code": "INVALID_LIMIT",
        "message": "invalid limit",
    }


def test_contract_error_allows_direct_traceback_assignment() -> None:
    error = ContractError(ReasonCode.INVALID_LIMIT)

    error.__traceback__ = None

    assert error.__traceback__ is None
    assert error.as_dict() == {
        "reason_code": "INVALID_LIMIT",
        "message": "invalid limit",
    }


def test_contract_error_allows_standard_exception_bookkeeping() -> None:
    error = ContractError(ReasonCode.INVALID_LIMIT)
    cause = RuntimeError("private cause")
    context = RuntimeError("private context")

    error.__cause__ = cause
    error.__context__ = context
    error.__suppress_context__ = True

    assert error.__cause__ is cause
    assert error.__context__ is context
    assert error.__suppress_context__ is True
    for attribute in ("__traceback__", "__cause__", "__context__", "__suppress_context__"):
        with pytest.raises(TypeError):
            delattr(error, attribute)
    assert error.as_dict() == {
        "reason_code": "INVALID_LIMIT",
        "message": "invalid limit",
    }


def test_generator_contextmanager_propagates_same_contract_error() -> None:
    @contextmanager
    def passthrough() -> Iterator[None]:
        yield

    original = ContractError(ReasonCode.INVALID_REQUEST)

    with pytest.raises(ContractError) as raised:
        with passthrough():
            raise original

    assert raised.value is original
    assert raised.value.reason_code is ReasonCode.INVALID_REQUEST


def test_normal_raise_and_bare_reraise_preserve_contract_error() -> None:
    original = ContractError(ReasonCode.INVALID_RUNNER)

    with pytest.raises(ContractError) as reraised:
        try:
            raise original
        except ContractError as caught:
            assert caught is original
            assert caught.reason_code is ReasonCode.INVALID_RUNNER
            raise

    assert reraised.value is original
    assert reraised.value.reason_code is ReasonCode.INVALID_RUNNER


def test_projection_format_identifiers_are_exact() -> None:
    assert contract.AUTHORITY_PROJECTION_FORMAT == "hackbot-authority-v1"
    assert contract.EXECUTION_PROJECTION_FORMAT == "hackbot-execution-v1"


def test_safe_fullmatch_format_identifier_is_exact() -> None:
    assert contract.SAFE_FULLMATCH_FORMAT == "hackbot-safe-fullmatch-v1"


def test_every_schema_version_and_document_limit_is_closed() -> None:
    assert (
        PROGRAM_SCHEMA_VERSION,
        SCOPE_SCHEMA_VERSION,
        AUTHORIZATION_SCHEMA_VERSION,
        ACTIONS_SCHEMA_VERSION,
        ACTION_REQUEST_SCHEMA_VERSION,
        RUNNER_SCHEMA_VERSION,
        AUTHORITY_PROJECTION_VERSION,
        EXECUTION_PROJECTION_VERSION,
    ) == (2, 2, 2, 1, 2, 2, 1, 1)
    assert (
        MAX_PROGRAM_DOCUMENT_BYTES,
        contract.MAX_SCOPE_DOCUMENT_BYTES,
        MAX_AUTHORIZATION_DOCUMENT_BYTES,
        MAX_RUNNER_DOCUMENT_BYTES,
        MAX_ACTION_MANIFEST_BYTES,
        MAX_DOCUMENT_NESTING_DEPTH,
    ) == (1_048_576, 1_048_576, 1_048_576, 1_048_576, 4_194_304, 32)


def test_profiles_parameter_types_and_execution_enums_are_closed() -> None:
    assert {item.value for item in Profile} == {
        "bug-bounty",
        "local-lab",
        "private-pentest",
    }
    assert {item.value for item in ParameterType} == {
        "string",
        "integer",
        "boolean",
        "enum",
        "port",
        "domain",
        "host",
        "ip",
        "cidr",
        "url",
        "network-endpoint",
        "repository",
        "contract",
        "target-list",
        "artifact-ref",
    }
    assert {item.value for item in RiskLevel} == {"L0", "L1", "L2", "L3"}
    assert {item.value for item in SecretTransport} == {"stdin", "file"}
    assert {item.value for item in contract.PlaceholderKind} == {
        "value",
        "target",
        "targets_file",
        "artifact_file",
        "secret_file",
    }
    assert {item.value for item in SourceIdentityMode} == {
        "none",
        "direct-interface",
        "attested-egress",
    }


def test_runner_roles_are_closed() -> None:
    assert {item.value for item in RunnerRole} == {"execution-node", "in-scope-target"}
    with pytest.raises(ValueError):
        RunnerRole("operator-controlled")


def test_all_action_and_input_bounds_are_closed() -> None:
    assert (
        MAX_ACTION_PARAMETERS,
        MAX_ACTION_SECRETS,
        MAX_TARGET_BINDINGS,
        MAX_ACTION_CAPABILITIES,
        MAX_ACTION_VULNERABILITY_TYPES,
        MAX_ACTION_IMPACTS,
        MAX_SCALAR_OR_TARGET_BYTES,
        MIN_UTF8_STRING_BYTES,
        MAX_UTF8_STRING_BYTES,
        MIN_ENUM_VALUES,
        MAX_ENUM_VALUES,
        MAX_TARGET_LIST_LENGTH,
        MAX_SECRET_BYTES,
        MAX_SECRETS_BYTES,
        MAX_PREPARED_INPUT_BYTES,
    ) == (
        128,
        32,
        32,
        64,
        64,
        64,
        2_048,
        1,
        8_192,
        1,
        256,
        65_536,
        1_048_576,
        4_194_304,
        67_108_864,
    )
    assert (
        contract.MAX_IDENTIFIER_BYTES,
        contract.MIN_SIGNED_INT64,
        contract.MAX_SIGNED_INT64,
        contract.MIN_PORT,
        contract.MAX_PORT,
        contract.MIN_ARGV_TOKEN_BYTES,
        contract.MAX_ARGV_TOKEN_BYTES,
        contract.ARGV_TOKEN_TERMINATOR_BYTES,
    ) == (128, -9_223_372_036_854_775_808, 9_223_372_036_854_775_807, 1, 65_535, 1, 4_096, 1)


def test_policy_and_pattern_bounds_are_closed() -> None:
    assert (
        MIN_REQUESTS_PER_SECOND,
        MAX_REQUESTS_PER_SECOND,
        MIN_RUNNER_CONCURRENCY,
        MAX_RUNNER_CONCURRENCY,
        MIN_TIMEOUT_SECONDS,
        MAX_TIMEOUT_SECONDS,
        MIN_OUTPUT_CAP_BYTES,
        MAX_OUTPUT_CAP_BYTES,
        MIN_TARGETS_PER_ACTION,
        MAX_TARGETS_PER_ACTION,
    ) == (1, 1_000, 1, 100, 1, 86_400, 4_096, 16_777_216, 1, 65_536)
    assert (
        MAX_SAFE_PATTERN_BYTES,
        MIN_SAFE_PATTERN_CLASS_LITERALS,
        MAX_SAFE_PATTERN_CLASS_LITERALS,
        MIN_SAFE_PATTERN_QUANTIFIER,
        MAX_SAFE_PATTERN_QUANTIFIER,
    ) == (256, 1, 64, 0, 1_024)


def test_sensitive_policy_field_registry_is_closed_and_immutable() -> None:
    assert contract.POLICY_BOOLEAN_FIELDS == frozenset(
        {
            "automated_scanning_allowed",
            "authenticated_testing_allowed",
            "exploit_execution_allowed",
            "payload_execution_allowed",
            "credential_access_allowed",
            "credential_capture_allowed",
            "state_changing_allowed",
            "privileged_execution_allowed",
            "lateral_movement_allowed",
            "persistence_allowed",
            "sensitive_data_access_allowed",
            "data_exfiltration_allowed",
            "account_creation_allowed",
            "multiple_accounts_allowed",
            "out_of_band_testing_allowed",
            "autonomous_progression_allowed",
            "operator_output_persistence_allowed",
            "social_engineering_allowed",
            "denial_of_service_allowed",
            "destructive_testing_allowed",
        }
    )
    with pytest.raises(AttributeError):
        contract.POLICY_BOOLEAN_FIELDS.add("unregistered_field")


def test_shell_interpreter_elevation_and_inline_mode_registries_are_immutable() -> None:
    assert SHELL_BASENAMES == frozenset(
        {
            "sh",
            "bash",
            "dash",
            "zsh",
            "ksh",
            "csh",
            "tcsh",
            "fish",
            "cmd",
            "cmd.exe",
            "powershell",
            "powershell.exe",
            "pwsh",
            "pwsh.exe",
        }
    )
    assert INTERPRETER_BASENAMES == SHELL_BASENAMES | frozenset(
        {
            "python",
            "python3",
            "python.exe",
            "perl",
            "perl.exe",
            "ruby",
            "ruby.exe",
            "php",
            "php.exe",
            "node",
            "node.exe",
        }
    )
    assert ELEVATION_BASENAMES == frozenset({"sudo", "su", "doas", "pkexec", "runas", "runas.exe"})
    assert INLINE_MODE_FLAGS == {
        "posix-shell": frozenset({"-c", "--command"}),
        "python": frozenset({"-c"}),
        "perl-ruby-php": frozenset({"-e", "-r"}),
        "node": frozenset({"-e", "--eval", "-p", "--print"}),
        "powershell": frozenset({"-command", "-c", "-encodedcommand", "-enc"}),
        "cmd": frozenset({"/c", "/k"}),
    }
    assert contract.INLINE_MODE_FLAGS_BY_BASENAME == {
        "sh": frozenset({"-c", "--command"}),
        "bash": frozenset({"-c", "--command"}),
        "dash": frozenset({"-c", "--command"}),
        "zsh": frozenset({"-c", "--command"}),
        "ksh": frozenset({"-c", "--command"}),
        "csh": frozenset({"-c", "--command"}),
        "tcsh": frozenset({"-c", "--command"}),
        "fish": frozenset({"-c", "--command"}),
        "cmd": frozenset({"/c", "/k"}),
        "cmd.exe": frozenset({"/c", "/k"}),
        "powershell": frozenset({"-command", "-c", "-encodedcommand", "-enc"}),
        "powershell.exe": frozenset({"-command", "-c", "-encodedcommand", "-enc"}),
        "pwsh": frozenset({"-command", "-c", "-encodedcommand", "-enc"}),
        "pwsh.exe": frozenset({"-command", "-c", "-encodedcommand", "-enc"}),
        "python": frozenset({"-c"}),
        "python3": frozenset({"-c"}),
        "python.exe": frozenset({"-c"}),
        "perl": frozenset({"-e", "-r"}),
        "perl.exe": frozenset({"-e", "-r"}),
        "ruby": frozenset({"-e", "-r"}),
        "ruby.exe": frozenset({"-e", "-r"}),
        "php": frozenset({"-e", "-r"}),
        "php.exe": frozenset({"-e", "-r"}),
        "node": frozenset({"-e", "--eval", "-p", "--print"}),
        "node.exe": frozenset({"-e", "--eval", "-p", "--print"}),
    }
    with pytest.raises(AttributeError):
        SHELL_BASENAMES.add("new-shell")
    with pytest.raises(TypeError):
        INLINE_MODE_FLAGS["node"] = frozenset()
    with pytest.raises(TypeError):
        contract.INLINE_MODE_FLAGS_BY_BASENAME["node"] = frozenset()


def test_lifecycle_cleanup_and_frame_type_registries_are_closed() -> None:
    assert [item.value for item in LifecycleState] == [
        "received",
        "validated",
        "allowed",
        "prepared",
        "spawned",
        "interaction-attempted",
        "child-finished",
        "evidence-finalized",
        "resource-cleanup",
        "target-cleanup",
        "finalized",
    ]
    assert {item.value for item in ResourceCleanupState} == {
        "not-required",
        "complete",
        "failed",
    }
    assert {item.value for item in TargetCleanupState} == {
        "not-required",
        "complete",
        "deferred",
        "failed",
        "unverified-self-report",
    }
    assert {item.value for item in FrameType} == set(range(1, 8))
    assert FRAME_TYPE_BY_DIRECTION == {
        "request": frozenset({FrameType.TARGET_LIST, FrameType.ARTIFACT, FrameType.SECRET}),
        "response": frozenset(
            {
                FrameType.STDOUT,
                FrameType.STDERR,
                FrameType.STRUCTURED_RESULT,
                FrameType.CLEANUP_RECEIPT,
            }
        ),
    }
    assert contract.FRAME_TYPE_NAMES == {
        FrameType.TARGET_LIST: "target-list",
        FrameType.ARTIFACT: "artifact",
        FrameType.SECRET: "secret",
        FrameType.STDOUT: "stdout",
        FrameType.STDERR: "stderr",
        FrameType.STRUCTURED_RESULT: "structured-result",
        FrameType.CLEANUP_RECEIPT: "cleanup-receipt",
    }
    with pytest.raises(TypeError):
        FRAME_TYPE_BY_DIRECTION["request"] = frozenset()
    with pytest.raises(TypeError):
        contract.FRAME_TYPE_NAMES[FrameType.SECRET] = "wrong"


def test_remote_protocol_magic_sizes_and_private_storage_modes_are_exact() -> None:
    assert PROTOCOL_MAGIC == b"HBV2RUN\x00"
    assert PROTOCOL_VERSION == 1
    assert (MAX_FRAME_COUNT, MAX_RESPONSE_BYTES) == (256, 41_943_040)
    assert HELPER_RUN_DIRECTORY_MODE == 0o700
    assert HELPER_FILE_MODE == 0o600
    assert (
        contract.MAX_PROTOCOL_HEADER_BYTES,
        contract.NONCE_BYTES,
        contract.NONCE_BASE64URL_LENGTH,
        contract.MIN_REQUEST_LIFETIME_SECONDS,
        contract.MAX_REQUEST_LIFETIME_SECONDS,
        contract.MAX_CLOCK_SKEW_SECONDS,
        contract.REPLAY_RESERVATION_SECONDS,
        contract.ED25519_PUBLIC_KEY_BYTES,
        contract.ED25519_SIGNATURE_BYTES,
        contract.MAX_EGRESS_OBSERVATION_AGE_SECONDS,
    ) == (1_048_576, 32, 43, 1, 300, 30, 600, 32, 64, 60)


def test_evidence_limits_and_prohibited_path_segments_are_closed() -> None:
    assert {item.value for item in contract.RetainedOutputType} == {"file", "directory"}
    assert (
        contract.MIN_RETAINED_OUTPUT_ITEM_COUNT,
        contract.MAX_RETAINED_OUTPUT_ITEM_COUNT,
        contract.MIN_RETAINED_OUTPUT_ITEM_BYTES,
        contract.MAX_RETAINED_OUTPUT_ITEM_BYTES,
        contract.MAX_RETAINED_OUTPUT_BYTES,
    ) == (1, 64, 1, 33_554_432, 67_108_864)
    assert contract.PROHIBITED_OUTPUT_PATH_SEGMENTS == frozenset({"", ".", ".."})
    with pytest.raises(AttributeError):
        contract.PROHIBITED_OUTPUT_PATH_SEGMENTS.add("unregistered")


def test_identifier_and_digest_patterns_accept_only_contract_syntax() -> None:
    assert IDENTIFIER_PATTERN.fullmatch("operator.probe-1")
    assert IDENTIFIER_PATTERN.fullmatch("operator._probe") is None
    assert contract.BINDING_NAME_PATTERN.fullmatch("target_name_1")
    assert contract.BINDING_NAME_PATTERN.fullmatch("1-target") is None
    assert contract.BINDING_NAME_PATTERN.fullmatch("target-name") is None
    assert contract.BINDING_NAME_PATTERN.fullmatch("target.name") is None
    assert contract.MAX_BINDING_NAME_BYTES == 64
    assert contract.MAPPING_KEY_PATTERN.fullmatch("policy_limit_1")
    assert contract.MAPPING_KEY_PATTERN.fullmatch("policy-limit") is None
    assert contract.SECRET_REFERENCE_PATTERN.fullmatch("secret:operator.token-1")
    assert contract.SECRET_REFERENCE_PATTERN.fullmatch("secret:Operator") is None
    assert contract.RUN_ID_PATTERN.fullmatch("123e4567-e89b-42d3-a456-426614174000")
    assert contract.RUN_ID_PATTERN.fullmatch("123e4567-e89b-12d3-a456-426614174000") is None
    assert AUTHORITY_DIGEST_PATTERN.fullmatch("sha256:" + "0" * 64)
    assert AUTHORITY_DIGEST_PATTERN.fullmatch("SHA256:" + "0" * 64) is None
    assert all(
        pattern.flags & re.ASCII
        for pattern in (
            contract.BINDING_NAME_PATTERN,
            contract.MAPPING_KEY_PATTERN,
            IDENTIFIER_PATTERN,
            contract.SECRET_REFERENCE_PATTERN,
            AUTHORITY_DIGEST_PATTERN,
            contract.RUN_ID_PATTERN,
        )
    )
    assert (contract.SHA256_PREFIX, contract.SHA256_HEX_LENGTH, contract.SHA256_RAW_BYTES) == (
        "sha256:",
        64,
        32,
    )
    assert (contract.OPERATOR_ACTION_ID_PREFIX, contract.SECRET_REFERENCE_PREFIX) == (
        "operator.",
        "secret:",
    )
    assert CANONICAL_JSON_FORMAT == "hackbot-canonical-json-v1"


def test_runner_security_projection_field_registry_is_exact_and_immutable() -> None:
    assert contract.RUNNER_SECURITY_PROJECTION_FIELDS == (
        "role",
        "node_identity",
        "ssh.host",
        "ssh.port",
        "ssh.user",
        "ssh.identity",
        "ssh.known_hosts_path",
        "ssh.host_key_sha256",
        "ssh.options.batch_mode",
        "ssh.options.identities_only",
        "ssh.options.strict_host_key_checking",
        "ssh.options.agent_forwarding",
        "ssh.options.x11_forwarding",
        "ssh.options.port_forwarding",
        "ssh.options.tty",
        "helper.path",
        "helper.protocol_version",
        "helper.sha256",
        "helper.code_signing_identity",
        "operating_system",
        "architecture",
        "permitted_privileges",
        "source_identity.mode",
        "source_identity.address",
        "egress_attestation.adapter_path",
        "egress_attestation.adapter_sha256",
        "egress_attestation.signer_public_key_fingerprint",
        "egress_attestation.max_observation_age_seconds",
        "privilege_signer_public_key_fingerprint",
    )
    assert contract.RUNNER_SECURITY_PROJECTION_EXCLUDED_FIELDS == (
        "ssh.private_key_path",
        "ssh.connection_timeout_seconds",
    )
    with pytest.raises(AttributeError):
        contract.RUNNER_SECURITY_PROJECTION_FIELDS.append("runtime_result")  # type: ignore[attr-defined]


def test_spec_reason_tokens_belong_to_the_closed_registry() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    spec_root = repository_root / "openspec" / "specs"
    reason_token = re.compile(
        r"`((?:INVALID|DENY|EXEC|EVIDENCE|CLEANUP)_[A-Z0-9_]+)`",
        re.ASCII,
    )
    tokens = {
        match.group(1)
        for path in spec_root.glob("*/spec.md")
        for match in reason_token.finditer(path.read_text(encoding="utf-8"))
    }

    assert "INVALID_DOCUMENT_STRUCTURE" in tokens
    assert tokens <= {reason.value for reason in ReasonCode}


def test_reason_codes_are_closed_and_errors_reject_unregistered_values() -> None:
    assert {item.value for item in ReasonCode} == {
        "INVALID_SCHEMA_VERSION",
        "INVALID_DOCUMENT_SIZE",
        "INVALID_DOCUMENT_ENCODING",
        "INVALID_DOCUMENT_STRUCTURE",
        "INVALID_UNKNOWN_FIELD",
        "INVALID_DUPLICATE_KEY",
        "INVALID_IDENTIFIER",
        "INVALID_LIMIT",
        "INVALID_CANONICAL_VALUE",
        "INVALID_ACTION_MANIFEST",
        "INVALID_PLACEHOLDER",
        "INVALID_REQUEST",
        "INVALID_RUNNER",
        "DENY_AUTHORIZATION_UNCONFIRMED",
        "DENY_AUTHORIZATION_STALE",
        "DENY_CAPABILITY_NOT_ALLOWED",
        "DENY_POLICY_LIMIT",
        "DENY_RATE_UNENFORCEABLE",
        "EXEC_PROTOCOL_INVALID",
        "EXEC_PROTOCOL_EXPIRED",
        "EXEC_PROTOCOL_REPLAY",
        "EXEC_TRUST_MISMATCH",
        "EXEC_PRIVILEGE_MISMATCH",
        "EVIDENCE_POLICY_DENIED",
        "CLEANUP_RESOURCE_INCOMPLETE",
        "CLEANUP_TARGET_INCOMPLETE",
    }
    with pytest.raises(TypeError, match="exact ReasonCode"):
        ContractError("INVALID_LIMIT")  # type: ignore[arg-type]
