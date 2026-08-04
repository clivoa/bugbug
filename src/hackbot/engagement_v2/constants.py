"""Immutable exact values for the engagement v2 security contracts."""

from __future__ import annotations

import re
from enum import Enum, IntEnum
from types import MappingProxyType

# Artifact versions and canonical encodings.
PROGRAM_SCHEMA_VERSION = 2
SCOPE_SCHEMA_VERSION = 2
AUTHORIZATION_SCHEMA_VERSION = 2
ACTIONS_SCHEMA_VERSION = 1
ACTION_REQUEST_SCHEMA_VERSION = 2
RUNNER_SCHEMA_VERSION = 2
AUTHORITY_PROJECTION_VERSION = 1
EXECUTION_PROJECTION_VERSION = 1
CANONICAL_JSON_FORMAT = "hackbot-canonical-json-v1"
AUTHORITY_PROJECTION_FORMAT = "hackbot-authority-v1"
EXECUTION_PROJECTION_FORMAT = "hackbot-execution-v1"

# Workflow (P6) schema version and the domain tag under which a validated
# workflow manifest joins the confirmed-authority digest. The tag is separate
# from the authority/execution projection domains so a workflow digest can never
# be confused with a bare authority digest.
WORKFLOW_SCHEMA_VERSION = 2
WORKFLOW_PROJECTION_FORMAT = "hackbot-workflow-authority-v1"

# Authority document limits.
MAX_PROGRAM_DOCUMENT_BYTES = 1_048_576
MAX_SCOPE_DOCUMENT_BYTES = 1_048_576
MAX_AUTHORIZATION_DOCUMENT_BYTES = 1_048_576
MAX_RUNNER_DOCUMENT_BYTES = 1_048_576
MAX_ACTION_MANIFEST_BYTES = 4_194_304
MAX_DOCUMENT_NESTING_DEPTH = 32

# Policy limits.
MIN_REQUESTS_PER_SECOND = 1
MAX_REQUESTS_PER_SECOND = 1_000
MIN_RUNNER_CONCURRENCY = 1
MAX_RUNNER_CONCURRENCY = 100
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 86_400
MIN_OUTPUT_CAP_BYTES = 4_096
MAX_OUTPUT_CAP_BYTES = 16_777_216
MIN_TARGETS_PER_ACTION = 1
MAX_TARGETS_PER_ACTION = 65_536

POLICY_BOOLEAN_FIELDS = frozenset(
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

# Strict identifiers and digests. Only contract identifier/digest syntax is
# compiled here; the safe user-supplied pattern language belongs to Task 3.
BINDING_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}", re.ASCII)
MAPPING_KEY_PATTERN = BINDING_NAME_PATTERN
IDENTIFIER_PATTERN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", re.ASCII)
SECRET_REFERENCE_PATTERN = re.compile(r"secret:[a-z0-9]+(?:[._-][a-z0-9]+)*", re.ASCII)
AUTHORITY_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
RUN_ID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.ASCII,
)
SHA256_PREFIX = "sha256:"
SHA256_HEX_LENGTH = 64
SHA256_RAW_BYTES = 32
OPERATOR_ACTION_ID_PREFIX = "operator."
SECRET_REFERENCE_PREFIX = "secret:"


class Profile(str, Enum):
    BUG_BOUNTY = "bug-bounty"
    LOCAL_LAB = "local-lab"
    PRIVATE_PENTEST = "private-pentest"


class ParameterType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    ENUM = "enum"
    PORT = "port"
    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    NETWORK_ENDPOINT = "network-endpoint"
    REPOSITORY = "repository"
    CONTRACT = "contract"
    TARGET_LIST = "target-list"
    ARTIFACT_REF = "artifact-ref"


class PlaceholderKind(str, Enum):
    VALUE = "value"
    TARGET = "target"
    TARGETS_FILE = "targets_file"
    ARTIFACT_FILE = "artifact_file"
    SECRET_FILE = "secret_file"


# Workflow (P6) manifest limits.
MAX_WORKFLOW_DOCUMENT_BYTES = 1_048_576
MAX_WORKFLOW_STEPS = 64
MAX_STEP_INPUTS = 64
MAX_STEP_OUTPUTS = 64
MAX_STEP_TARGET_VALUES = 256
MIN_STEP_RETRIES = 0
MAX_STEP_RETRIES = 8

# Action and prepared-input limits.
MAX_ACTIONS = 256
MAX_ACTION_PARAMETERS = 128
MAX_ACTION_SECRETS = 32
MAX_TARGET_BINDINGS = 32
MAX_ACTION_CAPABILITIES = 64
MAX_ACTION_VULNERABILITY_TYPES = 64
MAX_ACTION_IMPACTS = 64
MAX_ARGV_TOKENS = 128
MAX_IDENTIFIER_BYTES = 128
MAX_BINDING_NAME_BYTES = 64
MAX_SCALAR_OR_TARGET_BYTES = 2_048
MIN_UTF8_STRING_BYTES = 1
MAX_UTF8_STRING_BYTES = 8_192
MIN_ENUM_VALUES = 1
MAX_ENUM_VALUES = 256
MIN_SIGNED_INT64 = -(2**63)
MAX_SIGNED_INT64 = 2**63 - 1
MIN_PORT = 1
MAX_PORT = 65_535
MAX_TARGET_LIST_LENGTH = 65_536
MAX_SECRET_BYTES = 1_048_576
MAX_SECRETS_BYTES = 4_194_304
MAX_PREPARED_INPUT_BYTES = 67_108_864
SAFE_FULLMATCH_FORMAT = "hackbot-safe-fullmatch-v1"
MAX_SAFE_PATTERN_BYTES = 256
MIN_SAFE_PATTERN_CLASS_LITERALS = 1
MAX_SAFE_PATTERN_CLASS_LITERALS = 64
MIN_SAFE_PATTERN_QUANTIFIER = 0
MAX_SAFE_PATTERN_QUANTIFIER = 1_024
MIN_ARGV_TOKEN_BYTES = 1
MAX_ARGV_TOKEN_BYTES = 4_096
MAX_ARGV_BYTES = 65_536
ARGV_TOKEN_TERMINATOR_BYTES = 1


class Platform(str, Enum):
    LINUX = "linux"
    DARWIN = "darwin"
    WINDOWS = "windows"


class Architecture(str, Enum):
    X86_64 = "x86_64"
    ARM64 = "arm64"


class Privilege(str, Enum):
    NETWORK_RAW = "network-raw"
    NETWORK_ADMIN = "network-admin"
    PACKET_CAPTURE = "packet-capture"
    FILESYSTEM_PROTECTED_READ = "filesystem-protected-read"
    SUPERUSER = "superuser"


class RiskLevel(str, Enum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class EvidenceMode(str, Enum):
    METADATA_ONLY = "metadata-only"
    REDACTED_OUTPUT = "redacted-output"
    STRUCTURED = "structured"


class RateControlMode(str, Enum):
    ARGV_PLACEHOLDER = "argv-placeholder"
    NATIVE_ADAPTER = "native-adapter"
    NOT_APPLICABLE = "not-applicable"


class SecretTransport(str, Enum):
    STDIN = "stdin"
    FILE = "file"


POSIX_SHELL_BASENAMES = frozenset(
    {
        "sh",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "fish",
    }
)
CMD_BASENAMES = frozenset(
    {
        "cmd",
        "cmd.exe",
    }
)
POWERSHELL_BASENAMES = frozenset(
    {
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
    }
)
SHELL_BASENAMES = POSIX_SHELL_BASENAMES | CMD_BASENAMES | POWERSHELL_BASENAMES
PYTHON_BASENAMES = frozenset({"python", "python3", "python.exe"})
PERL_RUBY_PHP_BASENAMES = frozenset(
    {
        "perl",
        "perl.exe",
        "ruby",
        "ruby.exe",
        "php",
        "php.exe",
    }
)
NODE_BASENAMES = frozenset(
    {
        "node",
        "node.exe",
    }
)
INTERPRETER_BASENAMES = (
    SHELL_BASENAMES | PYTHON_BASENAMES | PERL_RUBY_PHP_BASENAMES | NODE_BASENAMES
)
ELEVATION_BASENAMES = frozenset({"sudo", "su", "doas", "pkexec", "runas", "runas.exe"})
INLINE_MODE_FLAGS = MappingProxyType(
    {
        "posix-shell": frozenset({"-c", "--command"}),
        "python": frozenset({"-c"}),
        "perl-ruby-php": frozenset({"-e", "-r"}),
        "node": frozenset({"-e", "--eval", "-p", "--print"}),
        "powershell": frozenset({"-command", "-c", "-encodedcommand", "-enc"}),
        "cmd": frozenset({"/c", "/k"}),
    }
)
INLINE_MODE_FLAGS_BY_BASENAME = MappingProxyType(
    {
        **{basename: INLINE_MODE_FLAGS["posix-shell"] for basename in POSIX_SHELL_BASENAMES},
        **{basename: INLINE_MODE_FLAGS["cmd"] for basename in CMD_BASENAMES},
        **{basename: INLINE_MODE_FLAGS["powershell"] for basename in POWERSHELL_BASENAMES},
        **{basename: INLINE_MODE_FLAGS["python"] for basename in PYTHON_BASENAMES},
        **{basename: INLINE_MODE_FLAGS["perl-ruby-php"] for basename in PERL_RUBY_PHP_BASENAMES},
        **{basename: INLINE_MODE_FLAGS["node"] for basename in NODE_BASENAMES},
    }
)


# Evidence and cleanup limits.
class RetainedOutputType(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"


MIN_RETAINED_OUTPUT_ITEM_COUNT = 1
MAX_RETAINED_OUTPUT_ITEM_COUNT = 64
MIN_RETAINED_OUTPUT_ITEM_BYTES = 1
MAX_RETAINED_OUTPUT_ITEM_BYTES = 33_554_432
MAX_RETAINED_OUTPUT_BYTES = 67_108_864
PROHIBITED_OUTPUT_PATH_SEGMENTS = frozenset({"", ".", ".."})


class LifecycleState(str, Enum):
    RECEIVED = "received"
    VALIDATED = "validated"
    ALLOWED = "allowed"
    PREPARED = "prepared"
    SPAWNED = "spawned"
    INTERACTION_ATTEMPTED = "interaction-attempted"
    CHILD_FINISHED = "child-finished"
    EVIDENCE_FINALIZED = "evidence-finalized"
    RESOURCE_CLEANUP = "resource-cleanup"
    TARGET_CLEANUP = "target-cleanup"
    FINALIZED = "finalized"


class ResourceCleanupState(str, Enum):
    NOT_REQUIRED = "not-required"
    COMPLETE = "complete"
    FAILED = "failed"


class TargetCleanupState(str, Enum):
    NOT_REQUIRED = "not-required"
    COMPLETE = "complete"
    DEFERRED = "deferred"
    FAILED = "failed"
    UNVERIFIED_SELF_REPORT = "unverified-self-report"


# Remote runner wire protocol.
PROTOCOL_MAGIC = b"HBV2RUN\x00"
PROTOCOL_VERSION = 1
L3_PROTOCOL_VERSION = 2
MAX_PROTOCOL_HEADER_BYTES = 1_048_576
MAX_FRAME_COUNT = 256
MAX_FRAME_BYTES = 67_108_864
MAX_REQUEST_BYTES = 75_497_472
MAX_RESPONSE_BYTES = 41_943_040


class FrameType(IntEnum):
    TARGET_LIST = 1
    ARTIFACT = 2
    SECRET = 3
    STDOUT = 4
    STDERR = 5
    STRUCTURED_RESULT = 6
    CLEANUP_RECEIPT = 7
    EXECUTION_PERMIT = 8


FRAME_TYPE_NAMES = MappingProxyType(
    {
        FrameType.TARGET_LIST: "target-list",
        FrameType.ARTIFACT: "artifact",
        FrameType.SECRET: "secret",
        FrameType.STDOUT: "stdout",
        FrameType.STDERR: "stderr",
        FrameType.STRUCTURED_RESULT: "structured-result",
        FrameType.CLEANUP_RECEIPT: "cleanup-receipt",
        FrameType.EXECUTION_PERMIT: "execution-permit",
    }
)
REQUEST_FRAME_TYPES = frozenset(
    {
        FrameType.TARGET_LIST,
        FrameType.ARTIFACT,
        FrameType.SECRET,
    }
)
L3_REQUEST_FRAME_TYPES = REQUEST_FRAME_TYPES | {FrameType.EXECUTION_PERMIT}
RESPONSE_FRAME_TYPES = frozenset(
    {
        FrameType.STDOUT,
        FrameType.STDERR,
        FrameType.STRUCTURED_RESULT,
        FrameType.CLEANUP_RECEIPT,
    }
)
FRAME_TYPE_BY_DIRECTION = MappingProxyType(
    {"request": REQUEST_FRAME_TYPES, "response": RESPONSE_FRAME_TYPES}
)
NONCE_BYTES = 32
NONCE_BASE64URL_LENGTH = 43
MIN_REQUEST_LIFETIME_SECONDS = 1
MAX_REQUEST_LIFETIME_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 30
REPLAY_RESERVATION_SECONDS = 600
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64


class RunnerRole(str, Enum):
    EXECUTION_NODE = "execution-node"
    IN_SCOPE_TARGET = "in-scope-target"


class SourceIdentityMode(str, Enum):
    NONE = "none"
    DIRECT_INTERFACE = "direct-interface"
    ATTESTED_EGRESS = "attested-egress"


MAX_EGRESS_OBSERVATION_AGE_SECONDS = 60
HELPER_RUN_DIRECTORY_MODE = 0o700
HELPER_FILE_MODE = 0o600

# P1 consumes this exact registry when constructing the confirmed runner
# security view. P0 freezes only the projection contract and golden vector.
RUNNER_SECURITY_PROJECTION_FIELDS = (
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
RUNNER_SECURITY_PROJECTION_EXCLUDED_FIELDS = (
    "ssh.private_key_path",
    "ssh.connection_timeout_seconds",
)
