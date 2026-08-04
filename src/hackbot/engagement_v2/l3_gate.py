"""Validation-only P5b gate which runs before replay reservation and resources."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from hackbot.engagement_v2.constants import FrameType
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.l3_deployment import L3DeploymentContract
from hackbot.engagement_v2.protocol import (
    FramedMessage,
    RunBinding,
    SignedExecutionPermit,
    decode_execution_permit_frame,
)
from hackbot.engagement_v2.remote_permit import (
    ExecutionPermitContext,
    verify_execution_permit_v2,
)


def _invalid() -> ContractError:
    return ContractError(ReasonCode.EXEC_PROTOCOL_INVALID)


@dataclass(frozen=True, slots=True)
class L3VerificationContext:
    """Pinned verification material and exact expected v2 permit bindings."""

    permit_context: ExecutionPermitContext
    signer_public_key: bytes
    pinned_signer_fingerprint: str
    now: datetime
    deployment: L3DeploymentContract
    architecture: str
    timeout_seconds: int
    stdout_cap_bytes: int
    stderr_cap_bytes: int


@dataclass(frozen=True, slots=True)
class ValidatedL3Execution:
    """Sanitized fixed execution identity safe to pass past the authority gate."""

    action_id: str
    runner_identity: str
    executable_path: str
    executable_sha256: str
    operating_system: str
    architecture: str
    required_privileges: tuple[str, ...]
    timeout_seconds: int
    stdout_cap_bytes: int
    stderr_cap_bytes: int
    execution_digest: str


@dataclass(frozen=True, slots=True)
class ValidatedL3Request:
    """An inert token proving validation and reservation ordering inputs."""

    signed_permit: SignedExecutionPermit
    run_binding: RunBinding
    execution: ValidatedL3Execution


def _require_header_echo(header: Mapping[str, object], permit: Mapping[str, object]) -> None:
    exact_echoes = {
        "authority_digest": "authority_digest",
        "action_id": "action_id",
        "run_id": "run_id",
        "nonce": "nonce",
        "runner_identity": "runner_identity",
        "required_privileges": "required_privileges",
        "issued_at": "issued_at",
        "expires_at": "expires_at",
    }
    if any(
        header.get(header_key) != permit.get(permit_key)
        for header_key, permit_key in exact_echoes.items()
    ):
        raise _invalid()


def _validated_execution(
    request: FramedMessage,
    context: L3VerificationContext,
) -> ValidatedL3Execution:
    header = request.header
    deployment = context.deployment
    executable = header.get("executable")
    privileges = header.get("required_privileges")
    argv = header.get("argv")
    if (
        type(deployment) is not L3DeploymentContract
        or deployment.permitted_signer_sha256 != context.pinned_signer_fingerprint
        or len(request.frames) != 1
        or type(argv) is not tuple
        or argv != (deployment.broker_path,)
        or not isinstance(executable, Mapping)
        or executable.get("path") != deployment.broker_path
        or executable.get("sha256") != deployment.broker_sha256
        or header.get("operating_system") != "linux"
        or type(context.architecture) is not str
        or header.get("architecture") != context.architecture
        or type(context.timeout_seconds) is not int
        or header.get("timeout_seconds") != context.timeout_seconds
        or type(context.stdout_cap_bytes) is not int
        or header.get("stdout_cap_bytes") != context.stdout_cap_bytes
        or type(context.stderr_cap_bytes) is not int
        or header.get("stderr_cap_bytes") != context.stderr_cap_bytes
        or not isinstance(privileges, tuple)
    ):
        raise _invalid()
    action_id = header.get("action_id")
    runner_identity = header.get("runner_identity")
    execution_digest = header.get("execution_digest")
    if not all(isinstance(value, str) for value in (action_id, runner_identity, execution_digest)):
        raise _invalid()
    return ValidatedL3Execution(
        action_id=str(action_id),
        runner_identity=str(runner_identity),
        executable_path=deployment.broker_path,
        executable_sha256=deployment.broker_sha256,
        operating_system="linux",
        architecture=context.architecture,
        required_privileges=tuple(str(item) for item in privileges),
        timeout_seconds=context.timeout_seconds,
        stdout_cap_bytes=context.stdout_cap_bytes,
        stderr_cap_bytes=context.stderr_cap_bytes,
        execution_digest=str(execution_digest),
    )


def validate_l3_request(
    request: FramedMessage,
    verification_context: L3VerificationContext,
    *,
    replay_reserver: Callable[[str, str, str, datetime], None],
    resource_factory: Callable[[ValidatedL3Request], object],
) -> object:
    """Verify, reserve replay state, then invoke an injected inert factory."""

    if (
        type(request) is not FramedMessage
        or type(verification_context) is not L3VerificationContext
        or not callable(replay_reserver)
        or not callable(resource_factory)
    ):
        raise _invalid()
    permit_frames = tuple(
        frame for frame in request.frames if frame.frame_type is FrameType.EXECUTION_PERMIT
    )
    if len(permit_frames) != 1:
        raise _invalid()

    signed = decode_execution_permit_frame(permit_frames[0])
    execution = _validated_execution(request, verification_context)
    binding = RunBinding.from_header(request.header)
    binding.validate_expiry(verification_context.now)
    verify_execution_permit_v2(
        signed.permit,
        signed.signature,
        verification_context.signer_public_key,
        pinned_signer_fingerprint=verification_context.pinned_signer_fingerprint,
        context=verification_context.permit_context,
        now=verification_context.now,
    )
    _require_header_echo(request.header, signed.permit)

    authority_digest = signed.permit["authority_digest"]
    run_id = signed.permit["run_id"]
    nonce = signed.permit["nonce"]
    if not all(isinstance(value, str) for value in (authority_digest, run_id, nonce)):
        raise _invalid()
    validated = ValidatedL3Request(
        signed_permit=signed,
        run_binding=binding,
        execution=execution,
    )
    object_reserver = cast(Callable[[str, str, str, datetime], object], replay_reserver)
    reservation_result = object_reserver(
        str(authority_digest),
        str(run_id),
        str(nonce),
        verification_context.now,
    )
    if reservation_result is not None:
        raise _invalid()
    return resource_factory(validated)


__all__ = [
    "L3VerificationContext",
    "ValidatedL3Execution",
    "ValidatedL3Request",
    "validate_l3_request",
]
