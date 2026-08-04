"""Validation-only P5b gate which runs before replay reservation and resources."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from hackbot.engagement_v2.constants import FrameType
from hackbot.engagement_v2.errors import ContractError, ReasonCode
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


@dataclass(frozen=True, slots=True)
class ValidatedL3Request:
    """An inert token proving validation and reservation ordering inputs."""

    request: FramedMessage
    signed_permit: SignedExecutionPermit
    run_binding: RunBinding


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


def validate_l3_request(
    request: FramedMessage,
    verification_context: L3VerificationContext,
    *,
    replay_reserver: Callable[[str, str, str, datetime], object],
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
        request=request,
        signed_permit=signed,
        run_binding=binding,
    )
    replay_reserver(
        str(authority_digest),
        str(run_id),
        str(nonce),
        verification_context.now,
    )
    return resource_factory(validated)


__all__ = [
    "L3VerificationContext",
    "ValidatedL3Request",
    "validate_l3_request",
]
