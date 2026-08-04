"""P5b pre-resource permit, replay, and inert factory ordering tests."""

from __future__ import annotations

import base64
import hashlib
import importlib
from datetime import datetime

import pytest

from hackbot.engagement_v2.canonical import canonical_bytes, execution_digest
from hackbot.engagement_v2.constants import PROTOCOL_VERSION, FrameType
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.protocol import Frame, FramedMessage
from hackbot.engagement_v2.remote_permit import (
    build_execution_permit_v2,
    sign_execution_permit_v2,
)

from ._ed25519_sign import public_key, sign
from .test_l3_permit import _NOW, _SEED, _context, _fingerprint


def _descriptor(index: int, frame_type: FrameType, payload: bytes) -> dict[str, object]:
    return {
        "index": index,
        "frame_type": frame_type.value,
        "length": len(payload),
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }


def _message(
    *,
    include_permit: bool = True,
    permit_changes: dict[str, object] | None = None,
    header_changes: dict[str, object] | None = None,
    corrupt_signature: bool = False,
) -> tuple[FramedMessage, object]:
    context = _context()
    permit = build_execution_permit_v2(context)
    if permit_changes:
        permit.update(permit_changes)
    signature = sign_execution_permit_v2(permit, lambda message: sign(_SEED, message))
    if corrupt_signature:
        changed = bytearray(signature)
        changed[0] ^= 1
        signature = bytes(changed)
    payload = canonical_bytes(
        {
            "permit": permit,
            "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        }
    )
    frames = (Frame(FrameType.EXECUTION_PERMIT, payload),) if include_permit else ()
    header: dict[str, object] = {
        "protocol_version": PROTOCOL_VERSION,
        "run_id": permit["run_id"],
        "nonce": permit["nonce"],
        "issued_at": permit["issued_at"],
        "expires_at": permit["expires_at"],
        "authority_digest": permit["authority_digest"],
        "action_id": permit["action_id"],
        "argv": ["/usr/local/libexec/hackbot-l3-runner"],
        "executable": {
            "path": "/usr/local/libexec/hackbot-l3-runner",
            "sha256": "sha256:" + "d" * 64,
        },
        "runner_identity": permit["runner_identity"],
        "operating_system": "linux",
        "architecture": "x86_64",
        "required_privileges": permit["required_privileges"],
        "frames": [
            _descriptor(index, frame.frame_type, frame.payload)
            for index, frame in enumerate(frames)
        ],
        "timeout_seconds": 60,
        "stdout_cap_bytes": 4096,
        "stderr_cap_bytes": 4096,
    }
    if header_changes:
        header.update(header_changes)
    request_without_digest = dict(header)
    header["execution_digest"] = execution_digest(
        {"schema_version": 1, "request": request_without_digest}
    )
    return FramedMessage(header=header, frames=frames), context


def _verification_context(permit_context: object):
    gate_module = importlib.import_module("hackbot.engagement_v2.l3_gate")
    return gate_module.L3VerificationContext(
        permit_context=permit_context,
        signer_public_key=public_key(_SEED),
        pinned_signer_fingerprint=_fingerprint(public_key(_SEED)),
        now=_NOW,
    )


def test_valid_request_reserves_replay_before_inert_resource_factory() -> None:
    """Catch resource creation before signature verification and replay reservation."""

    gate_module = importlib.import_module("hackbot.engagement_v2.l3_gate")
    assert callable(getattr(gate_module, "validate_l3_request", None))
    request, permit_context = _message()
    events: list[str] = []

    def reserve(authority: str, run_id: str, nonce: str, now: datetime) -> None:
        assert (authority, run_id, nonce, now) == (
            permit_context.snapshot.authority_digest,
            permit_context.run_id,
            permit_context.nonce,
            _NOW,
        )
        events.append("reserve")

    def create(validated: object) -> str:
        assert validated.request is request
        events.append("resource")
        return "inert-validation-token"

    result = gate_module.validate_l3_request(
        request,
        _verification_context(permit_context),
        replay_reserver=reserve,
        resource_factory=create,
    )
    assert result == "inert-validation-token"
    assert events == ["reserve", "resource"]


@pytest.mark.parametrize("failure", ["missing", "signature", "authority", "action", "run", "nonce"])
def test_invalid_request_calls_neither_reservation_nor_resource(failure: str) -> None:
    """Catch callbacks running after any invalid permit/header binding."""

    permit_changes: dict[str, object] | None = None
    header_changes: dict[str, object] | None = None
    include_permit = True
    corrupt_signature = False
    if failure == "missing":
        include_permit = False
    elif failure == "signature":
        corrupt_signature = True
    elif failure == "authority":
        header_changes = {"authority_digest": "sha256:" + "f" * 64}
    elif failure == "action":
        header_changes = {"action_id": "operator.fixture"}
    elif failure == "run":
        header_changes = {"run_id": "22222222-2222-4222-8222-222222222222"}
    else:
        different_nonce = base64.urlsafe_b64encode(b"z" * 32).decode("ascii").rstrip("=")
        header_changes = {"nonce": different_nonce}
    request, permit_context = _message(
        include_permit=include_permit,
        permit_changes=permit_changes,
        header_changes=header_changes,
        corrupt_signature=corrupt_signature,
    )
    events: list[str] = []
    gate_module = importlib.import_module("hackbot.engagement_v2.l3_gate")

    with pytest.raises(ContractError):
        gate_module.validate_l3_request(
            request,
            _verification_context(permit_context),
            replay_reserver=lambda *_args: events.append("reserve"),
            resource_factory=lambda _validated: events.append("resource"),
        )
    assert events == []


def test_reservation_failure_prevents_resource_factory() -> None:
    request, permit_context = _message()
    events: list[str] = []
    gate_module = importlib.import_module("hackbot.engagement_v2.l3_gate")

    def reject_replay(*_args: object) -> None:
        events.append("reserve")
        raise ContractError(ReasonCode.EXEC_PROTOCOL_REPLAY)

    with pytest.raises(ContractError) as excinfo:
        gate_module.validate_l3_request(
            request,
            _verification_context(permit_context),
            replay_reserver=reject_replay,
            resource_factory=lambda _validated: events.append("resource"),
        )
    assert excinfo.value.reason_code is ReasonCode.EXEC_PROTOCOL_REPLAY
    assert events == ["reserve"]
