"""P4 remote helper framed round-trip (loopback)."""

from __future__ import annotations

import io
import json

from hackbot.engagement_v2 import remote_runner_helper as helper
from hackbot.engagement_v2.canonical import execution_digest
from hackbot.engagement_v2.constants import PROTOCOL_VERSION
from hackbot.engagement_v2.protocol import (
    FramedMessage,
    FrameType,
    RunBinding,
    read_message,
    response_chain,
    write_message,
)

_RUN_ID = "11111111-1111-4111-8111-111111111111"
_NONCE = "A" * 43
_AUTH = "sha256:" + "a" * 64


def _request(argv: list[str], executable: str) -> tuple[bytes, dict]:
    header: dict = {
        "protocol_version": PROTOCOL_VERSION,
        "run_id": _RUN_ID,
        "nonce": _NONCE,
        "issued_at": "2026-07-27T12:00:00Z",
        "expires_at": "2026-07-27T12:05:00Z",
        "authority_digest": _AUTH,
        "action_id": "operator.echo",
        "argv": argv,
        "executable": {"path": executable, "sha256": "sha256:" + "3" * 64},
        "runner_identity": "runner.node",
        "operating_system": "linux",
        "architecture": "arm64",
        "required_privileges": [],
        "frames": [],
        "timeout_seconds": 30,
        "stdout_cap_bytes": 65536,
        "stderr_cap_bytes": 65536,
    }
    request = {k: v for k, v in header.items() if k != "execution_digest"}
    header["execution_digest"] = execution_digest({"schema_version": 1, "request": request})
    buffer = io.BytesIO()
    write_message(buffer, FramedMessage(header=header, frames=()))
    return buffer.getvalue(), header


def test_helper_round_trip_runs_argv_and_echoes_binding() -> None:
    request_bytes, header = _request(["/bin/echo", "p4-loopback"], "/bin/echo")
    sink = io.BytesIO()
    helper.run(io.BytesIO(request_bytes), sink)

    response = read_message(io.BytesIO(sink.getvalue()), response=True)
    # The response echoes the request's run binding.
    RunBinding.from_header(header).validate_response_echo(response.header)

    stdout = b"".join(f.payload for f in response.frames if f.frame_type is FrameType.STDOUT)
    assert stdout.strip() == b"p4-loopback"

    # The structured result carries the exact response hash chain over the output.
    output = tuple(
        f for f in response.frames if f.frame_type in (FrameType.STDOUT, FrameType.STDERR)
    )
    expected_chain = "sha256:" + response_chain(header["execution_digest"], output)
    structured = next(f for f in response.frames if f.frame_type is FrameType.STRUCTURED_RESULT)
    result = json.loads(structured.payload)
    assert result["response_chain"] == expected_chain
    assert result["exit_code"] == 0
