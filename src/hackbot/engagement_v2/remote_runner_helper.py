"""Fixed `hackbot-remote-runner` helper (remote side of the P4 transport).

Runs on the execution node. It reads one P0 framed request from stdin, runs the
bound argv with ``shell=False`` under the request's timeout and output caps, and
writes one P0 framed response to stdout: a stdout frame, a stderr frame, and a
structured-result frame carrying the response hash chain and exit code. It never
interprets a shell string and echoes the request's run binding.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import BinaryIO

from hackbot.engagement_v2.constants import PROTOCOL_VERSION
from hackbot.engagement_v2.protocol import (
    Frame,
    FramedMessage,
    FrameType,
    read_message,
    response_chain,
    write_message,
)


def _descriptor(index: int, frame: Frame) -> dict[str, object]:
    import hashlib

    return {
        "index": index,
        "frame_type": frame.frame_type.value,
        "length": len(frame.payload),
        "sha256": "sha256:" + hashlib.sha256(frame.payload).hexdigest(),
    }


def handle(request: FramedMessage) -> FramedMessage:
    header = request.header
    argv = header["argv"]
    if not isinstance(argv, (list, tuple)) or not all(isinstance(token, str) for token in argv):
        raise ValueError("invalid argv")
    timeout = header.get("timeout_seconds")
    stdout_cap = header.get("stdout_cap_bytes")
    stderr_cap = header.get("stderr_cap_bytes")

    completed = subprocess.run(  # noqa: S603 - argv array, shell=False, bounded
        list(argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=float(timeout) if isinstance(timeout, int) else 60.0,
        check=False,
    )
    out = completed.stdout[: stdout_cap if isinstance(stdout_cap, int) else 4096]
    err = completed.stderr[: stderr_cap if isinstance(stderr_cap, int) else 4096]

    execution_digest_value = str(header["execution_digest"])
    output_frames = (Frame(FrameType.STDOUT, out), Frame(FrameType.STDERR, err))
    chain = response_chain(execution_digest_value, output_frames)
    structured = json.dumps(
        {"exit_code": completed.returncode, "response_chain": "sha256:" + chain},
        sort_keys=True,
    ).encode("utf-8")
    frames = (*output_frames, Frame(FrameType.STRUCTURED_RESULT, structured))

    response_header: dict[str, object] = {
        "protocol_version": PROTOCOL_VERSION,
        "run_id": header["run_id"],
        "nonce": header["nonce"],
        "authority_digest": header["authority_digest"],
        "execution_digest": execution_digest_value,
        "frames": [_descriptor(index, frame) for index, frame in enumerate(frames)],
    }
    return FramedMessage(header=response_header, frames=frames)


def run(source: BinaryIO, sink: BinaryIO) -> None:
    request = read_message(source, response=False)
    write_message(sink, handle(request))


def main() -> int:
    run(sys.stdin.buffer, sys.stdout.buffer)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
