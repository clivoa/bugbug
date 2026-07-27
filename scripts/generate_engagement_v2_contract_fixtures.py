#!/usr/bin/env python3
"""Generate the deterministic engagement-v2 contract fixture corpus."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from io import BytesIO
from pathlib import Path
from typing import Final

_PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from hackbot.engagement_v2.canonical import (  # noqa: E402
    authority_digest,
    canonical_bytes,
    execution_digest,
)
from hackbot.engagement_v2.constants import PROTOCOL_VERSION  # noqa: E402
from hackbot.engagement_v2.patterns import (  # noqa: E402
    compile_safe_pattern,
    safe_fullmatch,
)
from hackbot.engagement_v2.protocol import (  # noqa: E402
    Frame,
    FramedMessage,
    FrameType,
    write_message,
)

_DEFAULT_ROOT: Final = _PROJECT_ROOT / "tests" / "fixtures" / "engagement_v2"
_AUTHORITY_INPUT: Final[dict[str, object]] = {
    "schema_version": 1,
    "profile": "private-pentest",
    "action": {
        "argv": [
            "--target",
            "https://scanner.example.invalid/health",
            "--format",
            "json",
        ],
        "artifact_hash": "sha256:"
        + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "endpoint": "https://scanner.example.invalid/health",
    },
}
_PATTERN_CASES: Final[list[dict[str, object]]] = [
    {
        "name": "synthetic hostname",
        "source": r"[A-Za-z0-9._\-]{1,64}",
        "value": "scanner.example.invalid",
        "expected": True,
    },
    {
        "name": "bounded decimal",
        "source": r"[0-9]{1,5}",
        "value": "65535",
        "expected": True,
    },
    {
        "name": "implicit full match",
        "source": r"[0-9]{1,5}",
        "value": "12x",
        "expected": False,
    },
    {
        "name": "escaped grammar literals",
        "source": r"fixture\{synthetic\}",
        "value": "fixture{synthetic}",
        "expected": True,
    },
    {
        "name": "explicit optional repetition",
        "source": r"lab{0,3}",
        "value": "la",
        "expected": True,
    },
    {
        "name": "negated printable ASCII class",
        "source": r"[^0-9]{1,4}",
        "value": "Test",
        "expected": True,
    },
]


def _pretty_json(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def _canonical_fixtures() -> dict[str, bytes]:
    return {
        "canonical/authority-input.json": _pretty_json(_AUTHORITY_INPUT),
        "canonical/authority-canonical.json": canonical_bytes(_AUTHORITY_INPUT),
        "canonical/authority-digest.txt": (authority_digest(_AUTHORITY_INPUT) + "\n").encode(
            "ascii"
        ),
    }


def _pattern_fixtures() -> dict[str, bytes]:
    for case in _PATTERN_CASES:
        source = case["source"]
        value = case["value"]
        expected = case["expected"]
        if (
            type(source) is not str
            or type(value) is not str
            or type(expected) is not bool
            or safe_fullmatch(compile_safe_pattern(source), value) is not expected
        ):
            raise ValueError("invalid synthetic pattern fixture")
    return {"patterns/cases.json": _pretty_json(_PATTERN_CASES)}


def _request_protocol_header(payload: bytes) -> dict[str, object]:
    descriptor = {
        "index": 0,
        "frame_type": FrameType.ARTIFACT.value,
        "length": len(payload),
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }
    header: dict[str, object] = {
        "protocol_version": PROTOCOL_VERSION,
        "run_id": "123e4567-e89b-42d3-a456-426614174000",
        "nonce": base64.urlsafe_b64encode(b"\x00" * 32).decode("ascii").rstrip("="),
        "issued_at": "2026-07-26T12:00:00Z",
        "expires_at": "2026-07-26T12:05:00Z",
        "authority_digest": "sha256:" + "1" * 64,
        "action_id": "operator.fixture",
        "argv": ["/opt/example.invalid/bin/synthetic-runner", "--fixture"],
        "executable": {
            "path": "/opt/example.invalid/bin/synthetic-runner",
            "sha256": "sha256:" + "3" * 64,
        },
        "runner_identity": "runner.example.invalid",
        "operating_system": "linux",
        "architecture": "x86_64",
        "required_privileges": [],
        "frames": [descriptor],
        "timeout_seconds": 60,
        "stdout_cap_bytes": 4096,
        "stderr_cap_bytes": 4096,
    }
    request = {key: value for key, value in header.items() if key != "execution_digest"}
    header["execution_digest"] = execution_digest({"schema_version": 1, "request": request})
    return header


def _protocol_fixtures() -> dict[str, bytes]:
    payload = b"synthetic-artifact"
    header = _request_protocol_header(payload)
    message = FramedMessage(
        header=header,
        frames=(Frame(FrameType.ARTIFACT, payload),),
    )
    stream = BytesIO()
    write_message(stream, message)
    encoded_message = stream.getvalue()
    return {
        "protocol/request-header.json": canonical_bytes(header),
        "protocol/request-frame.bin": encoded_message[-60:],
        "protocol/request-message.bin": encoded_message,
    }


def _generated_bytes() -> dict[str, bytes]:
    fixtures = _canonical_fixtures()
    fixtures.update(_pattern_fixtures())
    fixtures.update(_protocol_fixtures())
    return fixtures


def _atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    with temporary_path.open("wb") as temporary_file:
        temporary_file.write(value)
    os.replace(temporary_path, path)


def generate(root: Path, *, check: bool) -> tuple[str, ...]:
    """Generate fixtures below *root*, or report drift without mutating it."""

    generated = _generated_bytes()
    differing = tuple(
        relative_path
        for relative_path in sorted(generated)
        if not (root / relative_path).is_file()
        or (root / relative_path).read_bytes() != generated[relative_path]
    )
    if not check:
        for relative_path in differing:
            _atomic_write(root / relative_path, generated[relative_path])
    return differing


def main(arguments: list[str]) -> int:
    """Run the fixture generator with its deliberately small command interface."""

    if arguments not in ([], ["--check"]):
        raise SystemExit("usage: generate_engagement_v2_contract_fixtures.py [--check]")
    differing = generate(_DEFAULT_ROOT, check=arguments == ["--check"])
    if arguments == ["--check"] and differing:
        print("\n".join(differing))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
