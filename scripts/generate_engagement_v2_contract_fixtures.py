#!/usr/bin/env python3
"""Generate the deterministic engagement-v2 contract fixture corpus."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
from datetime import UTC, datetime, timedelta
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
from hackbot.engagement_v2.constants import (  # noqa: E402
    MAX_REQUEST_LIFETIME_SECONDS,
    NONCE_BYTES,
    PROTOCOL_VERSION,
)
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
        "nonce": base64.urlsafe_b64encode(b"\x00" * NONCE_BYTES).decode("ascii").rstrip("="),
        "issued_at": "2026-07-26T12:00:00Z",
        "expires_at": (
            datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
            + timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
    raw_header = canonical_bytes(header)
    header_offset = encoded_message.find(raw_header)
    if (
        header_offset < 0
        or encoded_message.find(raw_header, header_offset + 1) != -1
        or header_offset + len(raw_header) >= len(encoded_message)
    ):
        raise ValueError("ambiguous protocol fixture boundary")
    frame_bytes = encoded_message[header_offset + len(raw_header) :]
    return {
        "protocol/request-header.json": raw_header,
        "protocol/request-frame.bin": frame_bytes,
        "protocol/request-message.bin": encoded_message,
    }


def _generated_bytes() -> dict[str, bytes]:
    fixtures = _canonical_fixtures()
    fixtures.update(_pattern_fixtures())
    fixtures.update(_protocol_fixtures())
    return fixtures


def _unsafe_path(path: Path, reason: str) -> ValueError:
    return ValueError(f"unsafe fixture path {path}: {reason}")


def _directory(path: Path, *, create: bool) -> None:
    """Require a real directory at *path*, creating only a missing component."""

    try:
        status = path.lstat()
    except FileNotFoundError:
        if not create:
            raise
        path.mkdir()
        status = path.lstat()
    if stat.S_ISLNK(status.st_mode):
        raise _unsafe_path(path, "symlink")
    if not stat.S_ISDIR(status.st_mode):
        raise _unsafe_path(path, "not a directory")


def _managed_parent(root: Path, relative_path: str, *, create: bool) -> Path | None:
    """Return a real managed parent without traversing symlink components."""

    _directory(root, create=False)
    parent = root
    for component in Path(relative_path).parts[:-1]:
        parent = parent / component
        try:
            _directory(parent, create=create)
        except FileNotFoundError:
            return None
    return parent


def _read_managed_file(root: Path, relative_path: str) -> bytes | None:
    """Read one regular managed file without following a destination symlink."""

    parent = _managed_parent(root, relative_path, create=False)
    if parent is None:
        return None
    destination = parent / Path(relative_path).name
    try:
        status = destination.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(status.st_mode):
        raise _unsafe_path(destination, "symlink")
    if not stat.S_ISREG(status.st_mode):
        raise _unsafe_path(destination, "not a regular file")
    descriptor = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _unsafe_path(destination, "not a regular file")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            return source.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_write(root: Path, relative_path: str, value: bytes) -> None:
    """Publish a managed regular file through an exclusive sibling staging file."""

    parent = _managed_parent(root, relative_path, create=True)
    if parent is None:
        raise _unsafe_path(root, "missing managed parent")
    destination = parent / Path(relative_path).name
    try:
        existing = destination.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(existing.st_mode):
            raise _unsafe_path(destination, "symlink")
        if not stat.S_ISREG(existing.st_mode):
            raise _unsafe_path(destination, "not a regular file")

    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as temporary_file:
            descriptor = -1
            temporary_file.write(value)
        try:
            existing = destination.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(existing.st_mode):
                raise _unsafe_path(destination, "symlink")
            if not stat.S_ISREG(existing.st_mode):
                raise _unsafe_path(destination, "not a regular file")
        os.replace(temporary_path, destination)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _fixture_entries(root: Path, generated: dict[str, bytes]) -> set[str]:
    """Enumerate fixture entries without following directory or file symlinks."""

    _directory(root, create=False)
    entries: set[str] = set()
    managed_directories = {
        "/".join(Path(relative_path).parts[:-1])
        for relative_path in generated
        if len(Path(relative_path).parts) > 1
    }

    def visit(directory: Path, prefix: Path) -> None:
        for child in directory.iterdir():
            relative_path = (prefix / child.name).as_posix()
            status = child.lstat()
            if stat.S_ISDIR(status.st_mode):
                if relative_path not in managed_directories:
                    entries.add(relative_path)
                visit(child, prefix / child.name)
            else:
                entries.add(relative_path)

    visit(root, Path())
    return entries


def generate(root: Path, *, check: bool) -> tuple[str, ...]:
    """Generate fixtures below *root*, or report drift without mutating it."""

    generated = _generated_bytes()
    try:
        _directory(root, create=not check)
    except FileNotFoundError:
        return tuple(sorted(generated))
    managed_differences = {
        relative_path
        for relative_path, value in generated.items()
        if _read_managed_file(root, relative_path) != value
    }
    differing = tuple(
        sorted(managed_differences | (_fixture_entries(root, generated) - set(generated)))
    )
    if not check:
        for relative_path in sorted(managed_differences):
            _atomic_write(root, relative_path, generated[relative_path])
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
