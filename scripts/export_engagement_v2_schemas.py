#!/usr/bin/env python3
"""Export or check the committed engagement-v2 JSON Schema files."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from hackbot.engagement_v2.schemas import render_schema_files  # noqa: E402

SCHEMA_ROOT = REPOSITORY_ROOT / "schemas" / "engagement-v2"
_PRIVATE_FILE_MODE = 0o600


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"symlink destination rejected: {path}")


def _reject_symlink_components(path: Path) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    for candidate in (*reversed(absolute.parents), absolute):
        _reject_symlink(candidate)


def _drifted_files(destination: Path, rendered: dict[str, bytes]) -> tuple[str, ...]:
    if destination.is_symlink() or not destination.is_dir():
        return tuple(sorted(rendered))

    drifted: list[str] = []
    for name, expected in sorted(rendered.items()):
        path = destination / name
        _reject_symlink(path)
        try:
            actual = path.read_bytes()
        except OSError:
            drifted.append(name)
            continue
        if actual != expected:
            drifted.append(name)
    return tuple(drifted)


def _write_one(destination: Path, name: str, content: bytes) -> None:
    target = destination / name
    _reject_symlink_components(target)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=destination,
        prefix=f".{name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(file_descriptor, _PRIVATE_FILE_MODE)
        with os.fdopen(file_descriptor, "wb") as stream:
            file_descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_files(destination: Path, rendered: dict[str, bytes]) -> None:
    _reject_symlink_components(destination)
    destination.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(destination)
    if not destination.is_dir():
        raise RuntimeError(f"schema destination is not a directory: {destination}")

    for name in rendered:
        _reject_symlink_components(destination / name)
    for name, content in rendered.items():
        _write_one(destination, name, content)

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_descriptor = os.open(destination, directory_flags)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report exact-byte drift without writing files",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the exporter and return its process exit status."""

    arguments = _parser().parse_args(argv)
    rendered = render_schema_files()
    if arguments.check:
        _reject_symlink_components(SCHEMA_ROOT)
        drifted = _drifted_files(SCHEMA_ROOT, rendered)
        for name in drifted:
            print(f"drift: {name}", file=sys.stderr)
        return int(bool(drifted))

    _write_files(SCHEMA_ROOT, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
