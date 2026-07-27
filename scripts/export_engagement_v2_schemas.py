#!/usr/bin/env python3
"""Export or check the committed engagement-v2 JSON Schema files."""

from __future__ import annotations

import argparse
import errno
import inspect
import os
import secrets
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from hackbot.engagement_v2.schemas import render_schema_files  # noqa: E402

SCHEMA_ROOT = REPOSITORY_ROOT / "schemas" / "engagement-v2"
_PRIVATE_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o755
_TEMPORARY_ATTEMPTS = 100


def _before_entry_open(_name: str) -> None:
    """Provide a deterministic race-injection seam for the test suite."""


def _before_replace(_name: str) -> None:
    """Provide a deterministic race-injection seam for the test suite."""


def _before_temporary_verify(_temporary_name: str, _name: str) -> None:
    """Provide a deterministic temporary-substitution seam for the test suite."""


def _after_replace(_name: str) -> None:
    """Provide a deterministic publication-substitution seam for the test suite."""


def _require_descriptor_safe_primitives() -> None:
    required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
    required_functions = (os.open, os.mkdir, os.unlink)
    replace_parameters = inspect.signature(os.replace).parameters
    if (
        os.name != "posix"
        or any(not isinstance(getattr(os, name, None), int) for name in required_flags)
        or any(function not in os.supports_dir_fd for function in required_functions)
        or not {"src_dir_fd", "dst_dir_fd"} <= set(replace_parameters)
    ):
        raise RuntimeError("descriptor-safe schema export is unavailable on this platform")


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _entry_flags() -> int:
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


def _raise_unsafe_path(path: Path, error: OSError) -> None:
    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
        raise RuntimeError(f"symlink destination rejected: {path}") from error
    raise error


def _open_pinned_directory(destination: Path, *, create: bool) -> int:
    absolute = destination if destination.is_absolute() else Path.cwd() / destination
    descriptor = os.open(absolute.anchor, _directory_flags())
    try:
        for component in absolute.parts[1:]:
            if component in {"", ".", ".."}:
                raise RuntimeError(f"invalid schema destination component: {component!r}")
            try:
                next_descriptor = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, _DIRECTORY_MODE, dir_fd=descriptor)
                except FileExistsError:
                    pass
                try:
                    next_descriptor = os.open(
                        component,
                        _directory_flags(),
                        dir_fd=descriptor,
                    )
                except OSError as error:
                    _raise_unsafe_path(absolute, error)
            except OSError as error:
                _raise_unsafe_path(absolute, error)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_existing_entry(directory_descriptor: int, name: str) -> int:
    _before_entry_open(name)
    try:
        return os.open(name, _entry_flags(), dir_fd=directory_descriptor)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise RuntimeError(f"symlink destination rejected: {name}") from error
        raise


def _open_regular_entry(directory_descriptor: int, name: str) -> int:
    descriptor = _open_existing_entry(directory_descriptor, name)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError(f"schema destination entry is not a regular file: {name}")
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_entry(directory_descriptor: int, name: str) -> bytes:
    descriptor = _open_regular_entry(directory_descriptor, name)
    try:
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _preflight_existing_entry(directory_descriptor: int, name: str) -> None:
    try:
        descriptor = _open_regular_entry(directory_descriptor, name)
    except FileNotFoundError:
        return
    os.close(descriptor)


def _drifted_files(directory_descriptor: int, rendered: dict[str, bytes]) -> tuple[str, ...]:
    expected_names = set(rendered)
    actual_names = set(os.listdir(directory_descriptor))
    drifted = actual_names ^ expected_names

    for name in sorted(actual_names - expected_names):
        _preflight_existing_entry(directory_descriptor, name)

    for name in sorted(actual_names & expected_names):
        try:
            actual = _read_entry(directory_descriptor, name)
        except FileNotFoundError:
            drifted.add(name)
            continue
        if actual != rendered[name]:
            drifted.add(name)
    return tuple(sorted(drifted))


def _temporary_name(name: str) -> str:
    return f".{name}.{secrets.token_hex(16)}.tmp"


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _verify_temporary_entry(
    directory_descriptor: int,
    temporary_name: str,
    temporary_descriptor: int,
    name: str,
) -> None:
    _before_temporary_verify(temporary_name, name)
    descriptor = _open_regular_entry(directory_descriptor, temporary_name)
    try:
        if not _same_file(os.fstat(temporary_descriptor), os.fstat(descriptor)):
            raise RuntimeError(f"temporary schema entry changed before publication: {name}")
    finally:
        os.close(descriptor)


def _verify_published_entry(
    directory_descriptor: int,
    name: str,
    temporary_descriptor: int,
) -> None:
    try:
        descriptor = _open_regular_entry(directory_descriptor, name)
    except RuntimeError:
        try:
            os.unlink(name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        raise
    try:
        if not _same_file(os.fstat(temporary_descriptor), os.fstat(descriptor)):
            os.unlink(name, dir_fd=directory_descriptor)
            raise RuntimeError(f"published schema entry changed during publication: {name}")
    finally:
        os.close(descriptor)


def _write_bytes(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        remaining = remaining[written:]


def _write_one(directory_descriptor: int, name: str, content: bytes) -> None:
    _preflight_existing_entry(directory_descriptor, name)
    temporary_name = ""
    descriptor = -1
    for _ in range(_TEMPORARY_ATTEMPTS):
        temporary_name = _temporary_name(name)
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                _PRIVATE_FILE_MODE,
                dir_fd=directory_descriptor,
            )
        except FileExistsError:
            continue
        break
    if descriptor < 0:
        raise RuntimeError(f"could not create exclusive schema temporary for {name}")

    try:
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        _write_bytes(descriptor, content)
        os.fsync(descriptor)
        _before_replace(name)
        _preflight_existing_entry(directory_descriptor, name)
        _verify_temporary_entry(directory_descriptor, temporary_name, descriptor, name)
        os.replace(
            temporary_name,
            name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        _after_replace(name)
        _verify_published_entry(directory_descriptor, name, descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass


def _write_files(destination: Path, rendered: dict[str, bytes]) -> None:
    directory_descriptor = _open_pinned_directory(destination, create=True)
    try:
        document_names = sorted(set(rendered) - {"manifest.json"})
        for name in [*document_names, "manifest.json"]:
            content = rendered[name]
            _write_one(directory_descriptor, name, content)
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
    _require_descriptor_safe_primitives()
    rendered = render_schema_files()
    if arguments.check:
        try:
            directory_descriptor = _open_pinned_directory(SCHEMA_ROOT, create=False)
        except FileNotFoundError:
            drifted = tuple(sorted(rendered))
        else:
            try:
                drifted = _drifted_files(directory_descriptor, rendered)
            finally:
                os.close(directory_descriptor)
        for name in drifted:
            print(f"drift: {name}", file=sys.stderr)
        return int(bool(drifted))

    _write_files(SCHEMA_ROOT, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
