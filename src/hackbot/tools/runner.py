"""Policy-free subprocess execution: argv arrays only, never a shell.

This unit performs no policy decision. It runs an already-rendered argv array
with ``shell=False``, a mandatory bounded timeout, closed stdin, a sanitized
environment (never the operator's, so no secret env var leaks into a child),
and byte-capped output. Callers must obtain an ``ALLOW`` from the risk gate
before invoking it.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

_DEFAULT_ENV: dict[str, str] = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
_READ_CHUNK_BYTES = 64 * 1024
_READ_POLL_SECONDS = 0.01
_CLEANUP_GRACE_SECONDS = 1.0
_CLEANUP_STOP_SECONDS = 0.1


class RunnerError(Exception):
    """Raised for a malformed argv or a missing executable (fail-closed)."""


@dataclass(slots=True)
class _CaptureState:
    data: bytearray = field(default_factory=bytearray)
    truncated: bool = False
    error: OSError | None = None
    done: threading.Event = field(default_factory=threading.Event)


def _capture_fd(
    fd: int,
    *,
    cap: int,
    stop: threading.Event,
    failed: threading.Event,
    state: _CaptureState,
) -> None:
    try:
        while not stop.is_set():
            try:
                chunk = os.read(fd, _READ_CHUNK_BYTES)
            except BlockingIOError:
                stop.wait(_READ_POLL_SECONDS)
                continue
            if not chunk:
                return
            remaining = max(0, cap - len(state.data))
            if remaining:
                state.data.extend(chunk[:remaining])
            if len(chunk) > remaining:
                state.truncated = True
    except OSError as exc:
        state.error = exc
        failed.set()
    finally:
        state.done.set()


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool
    truncated: bool


class CommandRunner:
    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        output_cap_bytes: int = 1_048_576,
        env: Mapping[str, str] | None = None,
    ) -> None:
        if timeout_seconds <= 0 or output_cap_bytes <= 0:
            raise RunnerError("timeout and output cap must be positive")
        self._timeout = float(timeout_seconds)
        self._cap = int(output_cap_bytes)
        self._env = dict(env) if env is not None else dict(_DEFAULT_ENV)

    def _truncate(self, data: bytes) -> tuple[bytes, bool]:
        return (data[: self._cap], True) if len(data) > self._cap else (data, False)

    def run(self, argv: Sequence[str]) -> CommandResult:
        items = tuple(argv)
        if not items:
            raise RunnerError("argv must be non-empty")
        executable = items[0]
        if not (os.path.isabs(executable) and os.path.isfile(executable)):
            raise RunnerError(f"executable not found: {executable}")
        # A fresh, empty, per-run HOME: tools that need a config/cache dir get one
        # without ever seeing the operator's real HOME (which may hold secrets).
        home = tempfile.mkdtemp(prefix="hackbot-tool-home-")
        env = {**self._env, "HOME": home}
        start = time.monotonic()
        try:
            try:
                proc = subprocess.Popen(
                    list(items),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    start_new_session=True,
                    close_fds=True,
                )
            except OSError as exc:
                raise RunnerError(f"could not start executable: {executable}") from exc
            timed_out = False
            try:
                stdout, stderr = proc.communicate(timeout=self._timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                stdout, stderr = proc.communicate()
        finally:
            shutil.rmtree(home, ignore_errors=True)
        duration_ms = int((time.monotonic() - start) * 1000)
        stdout, out_truncated = self._truncate(stdout)
        stderr, err_truncated = self._truncate(stderr)
        return CommandResult(
            exit_code=None if timed_out else proc.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            truncated=out_truncated or err_truncated,
        )
