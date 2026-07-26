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
from typing import BinaryIO, cast

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


def _kill_process_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _all_done(states: tuple[_CaptureState, _CaptureState]) -> bool:
    return all(state.done.is_set() for state in states)


def _join_readers(
    threads: tuple[threading.Thread, ...],
    *,
    deadline: float,
) -> bool:
    for thread in threads:
        remaining = deadline - time.monotonic()
        if remaining > 0:
            thread.join(remaining)
    return all(not thread.is_alive() for thread in threads)


def _set_nonblocking(pipe: BinaryIO) -> int:
    fd = pipe.fileno()
    os.set_blocking(fd, False)
    return fd


def _cleanup_spawned_process(
    proc: subprocess.Popen[bytes],
    *,
    pgid: int,
    pipes: tuple[BinaryIO, BinaryIO],
    threads: tuple[threading.Thread, ...],
    stop: threading.Event,
) -> bool:
    _kill_process_group(pgid)
    cleanup_deadline = time.monotonic() + _CLEANUP_GRACE_SECONDS
    drain_deadline = cleanup_deadline - _CLEANUP_STOP_SECONDS
    while time.monotonic() < drain_deadline:
        child_reaped = proc.poll() is not None
        readers_stopped = all(not thread.is_alive() for thread in threads)
        if child_reaped and readers_stopped:
            break
        remaining = drain_deadline - time.monotonic()
        if remaining > 0:
            stop.wait(min(_READ_POLL_SECONDS, remaining))

    stop.set()
    readers_stopped = _join_readers(threads, deadline=cleanup_deadline)
    child_reaped = proc.poll() is not None
    if not child_reaped:
        remaining = cleanup_deadline - time.monotonic()
        if remaining > 0:
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                pass
        child_reaped = proc.poll() is not None

    if readers_stopped:
        for pipe in pipes:
            pipe.close()
    return readers_stopped and child_reaped


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

    def run(self, argv: Sequence[str]) -> CommandResult:
        items = tuple(argv)
        if not items:
            raise RunnerError("argv must be non-empty")
        executable = items[0]
        if not (os.path.isabs(executable) and os.path.isfile(executable)):
            raise RunnerError(f"executable not found: {executable}")

        home = tempfile.mkdtemp(prefix="hackbot-tool-home-")
        env = {**self._env, "HOME": home}
        start = time.monotonic()
        deadline = start + self._timeout
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

            pgid = proc.pid
            if proc.stdout is None or proc.stderr is None:
                _kill_process_group(pgid)
                try:
                    proc.wait(timeout=_CLEANUP_GRACE_SECONDS)
                except subprocess.TimeoutExpired as exc:
                    raise RunnerError("subprocess cleanup did not complete") from exc
                raise RunnerError("could not initialize subprocess capture")

            stdout_pipe = cast(BinaryIO, proc.stdout)
            stderr_pipe = cast(BinaryIO, proc.stderr)
            pipes = (stdout_pipe, stderr_pipe)
            stop = threading.Event()
            failed = threading.Event()
            stdout_state = _CaptureState()
            stderr_state = _CaptureState()
            states = (stdout_state, stderr_state)
            started_threads: list[threading.Thread] = []

            try:
                stdout_fd = _set_nonblocking(stdout_pipe)
                stderr_fd = _set_nonblocking(stderr_pipe)
                configured_threads = (
                    threading.Thread(
                        target=_capture_fd,
                        kwargs={
                            "fd": stdout_fd,
                            "cap": self._cap,
                            "stop": stop,
                            "failed": failed,
                            "state": stdout_state,
                        },
                        name=f"hackbot-stdout-{proc.pid}",
                        daemon=True,
                    ),
                    threading.Thread(
                        target=_capture_fd,
                        kwargs={
                            "fd": stderr_fd,
                            "cap": self._cap,
                            "stop": stop,
                            "failed": failed,
                            "state": stderr_state,
                        },
                        name=f"hackbot-stderr-{proc.pid}",
                        daemon=True,
                    ),
                )
                for thread in configured_threads:
                    thread.start()
                    started_threads.append(thread)
            except (OSError, RuntimeError) as exc:
                cleaned = _cleanup_spawned_process(
                    proc,
                    pgid=pgid,
                    pipes=pipes,
                    threads=tuple(started_threads),
                    stop=stop,
                )
                if not cleaned:
                    raise RunnerError("subprocess cleanup did not complete") from exc
                raise RunnerError("could not initialize subprocess capture") from exc

            threads = tuple(started_threads)
            timed_out = False
            capture_error: OSError | None = None
            while True:
                if failed.is_set():
                    capture_error = next(
                        (state.error for state in states if state.error is not None),
                        OSError("subprocess output capture failed"),
                    )
                    break
                child_reaped = proc.poll() is not None
                readers_stopped = all(not thread.is_alive() for thread in threads)
                if child_reaped and readers_stopped:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                failed.wait(min(_READ_POLL_SECONDS, remaining))

            if capture_error is not None or timed_out:
                cleaned = _cleanup_spawned_process(
                    proc,
                    pgid=pgid,
                    pipes=pipes,
                    threads=threads,
                    stop=stop,
                )
                late_error = next(
                    (state.error for state in states if state.error is not None),
                    None,
                )
                if capture_error is not None or late_error is not None:
                    raise RunnerError("subprocess output capture failed") from (
                        capture_error or late_error
                    )
                if not cleaned:
                    raise RunnerError("subprocess cleanup did not complete")
            else:
                if not _join_readers(threads, deadline=deadline):
                    cleaned = _cleanup_spawned_process(
                        proc,
                        pgid=pgid,
                        pipes=pipes,
                        threads=threads,
                        stop=stop,
                    )
                    if not cleaned:
                        raise RunnerError("subprocess cleanup did not complete")
                    timed_out = True
                else:
                    for pipe in pipes:
                        pipe.close()

            return CommandResult(
                exit_code=None if timed_out else proc.returncode,
                stdout=bytes(stdout_state.data),
                stderr=bytes(stderr_state.data),
                duration_ms=int((time.monotonic() - start) * 1000),
                timed_out=timed_out,
                truncated=stdout_state.truncated or stderr_state.truncated,
            )
        finally:
            shutil.rmtree(home, ignore_errors=True)
