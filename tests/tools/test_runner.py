"""Policy-free CommandRunner: argv arrays only, never a shell."""

import os
import threading

import pytest

from hackbot.tools.runner import (
    CommandResult,
    CommandRunner,
    RunnerError,
    _capture_fd,
    _CaptureState,
)


def _capture_bytes(payload: bytes, *, cap: int) -> _CaptureState:
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    stop = threading.Event()
    failed = threading.Event()
    state = _CaptureState()
    thread = threading.Thread(
        target=_capture_fd,
        kwargs={
            "fd": read_fd,
            "cap": cap,
            "stop": stop,
            "failed": failed,
            "state": state,
        },
        daemon=True,
    )
    thread.start()
    try:
        view = memoryview(payload)
        while view:
            written = os.write(write_fd, view)
            view = view[written:]
    finally:
        os.close(write_fd)
    thread.join(timeout=1)
    os.close(read_fd)
    assert thread.is_alive() is False
    assert failed.is_set() is False
    return state


def test_capture_fd_keeps_exact_cap_without_truncation():
    state = _capture_bytes(b"abcd", cap=4)
    assert bytes(state.data) == b"abcd"
    assert state.truncated is False
    assert state.error is None
    assert state.done.is_set() is True


def test_capture_fd_keeps_prefix_and_marks_first_excess_byte():
    state = _capture_bytes(b"abcde", cap=4)
    assert bytes(state.data) == b"abcd"
    assert state.truncated is True


def test_capture_fd_drains_large_payload_without_growing_prefix():
    state = _capture_bytes(b"x" * (2 * 1024 * 1024), cap=257)
    assert bytes(state.data) == b"x" * 257
    assert len(state.data) == 257
    assert state.truncated is True


def test_capture_fd_honors_stop_on_an_open_empty_pipe():
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    stop = threading.Event()
    failed = threading.Event()
    state = _CaptureState()
    thread = threading.Thread(
        target=_capture_fd,
        kwargs={
            "fd": read_fd,
            "cap": 10,
            "stop": stop,
            "failed": failed,
            "state": state,
        },
        daemon=True,
    )
    thread.start()
    stop.set()
    thread.join(timeout=1)
    os.close(write_fd)
    os.close(read_fd)
    assert thread.is_alive() is False
    assert state.done.is_set() is True
    assert state.error is None


def test_capture_fd_records_os_error_and_signals_failure():
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    os.close(write_fd)
    stop = threading.Event()
    failed = threading.Event()
    state = _CaptureState()
    _capture_fd(
        read_fd,
        cap=10,
        stop=stop,
        failed=failed,
        state=state,
    )
    assert isinstance(state.error, OSError)
    assert failed.is_set() is True
    assert state.done.is_set() is True


def test_captures_stdout_and_zero_exit():
    result = CommandRunner().run(("/bin/echo", "hello"))
    assert isinstance(result, CommandResult)
    assert result.exit_code == 0
    assert result.stdout.strip() == b"hello"
    assert result.timed_out is False
    assert result.truncated is False


def test_argv_is_never_shell_interpreted():
    result = CommandRunner().run(("/bin/echo", "a; rm -rf /"))
    assert b"a; rm -rf /" in result.stdout


def test_environment_is_sanitized(monkeypatch):
    monkeypatch.setenv("HACKBOT_TEST_SECRET", "topsecret")
    result = CommandRunner().run(("/usr/bin/env",))
    assert b"HACKBOT_TEST_SECRET" not in result.stdout
    assert b"topsecret" not in result.stdout


def test_timeout_kills_process_group():
    result = CommandRunner(timeout_seconds=0.5).run(("/bin/sleep", "5"))
    assert result.timed_out is True
    assert result.exit_code is None
    assert result.duration_ms < 4000


def test_output_is_capped_and_marked_truncated():
    result = CommandRunner(output_cap_bytes=10).run(("/bin/echo", "x" * 1000))
    assert result.truncated is True
    assert len(result.stdout) <= 10


def test_missing_executable_fails_closed():
    with pytest.raises(RunnerError):
        CommandRunner().run(("/nonexistent/tool-xyz",))


def test_empty_argv_fails_closed():
    with pytest.raises(RunnerError):
        CommandRunner().run(())


def test_provides_an_ephemeral_home():
    result = CommandRunner().run(("/usr/bin/env",))
    out = result.stdout.decode()
    assert "HOME=" in out  # tools that need a config/cache dir get one
    real = os.environ.get("HOME", "")
    if real:
        assert f"HOME={real}\n" not in out  # never the operator's real HOME
