"""Policy-free CommandRunner: argv arrays only, never a shell."""

import gc
import os
import subprocess
import sys
import threading
import time

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
    read_pipe = os.fdopen(read_fd, "rb", buffering=0)
    os.set_blocking(read_pipe.fileno(), False)
    stop = threading.Event()
    failed = threading.Event()
    state = _CaptureState()
    thread = threading.Thread(
        target=_capture_fd,
        kwargs={
            "fd": read_pipe.fileno(),
            "pipe": read_pipe,
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
    read_pipe.close()
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
    read_pipe = os.fdopen(read_fd, "rb", buffering=0)
    os.set_blocking(read_pipe.fileno(), False)
    stop = threading.Event()
    failed = threading.Event()
    state = _CaptureState()
    thread = threading.Thread(
        target=_capture_fd,
        kwargs={
            "fd": read_pipe.fileno(),
            "pipe": read_pipe,
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
    read_pipe.close()
    assert thread.is_alive() is False
    assert state.done.is_set() is True
    assert state.error is None


def test_capture_fd_records_os_error_and_signals_failure():
    read_fd, write_fd = os.pipe()
    read_pipe = os.fdopen(read_fd, "rb", buffering=0)
    closed_fd = read_pipe.fileno()
    read_pipe.close()
    os.close(write_fd)
    stop = threading.Event()
    failed = threading.Event()
    state = _CaptureState()
    _capture_fd(
        closed_fd,
        pipe=read_pipe,
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
    assert 400 <= result.duration_ms < 2000


def test_timeout_retains_output_prefix():
    code = "import os, time; os.write(1, b'before-timeout'); time.sleep(5)"
    result = CommandRunner(
        timeout_seconds=0.2,
        output_cap_bytes=128,
    ).run((sys.executable, "-c", code))
    assert result.stdout == b"before-timeout"
    assert result.timed_out is True
    assert result.exit_code is None


def test_output_is_capped_and_marked_truncated():
    result = CommandRunner(output_cap_bytes=10).run(("/bin/echo", "x" * 1000))
    assert result.truncated is True
    assert len(result.stdout) <= 10


def test_exact_cap_is_not_marked_truncated():
    result = CommandRunner(output_cap_bytes=4).run(
        (sys.executable, "-c", "import os; os.write(1, b'abcd')")
    )
    assert result.stdout == b"abcd"
    assert result.truncated is False


def test_first_byte_over_cap_is_marked_truncated():
    result = CommandRunner(output_cap_bytes=4).run(
        (sys.executable, "-c", "import os; os.write(1, b'abcde')")
    )
    assert result.stdout == b"abcd"
    assert result.truncated is True


def test_large_stdout_and_stderr_are_drained_independently():
    code = (
        "import os\n"
        "for _ in range(128):\n"
        "    os.write(1, b'o' * 65536)\n"
        "    os.write(2, b'e' * 65536)\n"
    )
    result = CommandRunner(
        timeout_seconds=5,
        output_cap_bytes=4096,
    ).run((sys.executable, "-c", code))
    assert result.exit_code == 0
    assert result.stdout == b"o" * 4096
    assert result.stderr == b"e" * 4096
    assert result.truncated is True
    assert result.timed_out is False


def test_excess_output_is_discarded_without_changing_exit_code():
    code = "import os; os.write(1, b'x' * 1048576); raise SystemExit(7)"
    result = CommandRunner(
        timeout_seconds=5,
        output_cap_bytes=32,
    ).run((sys.executable, "-c", code))
    assert result.exit_code == 7
    assert result.stdout == b"x" * 32
    assert result.truncated is True
    assert result.timed_out is False


def test_runner_never_calls_communicate(monkeypatch):
    def forbidden_communicate(*args, **kwargs):
        pytest.fail("CommandRunner must not call Popen.communicate")

    monkeypatch.setattr(subprocess.Popen, "communicate", forbidden_communicate)
    result = CommandRunner().run(("/bin/echo", "streamed"))
    assert result.stdout.strip() == b"streamed"


def test_descendant_holding_pipes_cannot_bypass_deadline():
    code = "import subprocess; subprocess.Popen(['/bin/sleep', '5']); raise SystemExit(0)"
    started = time.monotonic()
    result = CommandRunner(timeout_seconds=0.2).run((sys.executable, "-c", code))
    elapsed = time.monotonic() - started
    assert result.timed_out is True
    assert result.exit_code is None
    assert elapsed < 2


def test_nonblocking_setup_failure_fails_closed(monkeypatch):
    def fail_set_nonblocking(pipe):
        raise OSError("synthetic set_blocking failure")

    monkeypatch.setattr(
        "hackbot.tools.runner._set_nonblocking",
        fail_set_nonblocking,
    )
    started = time.monotonic()
    with pytest.raises(RunnerError, match="capture"):
        CommandRunner(timeout_seconds=5).run(("/bin/sleep", "5"))
    assert time.monotonic() - started < 2


def test_reader_failure_kills_child_and_fails_closed(monkeypatch):
    def fail_capture(*, fd, pipe, cap, stop, failed, state):
        state.error = OSError("synthetic reader failure")
        failed.set()
        state.done.set()

    monkeypatch.setattr("hackbot.tools.runner._capture_fd", fail_capture)
    started = time.monotonic()
    with pytest.raises(RunnerError, match="capture"):
        CommandRunner(timeout_seconds=5).run(("/bin/sleep", "5"))
    assert time.monotonic() - started < 2


def test_reader_failure_after_last_failed_check_fails_closed(monkeypatch):
    release_readers = threading.Event()
    readers_done = threading.Event()
    done_lock = threading.Lock()
    done_count = 0

    def fail_late(*, fd, pipe, cap, stop, failed, state):
        nonlocal done_count
        assert release_readers.wait(timeout=1)
        state.error = OSError("synthetic late reader failure")
        failed.set()
        state.done.set()
        with done_lock:
            done_count += 1
            if done_count == 2:
                readers_done.set()

    original_poll = subprocess.Popen.poll

    def poll_after_readers_fail(proc):
        result = original_poll(proc)
        if result is not None:
            release_readers.set()
            assert readers_done.wait(timeout=1)
        return result

    monkeypatch.setattr("hackbot.tools.runner._capture_fd", fail_late)
    monkeypatch.setattr(subprocess.Popen, "poll", poll_after_readers_fail)

    with pytest.raises(RunnerError, match="capture"):
        CommandRunner(timeout_seconds=2).run(("/usr/bin/true",))


def test_unjoined_readers_keep_pipe_fds_alive_after_runner_unwinds(monkeypatch):
    release_readers = threading.Event()
    readers_done = threading.Event()
    done_lock = threading.Lock()
    done_count = 0
    fd_errors: list[OSError] = []

    def hold_capture(*, fd=None, pipe=None, cap, stop, failed, state):
        nonlocal done_count
        target_fd = pipe.fileno() if pipe is not None else fd
        assert target_fd is not None
        release_readers.wait(timeout=3)
        try:
            os.fstat(target_fd)
        except OSError as exc:
            fd_errors.append(exc)
        finally:
            state.done.set()
            with done_lock:
                done_count += 1
                if done_count == 2:
                    readers_done.set()

    monkeypatch.setattr("hackbot.tools.runner._capture_fd", hold_capture)

    try:
        with pytest.raises(RunnerError, match="cleanup") as caught:
            CommandRunner(timeout_seconds=0.01).run(("/bin/sleep", "5"))
        del caught
        gc.collect()
    finally:
        release_readers.set()

    assert readers_done.wait(timeout=1)
    assert fd_errors == []


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
