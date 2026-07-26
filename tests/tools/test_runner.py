"""Policy-free CommandRunner: argv arrays only, never a shell."""

import gc
import os
import signal
import subprocess
import sys
import threading
import time

import pytest

import hackbot.tools.runner as runner_module
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


def test_capture_fd_extends_partial_prefix_from_original_chunk_view(monkeypatch):
    payload = b"abcdef"
    observed: list[object] = []

    class RecordingBuffer:
        def __len__(self):
            return 0

        def extend(self, value):
            observed.append(value)
            assert isinstance(value, memoryview)
            assert value.obj is payload
            assert bytes(value) == b"ab"

    reads = iter((payload, b""))
    monkeypatch.setattr(os, "read", lambda fd, size: next(reads))
    read_fd, write_fd = os.pipe()
    read_pipe = os.fdopen(read_fd, "rb", buffering=0)
    state = _CaptureState()
    state.data = RecordingBuffer()
    try:
        _capture_fd(
            read_pipe.fileno(),
            pipe=read_pipe,
            cap=2,
            stop=threading.Event(),
            failed=threading.Event(),
            state=state,
        )
    finally:
        read_pipe.close()
        os.close(write_fd)

    assert len(observed) == 1


def test_capture_fd_releases_previous_chunk_before_next_read(monkeypatch):
    released: list[int] = []
    read_number = 0

    class TrackedPayload(bytes):
        def __new__(cls, value, generation):
            instance = super().__new__(cls, value)
            instance.generation = generation
            return instance

        def __del__(self):
            released.append(self.generation)

    def read_generation(fd, size):
        nonlocal read_number
        read_number += 1
        if read_number == 1:
            return TrackedPayload(b"abcd", 1)
        gc.collect()
        assert released == [1]
        return b""

    monkeypatch.setattr(os, "read", read_generation)
    read_fd, write_fd = os.pipe()
    read_pipe = os.fdopen(read_fd, "rb", buffering=0)
    try:
        _capture_fd(
            read_pipe.fileno(),
            pipe=read_pipe,
            cap=2,
            stop=threading.Event(),
            failed=threading.Event(),
            state=_CaptureState(),
        )
    finally:
        read_pipe.close()
        os.close(write_fd)


def test_captures_stdout_and_zero_exit():
    result = CommandRunner().run(("/bin/echo", "hello"))
    assert isinstance(result, CommandResult)
    assert result.exit_code == 0
    assert result.stdout.strip() == b"hello"
    assert result.timed_out is False
    assert result.truncated is False


@pytest.mark.parametrize("timeout_seconds", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_timeout_fails_before_spawn(monkeypatch, timeout_seconds):
    def forbidden_popen(*args, **kwargs):
        pytest.fail("Popen must not be called for a non-finite timeout")

    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)

    with pytest.raises(RunnerError, match="positive"):
        CommandRunner(timeout_seconds=timeout_seconds).run(("/bin/echo", "no"))


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


def test_completion_observed_after_deadline_is_timeout(monkeypatch):
    readers_done = threading.Event()
    done_lock = threading.Lock()
    done_count = 0
    started_readers: list[threading.Thread] = []
    clock_lock = threading.Lock()
    deadline_crossed = False
    expired_ticks = 0

    def finish_capture(*, fd, pipe, cap, stop, failed, state):
        nonlocal done_count
        state.done.set()
        with done_lock:
            done_count += 1
            if done_count == 2:
                readers_done.set()

    def controlled_monotonic():
        nonlocal expired_ticks
        with clock_lock:
            if not deadline_crossed:
                return 0.0
            expired_ticks += 1
            return 1.0 + expired_ticks / 10

    original_poll = subprocess.Popen.poll
    original_start = threading.Thread.start

    def record_reader_start(thread):
        started_readers.append(thread)
        original_start(thread)

    def poll_crossing_deadline(proc):
        nonlocal deadline_crossed
        result = original_poll(proc)
        if result is not None:
            assert readers_done.wait(timeout=1)
            assert len(started_readers) == 2
            for thread in started_readers:
                thread.join(timeout=1)
                assert thread.is_alive() is False
            with clock_lock:
                deadline_crossed = True
        return result

    monkeypatch.setattr("hackbot.tools.runner._capture_fd", finish_capture)
    monkeypatch.setattr(
        "hackbot.tools.runner.time.monotonic",
        controlled_monotonic,
    )
    monkeypatch.setattr(threading.Thread, "start", record_reader_start)
    monkeypatch.setattr(subprocess.Popen, "poll", poll_crossing_deadline)

    result = CommandRunner(timeout_seconds=0.5).run(("/usr/bin/true",))

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


def test_detached_descendant_pipes_preserve_leader_until_group_kill(
    monkeypatch,
    tmp_path,
):
    descendant_pid_path = tmp_path / "detached.pid"
    code = (
        "import pathlib, subprocess, sys; "
        "child = subprocess.Popen(['/bin/sleep', '5'], start_new_session=True); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
        "raise SystemExit(0)"
    )
    group_kill_started = threading.Event()
    early_polls: list[int] = []
    original_poll = subprocess.Popen.poll
    original_kill = runner_module._kill_process_group

    def record_poll(proc):
        if not group_kill_started.is_set():
            early_polls.append(proc.pid)
        return original_poll(proc)

    def record_group_kill(pgid):
        group_kill_started.set()
        original_kill(pgid)

    monkeypatch.setattr(subprocess.Popen, "poll", record_poll)
    monkeypatch.setattr(
        "hackbot.tools.runner._kill_process_group",
        record_group_kill,
    )

    try:
        result = CommandRunner(timeout_seconds=0.1).run(
            (sys.executable, "-c", code, str(descendant_pid_path))
        )
    finally:
        cleanup_deadline = time.monotonic() + 1
        while not descendant_pid_path.exists() and time.monotonic() < cleanup_deadline:
            time.sleep(0.01)
        if descendant_pid_path.exists():
            descendant_pid = int(descendant_pid_path.read_text())
            try:
                os.kill(descendant_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            reap_deadline = time.monotonic() + 1
            while time.monotonic() < reap_deadline:
                try:
                    os.kill(descendant_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                pytest.fail("detached descendant survived test cleanup")

    assert result.timed_out is True
    assert result.exit_code is None
    assert group_kill_started.is_set() is True
    assert early_polls == []


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


def test_second_reader_start_failure_cleans_first_reader_and_process(monkeypatch):
    spawned: list[subprocess.Popen] = []
    first_reader: list[threading.Thread] = []
    start_calls = 0
    original_popen = subprocess.Popen
    original_start = threading.Thread.start

    def record_popen(*args, **kwargs):
        proc = original_popen(*args, **kwargs)
        spawned.append(proc)
        return proc

    def fail_second_start(thread):
        nonlocal start_calls
        start_calls += 1
        if start_calls == 2:
            raise RuntimeError("synthetic second reader start failure")
        first_reader.append(thread)
        original_start(thread)

    monkeypatch.setattr(subprocess, "Popen", record_popen)
    monkeypatch.setattr(threading.Thread, "start", fail_second_start)

    started = time.monotonic()
    observed: dict[str, object] = {}
    try:
        with pytest.raises(RunnerError, match="capture"):
            CommandRunner(timeout_seconds=5).run(("/bin/sleep", "5"))
        observed["elapsed"] = time.monotonic() - started
        observed["first_reader_stopped"] = len(first_reader) == 1 and not first_reader[0].is_alive()
        observed["child_reaped"] = len(spawned) == 1 and spawned[0].poll() is not None
        observed["stdout_closed"] = (
            len(spawned) == 1 and spawned[0].stdout is not None and spawned[0].stdout.closed
        )
        observed["stderr_closed"] = (
            len(spawned) == 1 and spawned[0].stderr is not None and spawned[0].stderr.closed
        )
    finally:
        for proc in spawned:
            if proc.poll() is None:
                runner_module._kill_process_group(proc.pid)
                proc.wait(timeout=1)
            if proc.stdout is not None and not proc.stdout.closed:
                proc.stdout.close()
            if proc.stderr is not None and not proc.stderr.closed:
                proc.stderr.close()
        for thread in first_reader:
            thread.join(timeout=1)

    assert observed["elapsed"] < 2
    assert start_calls == 2
    assert observed["first_reader_stopped"] is True
    assert observed["child_reaped"] is True
    assert observed["stdout_closed"] is True
    assert observed["stderr_closed"] is True


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
    started_readers: list[threading.Thread] = []

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

    original_start = threading.Thread.start
    original_is_alive = threading.Thread.is_alive
    readers_released = False

    def record_reader_start(thread):
        started_readers.append(thread)
        original_start(thread)

    def release_failure_on_liveness_check(thread):
        nonlocal readers_released
        if not readers_released:
            readers_released = True
            release_readers.set()
            assert readers_done.wait(timeout=1)
            assert len(started_readers) == 2
            for started_reader in started_readers:
                started_reader.join(timeout=1)
                assert original_is_alive(started_reader) is False
        return original_is_alive(thread)

    monkeypatch.setattr("hackbot.tools.runner._capture_fd", fail_late)
    monkeypatch.setattr(threading.Thread, "start", record_reader_start)
    monkeypatch.setattr(
        threading.Thread,
        "is_alive",
        release_failure_on_liveness_check,
    )

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
