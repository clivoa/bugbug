# Streaming Output Caps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound `CommandRunner` memory while a subprocess is running by keeping
only a fixed prefix of each output stream and draining all excess bytes without
changing the public result contract, exit-code behavior, or timeout semantics.

**Architecture:** One private daemon reader thread owns each nonblocking pipe.
Each reader retains at most the configured cap, marks the first excess byte,
and keeps draining until EOF. The synchronous main thread monitors the child,
both readers, and one absolute deadline; timeout and failure paths kill the
captured process group and perform bounded cleanup before returning or failing
closed.

**Tech Stack:** Python 3.11+ standard library (`math`, `os`, `signal`,
`subprocess`, `threading`, `time`), pytest, Ruff, mypy, existing offline wheel
smoke test.

## Global Constraints

- Preserve `CommandRunner.run(argv) -> CommandResult` and every
  `CommandResult` field unchanged.
- Preserve `shell=False`, closed stdin, sanitized environment, ephemeral HOME,
  absolute executable validation, and `start_new_session=True`.
- Treat stdout and stderr as independent caps; do not add a combined cap.
- Retain the first `output_cap_bytes` exactly. Exactly the cap is not
  truncation; the next byte is.
- Do not append a marker and do not expose discarded bytes to audit, evidence,
  logging, hashing, parsing, or terminal output.
- Continue execution after either cap is exceeded and preserve the real child
  exit code.
- The configured timeout covers both direct-child execution and pipe EOF. A
  descendant holding an inherited pipe cannot create an unbounded wait.
- Normalize the timeout to `float` and reject non-finite or non-positive values
  before HOME creation or `Popen`.
- Partial prefix extension must use `memoryview(chunk)[:remaining]`; release the
  view and payload reference before the next `os.read`.
- Do not poll/reap the group leader while either reader is alive. Deadline or
  reader failure must kill the captured process group before any reap.
- Never call `Popen.communicate()`.
- Any reader/setup failure after spawn must kill the captured process group,
  perform bounded cleanup, remove the ephemeral HOME, and raise `RunnerError`.
- Close pipe objects only after their reader threads have stopped.
- Keep documentation claims and test counts tied to freshly run evidence.

---

## Task 1: Add the bounded per-stream capture primitive

**Files:**

- Modify: `src/hackbot/tools/runner.py`
- Modify: `tests/tools/test_runner.py`

**Produces:**

- `_CaptureState`, the private mutable state owned by one reader.
- `_capture_fd(...)`, the private nonblocking prefix-capture loop.

**Consumed later by:** Task 2's process lifecycle in `CommandRunner.run`.

- [ ] **Step 1: Write RED tests for exact cap, excess-byte detection, draining,
  stop, and reader failure**

Add these imports to `tests/tools/test_runner.py`:

```python
import threading

from hackbot.tools.runner import (
    _CaptureState,
    _capture_fd,
)
```

Add a local helper that gives each test real pipe and thread behavior:

```python
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
```

Add tests:

```python
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
```

Run:

```bash
.venv/bin/python -m pytest tests/tools/test_runner.py -q
```

Expected: collection/import failure because `_CaptureState` and `_capture_fd`
do not exist yet. Record the RED result in the implementation notes.

- [ ] **Step 2: Implement the smallest bounded reader that makes the tests
  pass**

In `src/hackbot/tools/runner.py`, add `threading`, import `field`, and define:

```python
import threading
from dataclasses import dataclass, field

_READ_CHUNK_BYTES = 64 * 1024
_READ_POLL_SECONDS = 0.01
_CLEANUP_GRACE_SECONDS = 1.0
_CLEANUP_STOP_SECONDS = 0.1


@dataclass(slots=True)
class _CaptureState:
    data: bytearray = field(default_factory=bytearray)
    truncated: bool = False
    error: OSError | None = None
    done: threading.Event = field(default_factory=threading.Event)


def _capture_fd(
    fd: int,
    *,
    pipe: BinaryIO,
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
                prefix_view = memoryview(chunk)[:remaining]
                try:
                    state.data.extend(prefix_view)
                finally:
                    prefix_view.release()
                    del prefix_view
            if len(chunk) > remaining:
                state.truncated = True
            del chunk
    except OSError as exc:
        state.error = exc
        failed.set()
    finally:
        state.done.set()
```

The temporary `chunk` is the one fixed-size read allowance beyond the retained
prefix. The required `pipe` argument keeps strong ownership of its FD for the
reader lifetime. The partial prefix is a zero-copy view, and both the view and
chunk reference are gone before the next read. No second payload `bytes` object
may be introduced.

- [ ] **Step 3: Run focused tests and static checks**

Run:

```bash
.venv/bin/python -m pytest tests/tools/test_runner.py -q
.venv/bin/ruff check src/hackbot/tools/runner.py tests/tools/test_runner.py
.venv/bin/ruff format --check src/hackbot/tools/runner.py tests/tools/test_runner.py
.venv/bin/mypy src/hackbot/tools/runner.py
```

Expected: all focused checks pass. If formatting is the only failure, run
`.venv/bin/ruff format` on the two files and repeat all four commands.

- [ ] **Step 4: Review ownership and bounded-memory invariants**

Confirm directly in the diff:

- only `_capture_fd` mutates `state.data`;
- `state.data` never grows beyond `cap`;
- `BlockingIOError` waits rather than spins;
- `OSError` always sets both `state.error` and `failed`;
- `state.done` is set in every exit path; and
- no pipe is closed inside `_capture_fd`.

- [ ] **Step 5: Commit the primitive**

```bash
git add src/hackbot/tools/runner.py tests/tools/test_runner.py
git commit -m "test: specify bounded stream capture"
```

---

## Task 2: Replace `communicate()` with deadline-bound streaming lifecycle

**Files:**

- Modify: `src/hackbot/tools/runner.py`
- Modify: `tests/tools/test_runner.py`

**Consumes:** `_CaptureState` and `_capture_fd` from Task 1.

**Produces:** The unchanged `CommandRunner.run()` public API with streaming
capture, real exit-code preservation, process-group timeout, and bounded
cleanup.

- [ ] **Step 1: Write RED integration tests for the approved public contract**

Add `subprocess`, `sys`, and `time` imports to `tests/tools/test_runner.py`.
Use `sys.executable` for Python child scripts.

Add:

```python
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
```

Strengthen the existing timeout test and add prefix retention:

```python
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
```

Add the inherited-pipe deadline regression:

```python
def test_descendant_holding_pipes_cannot_bypass_deadline():
    code = "import subprocess; subprocess.Popen(['/bin/sleep', '5']); raise SystemExit(0)"
    started = time.monotonic()
    result = CommandRunner(timeout_seconds=0.2).run((sys.executable, "-c", code))
    elapsed = time.monotonic() - started
    assert result.timed_out is True
    assert result.exit_code is None
    assert elapsed < 2
```

Run:

```bash
.venv/bin/python -m pytest tests/tools/test_runner.py -q
```

Expected: tests exposing post-exit truncation and `communicate()` usage fail.
Record the RED failures before implementation.

- [ ] **Step 2: Add private lifecycle helpers**

In `src/hackbot/tools/runner.py`, add:

```python
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
```

Add these exact helpers (also import `BinaryIO` from `typing`):

```python
from typing import BinaryIO


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
```

This uses exactly one one-second cleanup deadline, reserves its final 100 ms
for `stop` and joins, reaps the child only with bounded waits, and closes local
pipes only after every started reader has stopped. The variadic thread tuple
also covers failures after only one reader starts.

- [ ] **Step 3: Implement normal streaming execution**

Delete `_truncate`. Replace `CommandRunner.run()` with this implementation:

```python
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

        pipes = (proc.stdout, proc.stderr)
        stop = threading.Event()
        failed = threading.Event()
        stdout_state = _CaptureState()
        stderr_state = _CaptureState()
        states = (stdout_state, stderr_state)
        started_threads: list[threading.Thread] = []

        try:
            stdout_fd = _set_nonblocking(proc.stdout)
            stderr_fd = _set_nonblocking(proc.stderr)
            configured_threads = (
                threading.Thread(
                    target=_capture_fd,
                    kwargs={
                        "fd": stdout_fd,
                        "pipe": proc.stdout,
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
                        "pipe": proc.stderr,
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
            readers_stopped = all(not thread.is_alive() for thread in threads)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if readers_stopped:
                capture_error = next(
                    (state.error for state in states if state.error is not None),
                    None,
                )
                if capture_error is not None:
                    break
                if proc.poll() is not None:
                    if deadline - time.monotonic() <= 0:
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
```

Use the captured `pgid = proc.pid`; do not call `os.getpgid(proc.pid)` after the
leader may have exited. Normalize the constructor timeout once and require
`math.isfinite(timeout) and timeout > 0` before any HOME or subprocess work.

- [ ] **Step 4: Add RED tests for post-spawn setup and reader failures**

Add:

```python
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
```

For reader failure, monkeypatch the module-level `_capture_fd` with a test
double that records an `OSError`, sets `failed`, and always sets `done`. Patch
before constructing/running the runner:

```python
def test_reader_failure_kills_child_and_fails_closed(monkeypatch):
    def fail_capture(*, fd, cap, stop, failed, state):
        state.error = OSError("synthetic reader failure")
        failed.set()
        state.done.set()

    monkeypatch.setattr("hackbot.tools.runner._capture_fd", fail_capture)
    started = time.monotonic()
    with pytest.raises(RunnerError, match="capture"):
        CommandRunner(timeout_seconds=5).run(("/bin/sleep", "5"))
    assert time.monotonic() - started < 2
```

Run the focused test file and confirm these initially expose any missing
failure cleanup:

```bash
.venv/bin/python -m pytest tests/tools/test_runner.py -q
```

- [ ] **Step 5: Make failure cleanup tests GREEN**

Normalize all failures after `Popen` into safe `RunnerError` messages that do
not embed child output or environment values. Ensure:

- setup failure handles zero or one started reader;
- reader failure checks both states after joining;
- `ProcessLookupError` and `PermissionError` from `killpg` do not mask the
  original failure;
- pipe objects remain open until every started reader is stopped; and
- HOME cleanup runs in all cases.

- [ ] **Step 6: Run focused regression and static gates**

```bash
.venv/bin/python -m pytest tests/tools/test_runner.py -q -ra
.venv/bin/python -m pytest tests/tools/test_adapter.py tests/tools/test_remote.py \
  tests/audit tests/evidence -q -ra
.venv/bin/ruff check src/hackbot/tools/runner.py tests/tools/test_runner.py
.venv/bin/ruff format --check src/hackbot/tools/runner.py tests/tools/test_runner.py
.venv/bin/mypy src/hackbot/tools/runner.py
git diff --check
```

Expected: all pass. Repeat the timeout and inherited-pipe tests at least five
times to detect timing flakes:

```bash
for run_number in 1 2 3 4 5; do
  .venv/bin/python -m pytest tests/tools/test_runner.py \
    -k 'timeout or descendant_holding_pipes' -q || exit 1
done
```

- [ ] **Step 7: Review the lifecycle against the approved failure matrix**

Inspect every path:

| Path | Group kill | Bounded join/reap | Result |
|---|---:|---:|---|
| normal child exit + both EOF | no | yes | real exit code |
| output exceeds cap | no | yes | real exit code, truncated |
| deadline before child/EOF | yes | yes | timed out, exit code `None` |
| child exits, descendant holds pipe | yes at deadline | yes | timed out |
| pipe setup fails | yes | yes | `RunnerError` |
| reader raises `OSError` | yes | yes | `RunnerError` |
| reader cannot stop | yes | attempted for one deadline | `RunnerError` |
| second reader fails to start | yes | yes, including first reader | `RunnerError` |

Search for forbidden old behavior:

```bash
rg -n "communicate\\(|def _truncate|\\.read\\(\\)" src/hackbot/tools/runner.py
```

Expected: no matches. `os.read` with `_READ_CHUNK_BYTES` is the only pipe-read
operation.

- [ ] **Step 8: Commit the lifecycle**

```bash
git add src/hackbot/tools/runner.py tests/tools/test_runner.py
git commit -m "feat: stream capped subprocess output"
```

---

## Task 3: Document semantics, refresh roadmap, and prove all gates

**Files:**

- Modify: `docs/tool-execution.md`
- Modify: `README.md`
- Modify: `docs/next-steps.md`
- Modify only if fresh collection finds another current-count reference:
  documentation returned by `rg`

**Consumes:** The implemented and focused-tested runner from Task 2.

**Produces:** Operator-facing semantics, roadmap state, and reproducible final
verification evidence.

- [ ] **Step 1: Document the new capture and timeout semantics**

In `docs/tool-execution.md`, replace the current byte-cap bullet with language
that explicitly states:

- stdout and stderr are drained concurrently while the child runs;
- each stream retains only its first configured byte prefix;
- excess bytes are discarded, never persisted or interpreted;
- exactly the cap is not truncation, while any additional byte sets the
  combined `truncated=True`;
- exceeding a cap does not kill the tool or replace its real exit code; and
- timeout covers both process execution and inherited pipe EOF, kills the
  launch-time process group, and may include at most one second of cleanup plus
  scheduler overhead.

Do not claim that `CommandRunner` itself performs policy decisions.

- [ ] **Step 2: Update roadmap state**

In `docs/next-steps.md`:

- mark streaming output caps implemented;
- move it from numbered future work into the completed status paragraph;
- promote “Reviewed recon skills / internal-recon” to item 1;
- retain the rule that internal-recon stays disabled without a confirmed,
  explicitly authorized internal profile; and
- leave provider gateway/MCP after that decision.

In `README.md`, update the execution-substrate summary to say output caps are
enforced during streaming capture.

- [ ] **Step 3: Run the complete verification suite and capture fresh counts**

```bash
.venv/bin/python -m pytest tests -q -ra
.venv/bin/python -m pytest tests --collect-only -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
bash scripts/smoke_test.sh
git diff --check
```

Expected: no failures; one environment-dependent nmap skip remains acceptable
only if the output identifies it as the known skip. The collected/passed counts
must come from these commands, not from the pre-feature baseline.

- [ ] **Step 4: Refresh every current test-count claim**

Find current claims:

```bash
rg -n "[0-9]+ (automated tests|tests passing|collected|pass|passing)" \
  README.md docs --glob '*.md'
```

Update only present-tense project status references (`README.md` and
`docs/next-steps.md`, plus any other clearly current status page) to the fresh
collection/pass/skip evidence. Historical specs and plans remain historical.

- [ ] **Step 5: Perform acceptance and unfinished-marker scans**

```bash
rg -n "communicate\\(" src tests
rg -n "TO[D]O|TB[D]|FIX[M]E|implement[ ]later|coming[ ]soon" \
  src/hackbot/tools/runner.py tests/tools/test_runner.py \
  docs/tool-execution.md README.md docs/next-steps.md
git diff --check
git status --short
```

Acceptance requires:

- no production or test path depends on `Popen.communicate()`;
- no unfinished implementation markers were introduced;
- public `CommandResult` annotations are unchanged;
- evidence/audit/remote/adapter tests remain green; and
- the only intended modified files are visible.

Treat pre-existing unrelated license markers in project metadata or historical
documents as out of scope; do not silently edit them.

- [ ] **Step 6: Commit documentation and verified counts**

```bash
git add docs/tool-execution.md README.md docs/next-steps.md
git commit -m "docs: explain streaming output caps"
```

- [ ] **Step 7: Run verification again from the committed tree**

```bash
.venv/bin/python -m pytest tests -q -ra
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
bash scripts/smoke_test.sh
git diff --check
git status --short --branch
```

Expected: all gates pass and the branch is clean.

---

## Task 4: Independent review, remediation, and local integration

**Files:** Any Task 1–3 file only when a review finding is demonstrated against
the approved design.

- [ ] **Step 1: Request independent spec-compliance review**

The reviewer must compare the implementation against:

- `docs/superpowers/specs/2026-07-26-streaming-output-caps-design.md`
- this plan
- `src/hackbot/tools/runner.py`
- `tests/tools/test_runner.py`
- operator-facing documentation

Required review questions:

1. Can any output path grow without the configured prefix bound plus one fixed
   read chunk?
2. Can stdout/stderr production deadlock the child?
3. Can direct-child exit or an inherited pipe bypass the original deadline?
4. Can any failure leave a child/process group or reader thread running?
5. Can pipe closure race a reader?
6. Are exit code, timeout, truncation, audit, and evidence contracts unchanged?
7. Are all failure branches tested with demonstrated behavior?

- [ ] **Step 2: Request independent security/robustness review**

Review specifically:

- process-group identity captured at launch;
- `SIGKILL` failure handling;
- bounded cleanup arithmetic;
- partial thread startup;
- file-descriptor lifecycle;
- event/thread visibility assumptions;
- exception chaining and secret-free messages;
- timing-test flake risk; and
- compatibility with Python 3.11+ and POSIX systems.

- [ ] **Step 3: Reproduce and remediate demonstrated findings with TDD**

For every valid finding:

1. add or strengthen a test that fails for the demonstrated issue;
2. run it and record RED;
3. make the smallest implementation correction;
4. run GREEN plus the relevant regression group;
5. commit with a focused `fix:` message.

Do not implement speculative scope expansion. Document rejected findings with
the concrete evidence that makes them inapplicable.

- [ ] **Step 4: Apply verification-before-completion**

Run the complete Task 3 Step 7 gate set once more after the final review fix.
Inspect `git log --oneline main..HEAD`, `git diff --stat main...HEAD`, and
`git status --short --branch`. Claims of completion must cite this fresh run.

- [ ] **Step 5: Merge locally into `main`**

After all gates pass:

```bash
git switch main
git merge --no-ff feat/streaming-output-caps -m "Merge streaming output caps"
```

Run the complete gates on the merge commit. Only after that evidence is green:

```bash
git branch -d feat/streaming-output-caps
```

If the implementation used an isolated worktree, remove that exact worktree
only after confirming it is clean and the merge commit is verified.

- [ ] **Step 6: Document the integration result and advance the roadmap**

Record:

- merge commit;
- exact pass/skip/collection counts;
- Ruff, format, mypy, smoke, and diff-check results;
- deleted branch/worktree state;
- demonstrated review findings and their fix commits; and
- the next roadmap item: the guarded internal-recon authorization decision.

No internal-recon execution or enablement is authorized by this plan; the next
step begins with a separate design/authorization review.
