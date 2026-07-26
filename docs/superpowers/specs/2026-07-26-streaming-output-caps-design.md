# Streaming subprocess output caps — design

**Status:** approved (2026-07-26), safety amendments incorporated

**Goal:** Make `CommandRunner` enforce its existing per-stream byte caps while
the child is running, so `stdout` and `stderr` cannot accumulate without bound
in memory before timeout or process exit.

**Non-goals:** No live terminal output, kill-on-cap behavior, combined
stdout/stderr cap, new `CommandResult` fields, changes to audit/evidence/CLI,
`asyncio`, shell execution, or Windows-specific support.

## Context

`src/hackbot/tools/runner.py` currently launches a code-owned argv array with
`subprocess.Popen`, captures both pipes through `communicate()`, and truncates
the complete byte strings afterward. The returned result is capped, but the
process can make the parent buffer arbitrarily large output before the cap is
applied.

The current public contract must stay stable:

```python
CommandResult(
    exit_code: int | None,
    stdout: bytes,
    stderr: bytes,
    duration_ms: int,
    timed_out: bool,
    truncated: bool,
)
```

`stdout` and `stderr` each have their own `output_cap_bytes` allowance.
Audit and evidence record the retained prefixes and the combined
`truncated` boolean. Remote execution, adapters, and the CLI all consume this
same object and require no interface changes.

## Chosen approach

Use two private reader threads, one per pipe, while keeping
`CommandRunner.run()` synchronous.

Each reader:

1. reads fixed-size chunks from one nonblocking pipe;
2. appends only the bytes that fit in its bounded prefix buffer through a
   `memoryview` of the original chunk, without allocating a sliced `bytes`
   payload;
3. sets its truncation flag on the first excess byte; and
4. releases the view and chunk references before the next `os.read`, then
   continues reading and discarding subsequent bytes until EOF.

This avoids the classic deadlock where a child fills one pipe while the parent
waits on the other. It is also simpler and more locally testable than a
single-threaded `selectors` state machine, while avoiding the event-loop
integration cost of `asyncio.subprocess`.

Rejected alternatives:

- **POSIX selectors:** viable on the supported operating systems, but requires
  more state for pipe readiness, child exit, deadline, and cleanup.
- **`asyncio.subprocess`:** changes a synchronous core API and introduces an
  event loop with no benefit to current callers.
- **Kill on cap:** changes exit-code semantics and tool behavior. The approved
  behavior is to keep executing while discarding excess bytes.

## Compatibility contract

- The first `output_cap_bytes` from each stream are retained byte-for-byte.
- No textual truncation marker is appended.
- Exactly the cap is not truncated; the first additional byte sets
  `truncated=True`.
- `CommandResult.truncated` is true when either stream exceeds its own cap.
- A process that exceeds a cap continues to completion and retains its real
  exit code.
- A timeout still returns `exit_code=None` and `timed_out=True`.
- Timeout configuration must normalize to a finite positive float; `NaN` and
  either infinity fail closed before HOME creation or process spawn.
- Non-zero child exits remain ordinary `CommandResult` values.
- Environment sanitization, ephemeral HOME, `shell=False`, closed stdin,
  absolute executable validation, and process-group isolation stay unchanged.

## Components

### Per-stream capture state

Add a private mutable state object in `runner.py`, owned by exactly one reader
thread:

- a `bytearray` containing at most the configured cap;
- `truncated: bool`;
- `error: OSError | None`; and
- an EOF/completion signal.

No lock is needed for the buffer itself because only its reader thread mutates
it and the main thread consumes it only after a successful join. Thread events
coordinate failure, stop, and completion.

### Reader loop

Each `Popen` pipe is switched to nonblocking mode. A reader repeatedly calls
`os.read(fd, 64 * 1024)`:

- bytes within the remaining allowance extend the prefix buffer;
- a partial prefix is passed to `bytearray.extend` as
  `memoryview(chunk)[:remaining]`, then both view and chunk references are
  explicitly released before the next read;
- any bytes beyond the allowance are discarded and mark truncation;
- `BlockingIOError` waits briefly on the shared stop event instead of spinning;
- `b""` marks EOF and normal completion; and
- any other `OSError` is recorded and signals reader failure.

Nonblocking descriptors ensure a reader can honor cleanup/stop requests even
if a malformed or detached descendant keeps the write end open.

### Main lifecycle

`CommandRunner.run()`:

1. validates a finite positive timeout and argv before creating the per-run
   HOME;
2. records a monotonic start time and absolute deadline;
3. starts `Popen` with its existing safety flags;
4. records the new session's process-group ID immediately (the group leader is
   `proc.pid` because `start_new_session=True`);
5. starts one daemon reader thread per pipe;
6. monitors reader failure and both pipe EOFs under the absolute deadline
   without polling/reaping the direct child while either reader is alive;
7. when both readers have stopped, rechecks reader errors and the deadline,
   then polls the direct child with a second deadline check before accepting
   normal completion; and
8. on timeout or reader failure, kills the captured process group before any
   child reap, then returns only after bounded cleanup.

The monitoring interval is bounded and small (10 ms maximum); it never replaces
the configured deadline with a new unbounded wait.

### Timeout and cleanup

The configured timeout covers both child execution and pipe draining. This
matters when a direct child exits but a descendant retains an inherited pipe.

When the deadline expires:

1. set `timed_out=True`;
2. send `SIGKILL` to the process group recorded at launch;
3. only after that group kill, poll/wait the still-unreaped direct child;
4. open a single one-second cleanup deadline;
5. reserve the final 100 ms of that deadline for forced reader shutdown;
6. until then, allow readers to consume already available bytes and reach EOF;
7. signal any remaining readers to stop and require them to join within the
   reserved 100 ms; and
8. close local pipe objects only after the readers have stopped.

The measured duration includes bounded cleanup and may therefore exceed the
configured timeout by at most the one-second cleanup deadline and scheduler
overhead.

If a reader fails, the same group-kill and bounded cleanup path runs, then
`RunnerError` is raised. If a reader remains alive after stop/cleanup,
`RunnerError` is raised rather than returning a partially trusted result.
The ephemeral HOME is removed in every path.

`ProcessLookupError` and `PermissionError` during group kill remain
best-effort cleanup cases; they do not mask the timeout or the original reader
failure.

Any failure after `Popen` but before both readers are fully running — obtaining
pipe descriptors, switching them to nonblocking mode, or starting a thread —
uses the same group-kill and bounded cleanup path, then raises `RunnerError`.

## Data flow

```text
validated argv
    → Popen(shell=False, new session, stdout/stderr pipes)
        ├─ stdout reader → prefix ≤ cap + discard remainder
        └─ stderr reader → prefix ≤ cap + discard remainder
    → process/pipe deadline monitor
        ├─ normal exit + both EOF → real exit code
        ├─ deadline → kill group → timed_out, exit_code=None
        └─ reader failure → kill group → RunnerError
    → CommandResult(prefixes, duration, timed_out, either-truncated)
```

Only the retained prefixes proceed to audit metadata, redaction, and evidence.
Discarded bytes are never hashed, logged, stored, printed, or interpreted.

## Error handling

- Empty argv or invalid executable: existing `RunnerError`, before spawn.
- `Popen` failure: existing safe `RunnerError`, without leaking child details.
- Reader `OSError`: kill/cleanup, then `RunnerError`.
- Deadline exceeded by process or inherited pipe: process-group kill and a
  timed-out result.
- Reader cannot terminate after bounded cleanup: `RunnerError`.
- Child exit non-zero: normal result with its real code.
- Output above either cap: normal result with retained prefix and
  `truncated=True`.

No failure path returns output that may still be mutating in another thread.

## Testing strategy

Implement test-first in `tests/tools/test_runner.py`.

### Cap semantics

- Exactly `cap` bytes on one stream: retained exactly, `truncated=False`.
- `cap + 1`: retained prefix equals the first `cap` bytes,
  `truncated=True`.
- Large stdout and stderr written in the same run with a small cap: both
  retained prefixes are bounded, no deadlock, combined flag true.
- Child writes far beyond the cap and exits with a non-zero code: runner
  continues draining/discarding and preserves that exact exit code.
- A focused monkeypatch makes `Popen.communicate()` fail if called, proving the
  old accumulation path is gone.
- Deterministic ownership tests prove partial extension receives a view of the
  original chunk and that the previous payload generation is released before
  the next `os.read`.

### Timeout and process groups

- `NaN`, positive infinity, and negative infinity are rejected before spawn.
- A child emits a prefix, flushes, then sleeps past the deadline: the prefix is
  retained, `timed_out=True`, and `exit_code=None`.
- A direct child launches a descendant that inherits the pipes and exits: the
  run still honors its deadline, kills the captured group, and returns without
  a stuck reader.
- A detached descendant that inherits the pipes proves the leader is not
  polled/reaped while readers remain alive and that group kill begins first.
- Failure to start the second reader proves bounded cleanup stops the first
  reader, reaps the child, and closes both pipes.
- Existing timeout duration remains bounded.

### Regression

Keep existing tests green for:

- stdout capture and zero exit;
- literal shell metacharacters;
- sanitized environment;
- ephemeral HOME;
- invalid executable and empty argv; and
- remote/adaptor/audit/evidence consumers of `CommandResult`.

Then run the full project suite, Ruff check, Ruff format check, mypy, offline
wheel smoke, and `git diff --check`.

## Documentation and roadmap

Update:

- `docs/tool-execution.md` with streaming prefix capture, discard semantics,
  separate caps, deadline coverage, and the unchanged public result;
- `README.md` status text and verified test count;
- `docs/next-steps.md` to mark streaming output caps complete and promote the
  guarded internal-recon decision to the next item; and
- any stale test-count references found by the final collection.

## Acceptance criteria

1. No code path calls `Popen.communicate()`.
2. At most one configured prefix plus one fixed read chunk is held per stream
   by the capture layer; partial append uses a zero-copy view and releases both
   the view and payload reference before the next read.
3. Excess output is drained and discarded until EOF or timeout.
4. Exit codes and timeout semantics match the existing public contract.
5. Caps remain separate for stdout and stderr.
6. Both pipes can produce large output without deadlock.
7. Direct-child exit cannot bypass the deadline while a descendant holds a
   pipe open.
8. Timeout kills the captured process group before the leader is reaped; the
   normal monitor does not poll the leader until both readers stop.
9. Reader failures, partial reader startup, and stuck cleanup fail closed with
   `RunnerError`.
10. Audit, evidence, remote execution, adapters, and CLI require no interface
   changes.
11. All regression gates pass and published counts match fresh evidence.
