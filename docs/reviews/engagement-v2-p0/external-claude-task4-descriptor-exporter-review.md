# Security review (read-only) — engagement-v2 schema exporter

Scope: `scripts/export_engagement_v2_schemas.py`, supported by
`src/hackbot/engagement_v2/schemas.py`, `tests/engagement_v2/test_schemas.py`,
and `.superpowers/sdd/2026-07-26-engagement-v2-security-contracts/task-4-report.md`.
Worktree: `.worktrees/engagement-v2-security-contracts`. No file was edited; no
offensive/destructive command was executed.

---

## Verdict

The previous review's confirmation stands: **all of the exporter's symlink
defenses are path-based (`lstat` via `Path.is_symlink`) and are re-resolved by
path at the moment of use** (`tempfile.mkstemp(dir=...)`,
`os.replace(temporary, target)`, `path.read_bytes()`, `os.open(destination)`).
Between the check and the use there is a classic TOCTOU window: a path
component (typically the `destination` directory itself, or a parent) can be
swapped for a symlink after the check and before the operation. **There is not
a single `O_NOFOLLOW`, nor a single `dir_fd`-relative operation, anywhere in
the file.**

Under the normal configuration — `SCHEMA_ROOT` derived from
`Path(__file__).resolve()` under an operator-owned repository — exploitability
is low (it requires a writable, hostile parent directory). But this task's
contract is *drift-proof and symlink-safe*, and the current guarantee is
probabilistic (window width), not structural. **I recommend reimplementing
write and `--check` with descriptor-pinned directories (chained `openat` with
`O_DIRECTORY|O_NOFOLLOW`), `dir_fd`-relative operations, `os.replace` with
`src_dir_fd/dst_dir_fd`, and `fsync` of the directory fd**, with **strict
fail-closed** behavior when the platform doesn't offer `dir_fd`/`O_NOFOLLOW`.

Beyond the TOCTOU, I found two functional security gaps that the TOCTOU had
obscured: **`--check` does not detect extra files** and **write does not
remove stale files** — meaning an injected schema file passes the drift gate
unnoticed.

Aggregate severity: **1 Critical, 3 Important, 4 Minor.** Nothing blocks use
as a local dev/CI tool, but the Critical finding should be fixed before any
run against a destination directory that isn't exclusively trusted.

---

## Recommended design (the smallest safe design)

Principle: **pin the destination directory's inode to a descriptor and never
touch the path by string again.** Once `dir_fd` points at the real inode, any
later swap of the *name* `schemas/engagement-v2` for a symlink has no effect —
writes keep going to the pinned inode.

Constraints respected: Python 3.11+, zero runtime dependencies, stdlib
(`os`) only. `tempfile.mkstemp` **does not** accept `dir_fd`, so the temporary
file is created by hand with
`os.open(..., O_CREAT|O_EXCL|O_NOFOLLOW, 0o600, dir_fd=...)` and a random
suffix from `secrets.token_hex` (stdlib).

### 1. Capability gate (fail-closed, once, at the start of `main`)

```python
_REQUIRED_DIR_FD = (os.open, os.mkdir, os.replace, os.unlink, os.stat)

def _require_secure_fs() -> None:
    missing = [name for name in ("O_DIRECTORY", "O_NOFOLLOW")
               if not hasattr(os, name)]
    if missing or not all(fn in os.supports_dir_fd for fn in _REQUIRED_DIR_FD) \
       or os.listdir not in os.supports_fd:
        raise RuntimeError(
            "refusing to run: platform lacks O_NOFOLLOW/dir_fd support "
            "required for symlink-safe schema export"
        )
```

Key point: **remove today's `getattr(os, "O_DIRECTORY", 0)`** (line 89). That
silent fallback is the opposite of fail-closed.

### 2. Pin the path by component (chained openat)

`SCHEMA_ROOT` = `REPOSITORY_ROOT / "schemas" / "engagement-v2"`.
`REPOSITORY_ROOT` is already canonicalized by `.resolve()` at import time, so
it is the trust root. Opening each relative component below it with
`O_NOFOLLOW|O_DIRECTORY` eliminates a symlink at *any* component, and the
parent TOCTOU:

```python
def _open_pinned_dir(root_fd: int, name: str, *, create: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=root_fd)      # ELOOP if symlink
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(name, 0o700, dir_fd=root_fd)
        return os.open(name, flags, dir_fd=root_fd)
```

Chain `schemas` → `engagement-v2` starting from an fd opened on
`REPOSITORY_ROOT`. `O_NOFOLLOW` makes `open` fail with `ELOOP` if the final
component is a symlink; `O_DIRECTORY` guarantees it is a directory (or
`ENOTDIR`). Translate `ELOOP`/`ENOTDIR`/`FileExistsError` into
`RuntimeError("symlink destination rejected: ...")` to preserve the
already-tested message contract.

### 3. Atomic write relative to the pinned fd

```python
def _write_one(dir_fd: int, name: str, content: bytes) -> None:
    tmp = f".{name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=dir_fd)
    try:
        os.fchmod(fd, 0o600)          # keep: O_CREAT mode is subject to umask
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp, dir_fd=dir_fd)
        raise
    finally:
        pass
os.fsync(dir_fd)   # once, after all replaces
```

`O_EXCL` prevents following/reusing a planted temporary file. `os.replace`
with both `src_dir_fd`/`dst_dir_fd` performs a `renameat` within the pinned
inode — the parent is not re-resolved by path, and `rename(2)` does not follow
a symlink at the final destination component. `fsync(dir_fd)` makes the
renames durable.

### 4. Prune stale/extra files (write)

After writing the expected set, list the directory via the fd and remove
anything that doesn't belong — otherwise an injected schema survives
re-exports:

```python
expected = set(rendered)
for entry in os.listdir(dir_fd):
    if entry not in expected and not entry.endswith(".tmp"):
        os.unlink(entry, dir_fd=dir_fd)   # or report and fail, see decision
```

Product decision: prune automatically **or** refuse with an error. For a
*drift-proof* tool I would recommend pruning on write and **reporting it as
drift** in `--check` (see §5) — but that's a contract choice; I'm flagging it,
not deciding it.

### 5. `--check` with zero writes

Same pin, but it **never** creates the directory, never opens with a write
flag, never calls `mkstemp`/`replace`/`fsync`:

```python
def _check(root_fd) -> tuple[str, ...]:
    try:
        dir_fd = _open_pinned_dir(root_fd, "engagement-v2", create=False)
    except FileNotFoundError:
        return tuple(sorted(rendered))          # everything is drift, don't create
    # ELOOP -> RuntimeError (symlink) propagates
    drifted = []
    present = set(os.listdir(dir_fd))
    for name, expected in sorted(rendered.items()):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError:                          # ELOOP/ENOENT -> drift
            drifted.append(name); continue
        with os.fdopen(fd, "rb") as s:
            if s.read() != expected:
                drifted.append(name)
    drifted += sorted(present - set(rendered) - {n for n in present if n.endswith(".tmp")})
    return tuple(drifted)
```

`O_RDONLY|O_NOFOLLOW` on the read closes the symlink-redirection hole that the
current read (`path.read_bytes()`, which **follows** symlinks) leaves open.

---

## Platform matrix

| Capability | Linux | macOS (darwin) | General POSIX (BSD/Solaris) | Windows |
|---|---|---|---|---|
| `os.O_NOFOLLOW` | ✔ | ✔ | ✔ | **absent** |
| `os.O_DIRECTORY` | ✔ | ✔ | ✔ | **absent** |
| `dir_fd` on `open/mkdir/unlink/stat` (`os.supports_dir_fd`) | ✔ | ✔ | ✔ (POSIX.1-2008 `*at`) | **no** |
| `os.replace` with `src_dir_fd`/`dst_dir_fd` | ✔ | ✔ | ✔ (`renameat`) | **no** |
| `os.listdir(fd)` (`os.supports_fd`) | ✔ | ✔ | ✔ | **no** |
| `fsync` on a directory fd | ✔ | ✔ (no F_FULLFSYNC; see note) | ✔ | **not permitted** on a dir handle |
| `0600` mode meaningful | ✔ | ✔ | ✔ | partial (ACL, not POSIX bits) |

Relevant notes:

- **`O_NOFOLLOW` only protects the final component** of `open`. That's why the
  design chains one `openat` per component starting from `REPOSITORY_ROOT` —
  this is what the absence of `O_RESOLVE_BENEATH`/`RESOLVE_NO_SYMLINKS` (not
  exposed by CPython's `os` module in 3.11) requires. No new dependency is
  needed: manual chaining covers it.
- **macOS**: `fsync` does not force a flush to platter (would need
  `fcntl F_FULLFSYNC` via `fcntl.fcntl`, stdlib). For a repository artifact
  this is acceptable; the ordering (data → rename → dir fsync) remains
  correct. The residual durability risk only shows up on power loss; it does
  not affect the symlink threat model.
- **Windows**: everything the pin relies on is missing. The current code
  "works" by accident (`getattr(...,0)` plus `os.open` on a directory failing
  anyway), which is fragile. Recommendation: **explicit fail-closed** (the §1
  gate). The exporter is a POSIX dev/CI tool; refusing on Windows with a clear
  message is preferable to an insecure path-based fallback.

---

## Deterministic tests (race/symlink at the check→use boundary)

Real threads make the test flaky. Make the race deterministic by injecting the
swap **exactly** at the boundary, via monkeypatch, and prove the pin
neutralizes it.

1. **Symlink at the destination, opened with `O_NOFOLLOW`** (replaces the
   `lstat` tests): pre-create `engagement-v2` as a symlink → `_open_pinned_dir`
   must raise `RuntimeError("symlink destination rejected")` via `ELOOP`, both
   with `[]` and with `["--check"]`. Same for the parent (`schemas` →
   symlink) and for the final file (`program.schema.json` → symlink) — the
   latter now proven by `open(O_NOFOLLOW)` failing, not by `lstat`.

2. **Race won, neutralized by the pin (the key test)**: wrap the temp-name
   helper (or `os.replace`) with a wrapper that, on the first call, performs
   the malicious swap of the `SCHEMA_ROOT` *path* for a symlink pointing at an
   `attacker_dir`, then delegates. Assert: the expected bytes appear in the
   originally pinned inode and **`attacker_dir` stays empty**. This
   demonstrates that winning the race does not redirect the write — it is the
   positive proof of the descriptor pin (the test a path-based design cannot
   pass).

3. **Capability fail-closed**: `monkeypatch.delattr(os, "O_NOFOLLOW")` and,
   separately, `monkeypatch.setattr(os, "supports_dir_fd", set())` →
   `main([])` and `main(["--check"])` raise `RuntimeError` and **nothing** is
   written (assert the directory is unchanged / does not exist).

4. **Zero writes during `--check` (fd-spy)**: wrap `os.open` to raise if any
   write flag (`O_CREAT|O_WRONLY|O_RDWR`) is used during `--check`, and wrap
   `os.replace`/`os.mkdir`/`os.fsync` to fail if called. Run `--check` against
   (a) an identical destination, (b) one with drift, (c) one with an extra
   file, (d) a missing destination. Assert exit codes and that the wrappers
   never fired. Reinforces the current mtime-before/after tests.

5. **Extra-file detection**: place a `rogue.schema.json` in the destination →
   `--check` returns exit 1 listing `drift: rogue.schema.json` (sorted); and
   (per the §4 decision) write removes it. Covers the gap the current tests
   don't exercise (they only test modified/removed).

6. **Temp-file cleanup on `replace` failure** (adapt the existing test):
   `os.replace` fails → assert `os.listdir(dir_fd)` contains no `*.tmp` entry
   (via fd, not path `glob`) and that `os.fsync` on the file occurred.

7. **Flag spy**: assert that the file's `os.open` received
   `O_CREAT|O_EXCL|O_NOFOLLOW` and a non-null `dir_fd`, and that `os.replace`
   received `src_dir_fd` and `dst_dir_fd` — guards against the implementation
   regressing to path-based operations.

8. **`--check` does not create a missing destination** (keep the current
   test) and does not follow a symlink on read: a destination with a file
   symlink pointing outside → `--check` flags drift/rejects, without reading
   the external target.

---

## Findings

### Critical

**C1 — TOCTOU on writes: both the check and the use are path-based, without
`O_NOFOLLOW`/`dir_fd`.**
`scripts/export_engagement_v2_schemas.py:51-74` (`_write_one`) and `:77-94`
(`_write_files`). `_reject_symlink_components(target)` (l.53) does an `lstat`
by path; then `tempfile.mkstemp(dir=destination)` (l.54) and
`os.replace(temporary, target)` (l.67) re-resolve `destination`/parents by
string. `_write_files` mitigates with a double check (l.78 and l.80) but does
not close the window.
Failure scenario: in a `SCHEMA_ROOT` whose parent is writable by another
user/process (shared tmp, multi-user engagement directory, CI with a hostile
workspace), swapping `engagement-v2` (or `schemas`) for a symlink between the
check and the `replace` makes the `0600` write — including `manifest.json` —
land outside the intended tree, at an inode of the attacker's choosing.
Minimal fix: descriptor pin (Design §2–§3): chained `openat` with
`O_DIRECTORY|O_NOFOLLOW`, temp file with `O_CREAT|O_EXCL|O_NOFOLLOW` +
`dir_fd`, `os.replace(..., src_dir_fd, dst_dir_fd)`, `fsync(dir_fd)`.

### Important

**I1 — `--check` verifies the symlink by path, then reads by following the
symlink.**
`:33-48` (`_drifted_files`) and `:112-114`. `destination.is_symlink()`/
`_reject_symlink(path)` are `lstat`; `path.read_bytes()` (l.42) **follows**
symlinks. Scenario: swapping a component or the final file for a symlink
between `_reject_symlink` (l.40) and `read_bytes` (l.42) makes `--check` read
the attacker-controlled target, influencing the drift result/exit code (and
reading content from outside the tree). It doesn't write, but it undermines
the reliability of the gate.
Minimal fix: pin + `os.open(name, O_RDONLY|O_NOFOLLOW, dir_fd=...)`
(Design §5).

**I2 — Extra/stale files are neither detected nor removed.**
`:33-48` (check only iterates `rendered.items()`) and `:84-87` (write only
writes the expected set, never prunes). Scenario: an `injected.schema.json`
(planted by any means) survives indefinitely through `--check` (exit 0, "no
drift") and through re-exports; a loader that `glob`s the directory loads it
as a valid contract. The manifest lists only the expected files, but the
directory becomes a silent superset. Confirmed by the tests:
`test_exporter_check_..._drift` only covers modified/removed; no test covers
an extra file.
Minimal fix: in `--check`, compare `set(os.listdir(dir_fd))` against
`set(rendered)` and report extras as drift; in write, prune (Design §4). The
contract decision (prune vs. refuse) belongs to the team.

**I3 — Silent capability degradation instead of fail-closed.**
`:89` `directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)`. The
`getattr(..., 0)` turns the absence of `O_DIRECTORY` into a no-op instead of a
refusal. Since the secure design now *depends* on `O_NOFOLLOW`/`dir_fd`, any
platform lacking those must **refuse**, not fall back to path-based behavior.
Scenario: running in an environment without `dir_fd` (Windows/embedded) would
silently execute the insecure path.
Minimal fix: fail-closed capability gate at the start of `main` (Design §1)
and remove the `getattr` fallback.

### Minor

**M1 — `mkdir(exist_ok=True)` accepts a destination that is already a
symlink-to-directory.**
`:79`. `Path.mkdir(exist_ok=True)` suppresses `FileExistsError` when the
target resolves to a directory (follows the symlink), so an `engagement-v2`
that is already a symlink-to-dir passes; only the re-check `lstat` at l.80
catches it. Depends on the ordering of two `lstat` calls — fragile. The
descriptor pin (`os.mkdir(..., dir_fd=)` + reopening with `O_NOFOLLOW`)
eliminates the ambiguity.

**M2 — No global atomicity across the set.** `:84-94`. Each file is
`replace`d individually; a crash mid-way leaves a partial set. `manifest.json`
is written last (it appears last in `rendered`, `schemas.py:1200`), which
helps consumers that validate via the manifest, but there is no transactional
barrier. Acceptable for the tool; note it as residual.

**M3 — `fchmod` is redundant with `mkstemp`'s `0600`, but correct — keep it.**
`:61`. `tempfile.mkstemp` already creates with `0600`; in the new design,
`O_CREAT` is subject to `umask`, so **keeping the explicit `fchmod`**
guarantees exactly `0600` regardless of `umask`. Informational: do not remove
it during the refactor.

**M4 — Error messages include the destination path.** `:24`,`:82`. Low
impact (a local operator tool), but in shared CI logs it exposes directory
layout. Acceptable; note it.

---

## Residual risks (after the recommended design)

- **Trust root = `REPOSITORY_ROOT`.** The pin chains starting from
  `Path(__file__).resolve()`, which follows symlinks at import time. If the
  checkout itself lives under a hostile parent, that gets canonicalized once
  at import — there is a tiny window in the parents *above* `REPOSITORY_ROOT`
  before the root fd is opened, equivalent to the trust of simply running the
  script. **Severity: low**; mitigable by opening `REPOSITORY_ROOT` with
  `O_NOFOLLOW` and validating `st_dev/st_ino`, but likely overkill.
- **macOS durability** (no F_FULLFSYNC): loss only on power failure; does not
  affect the anti-symlink property. **Low.**
- **Multi-file non-atomicity (M2):** partial set after a crash; the next
  `--check` detects it and the next write fixes it. **Low.**
- **Pruning decision (I2):** if the team chooses to *report* extras instead of
  *removing* them, operators need to act on the drift; if *removing*, a
  legitimate non-generated file placed in the directory gets deleted.
  Contract choice, not a defect. **Low, policy-dependent.**
- **Signals outside the filesystem:** the exporter trusts
  `render_schema_files()` as the source of truth; the integrity of the
  generated bytes (not their transport to disk) is out of scope for this task
  and is already covered by `schemas.py` +
  `test_schema_rendering_and_manifest_hashes_are_deterministic`. No finding.

---

### Provenance note

The report path given in the prompt
(`.superpowers/sdd/2026-07-26-.../task-4-report.md`) was correct; the first
read attempt failed due to a relative path. I read the report and
`task-4-recovery.md` in the worktree. The report states "No open Task 4
concerns" and notes that an external read-only review was requested but did
not return within the window — this document is that review, and it
**reopens** the TOCTOU item (C1) plus three gaps (I1–I3) not covered by the
self-review or by the current tests.
