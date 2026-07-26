# Remote wordlist discovery — design

**Date:** 2026-07-26
**Status:** approved (design)
**Consumer:** `web.dir-enum-gobuster` (the `{wordlist}` operator-supplied path)

## Problem

`web.dir-enum-gobuster` takes an operator-supplied absolute `{wordlist}` path on
the run host (e.g. a SecLists list). Today the operator must already know a valid
path on the remote host and hard-code it. We want to *enumerate* which wordlist
files a remote host actually has, so the operator can pick a real path instead of
guessing.

This is the roadmap item "Remote wordlist discovery" in
[`docs/next-steps.md`](../../next-steps.md).

## Non-goals

- Not a gated action. Like `RemoteRunner.probe()`, this is infra introspection of
  the operator's own authorized host, not a network action against a target.
- Does **not** select, rank, or auto-run a wordlist. **Discovery ≠ authorization**
  (CLAUDE.md rule 6): it only lists paths; the operator copies one into a request.
- No operator-configurable directories in this increment (a fixed code-owned
  allowlist). Configurable roots can come later.
- Remote-only. No `--runner local` variant in this increment.

## Architecture

Mirrors `RemoteRunner.probe()` exactly: a **code-owned** shell script runs once
over the existing SSH transport (`_ssh_argv`), and its stdout is treated as
**untrusted data** (CLAUDE.md rule 3) and parsed defensively. No target-controlled
content and no operator free-text enters the remote command. The risk gate, risk
model, and action registry are unchanged.

Discovered paths are display-only. The operator copies one path into a
`request.json` as the `wordlist` field, where `ActionRequest.__post_init__`
re-validates it (absolute, no control characters) and the gate runs as usual. A
discovered path therefore passes through **two** independent validations and never
becomes argv automatically.

## Components

### 1. Fixed allowlist (code-owned)

In `src/hackbot/tools/remote.py`, a module-level constant scoped to the
directory-enumeration consumer:

```python
_WORDLIST_ROOTS: tuple[str, ...] = (
    "/usr/share/seclists/Discovery/Web-Content",
    "/usr/share/seclists/Discovery/DNS",
    "/usr/share/wordlists/dirb",
    "/usr/share/wordlists/dirbuster",
)
```

Absolute, fixed, not derived from any input. A host missing all of them yields an
empty result (not an error).

### 2. `WordlistEntry`

```python
@dataclass(frozen=True, slots=True)
class WordlistEntry:
    path: str
    size_bytes: int
```

### 3. Remote script (code-owned, bounded)

For each root, GNU `find` (the remote is Linux/Kali) emits `size<TAB>path`, with
total output bounded so a large tree cannot flood the runner's output cap:

```
find <root> -maxdepth 4 -type f -name '*.txt' -printf '%s\t%p\n' 2>/dev/null
```

joined across roots with `;` and piped through `head -n <_MAX_WORDLIST_LINES>`
(constant, e.g. 2000). Every literal token is fixed; each root is `shlex.quote`d.
No input other than the fixed allowlist reaches the command.

### 4. `RemoteRunner.discover_wordlists()`

```python
def discover_wordlists(self) -> tuple[WordlistEntry, ...]: ...
```

Runs the script via `self._runner.run(self._ssh_argv(script))` (same as `probe`).
Parses stdout defensively:

- Decode `latin-1`, split into lines.
- Accept a line only if it is exactly `<digits><TAB><path>` where `<path>`
  matches `^[A-Za-z0-9._/-]+$` **and** starts with one of `_WORDLIST_ROOTS`
  (followed by `/`). Any line with control chars, whitespace in the path, or an
  out-of-allowlist prefix is dropped silently.
- `size_bytes = int(<digits>)`.
- De-duplicate by path; return sorted by path.

Raises `RemoteError` on SSH/runner failure (wrapping `RunnerError`), like `run`
and `probe`.

### 5. CLI: `hackbot wordlists`

New subcommand in `src/hackbot/cli/` (own module `wordlists_cmd.py`, wired in
`main.py`), remote-only:

```
hackbot wordlists --runner remote --engagement <dir> [--json]
```

- `--runner remote` (only value accepted in v1; anything else → `error: unknown
  runner` exit 2). `--runner` defaults to `remote` for this command since local is
  unsupported.
- Requires `--engagement`; reads `<engagement>/runner.json` via
  `load_remote_config` (same as `skills list --runner remote`). Missing → exit 2.
- Text output: one row per entry, `f"  {size_bytes:>12}  {path}"`, preceded by a
  count; empty result prints a "no wordlists found under known roots" note.
- `--json`: `{"wordlists": [{"path": ..., "size_bytes": ...}, ...]}` sorted by path.
- `RemoteError` → `error: <msg>` on stderr, exit 2.

## Data flow

```
operator runs: hackbot wordlists --runner remote --engagement E
  -> load_remote_config(E/runner.json)
  -> RemoteRunner(cfg).discover_wordlists()
       -> ssh <host> '<code-owned find script over fixed allowlist>'
       -> stdout (untrusted) parsed defensively -> tuple[WordlistEntry]
  -> printed as table / json  (DISPLAY ONLY)
operator copies a path into request.json "wordlist"
  -> ActionRequest re-validates (absolute, no control chars)
  -> gate (scope + risk + L2 approval) -> RemoteRunner.run(argv)
```

## Error handling

- Invalid/missing `runner.json`, unreachable host, SSH non-zero → `RemoteError`
  → CLI exit 2 with message.
- No `--engagement` → CLI exit 2.
- Host has none of the roots → empty list, exit 0 (normal).
- Malformed stdout lines → dropped silently (defensive parse); never raises.

## Testing

Unit (fake runner injected via the existing pattern — an object with
`run(argv) -> CommandResult`):

- Parser accepts well-formed `size\tpath` lines, sorts by path, de-dups.
- Parser drops: control chars in path, whitespace in path, non-numeric size,
  a path not under any allowlist root.
- Empty stdout → empty tuple.
- Script construction: every root appears `shlex.quote`d; literal `find` /
  `-maxdepth 4` / `-printf` / `head` tokens present; no input interpolated.
- `RunnerError` from the injected runner → `RemoteError`.

CLI (fake `RemoteRunner`):

- Table output lists entries with sizes; `--json` shape correct and sorted.
- Missing `--engagement` → exit 2.
- Unknown `--runner` value → exit 2.
- `RemoteError` → exit 2.

Real verification (Kali, `192.168.64.4`, existing `runner.json`):

- `discover_wordlists()` returns an entry for
  `/usr/share/seclists/Discovery/Web-Content/common.txt` with a positive
  `size_bytes`.

## Docs

- `docs/remote-runner.md`: replace the "later increment" note with a "Remote
  wordlist discovery" section documenting `hackbot wordlists --runner remote`.
- `docs/next-steps.md`: move item 1 (remote wordlist discovery) to Done; renumber.
- Test-count bumps (README, next-steps) after the suite grows.

## Boundary recap

Execution is remote; the enumeration is code-owned and reads a fixed allowlist;
stdout is untrusted and parsed defensively; discovered paths are display-only and
re-validated by the risk model before any run. Nothing here can expand scope,
select a target, or run a tool.
