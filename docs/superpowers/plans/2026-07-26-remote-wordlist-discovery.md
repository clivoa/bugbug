# Remote Wordlist Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `RemoteRunner.discover_wordlists()` and a `hackbot wordlists --runner remote` CLI so an operator can enumerate real wordlist paths on a remote host to feed `web.dir-enum-gobuster`'s `{wordlist}`.

**Architecture:** Mirror the existing `RemoteRunner.probe()` — a code-owned SSH script over a fixed allowlist of wordlist roots, stdout treated as untrusted data and parsed defensively into typed `WordlistEntry` records. Display-only; the risk model re-validates any path the operator later uses. No change to the gate, risk model, or action registry.

**Tech Stack:** Python 3.11+ stdlib only (`dataclasses`, `re`, `shlex`, `os`), pytest, Ruff, mypy. Reuses `RemoteRunner._ssh_argv`, `CommandRunner`, `CommandResult`.

## Global Constraints

- Python 3.11+, stdlib-only core (no new dependencies).
- Discovery ≠ authorization (CLAUDE.md rule 6): the feature only lists paths; it never selects, ranks, or runs a wordlist, and never expands scope.
- All remote command tokens are code-owned; every interpolated root is `shlex.quote`d; no target-controlled content or operator free-text enters the remote command (CLAUDE.md rules 3, 4).
- Remote stdout is untrusted: parse defensively, drop malformed lines silently, never raise on bad content.
- Frozen dataclasses (`frozen=True, slots=True`) as in `remote.py`.
- Ruff check + `ruff format --check` clean; `mypy src` clean; full `pytest` green; `scripts/smoke_test.sh` passes before merge.
- `CommandResult` signature: `CommandResult(exit_code, stdout, stderr, duration_ms, timed_out, truncated)`.
- Fake-runner test pattern: an object with `run(self, argv) -> CommandResult`, injected via `RemoteRunner(cfg, runner=fake, ssh_path="/usr/bin/ssh")`.

---

### Task 1: `WordlistEntry` + `discover_wordlists()` in `remote.py`

**Files:**
- Modify: `src/hackbot/tools/remote.py`
- Test: `tests/tools/test_remote.py`

**Interfaces:**
- Consumes: `RemoteRunner._ssh_argv(remote_cmd: str) -> tuple[str, ...]`, `self._runner.run(argv) -> CommandResult`, `RunnerError`, `RemoteError`.
- Produces:
  - `WordlistEntry(path: str, size_bytes: int)` — frozen dataclass.
  - `RemoteRunner.discover_wordlists() -> tuple[WordlistEntry, ...]` — sorted by path, de-duplicated, raises `RemoteError` on runner failure.
  - Module constants `_WORDLIST_ROOTS: tuple[str, ...]`, `_MAX_WORDLIST_LINES: int = 2000`, `_WORDLIST_PATH_RE` (compiled).

- [ ] **Step 1: Write the failing tests**

Add to `tests/tools/test_remote.py` (the `_cfg`, `RemoteRunner`, `RemoteError`, `CommandResult`, `WordlistEntry` imports must be present — add `WordlistEntry` to the existing `from hackbot.tools.remote import ...` line):

```python
def test_discover_wordlists_parses_and_sorts(tmp_path):
    class _W:
        def run(self, argv):
            self.argv = tuple(argv)
            return CommandResult(
                0,
                b"4749\t/usr/share/seclists/Discovery/Web-Content/common.txt\n"
                b"100\t/usr/share/wordlists/dirb/small.txt\n"
                b"4749\t/usr/share/seclists/Discovery/Web-Content/common.txt\n",  # dup
                b"",
                7,
                False,
                False,
            )

    fake = _W()
    runner = RemoteRunner(_cfg(tmp_path), runner=fake, ssh_path="/usr/bin/ssh")
    entries = runner.discover_wordlists()
    assert entries == (
        WordlistEntry("/usr/share/seclists/Discovery/Web-Content/common.txt", 4749),
        WordlistEntry("/usr/share/wordlists/dirb/small.txt", 100),
    )
    remote_cmd = fake.argv[-1]
    assert "find" in remote_cmd and "-maxdepth 4" in remote_cmd
    # roots are shlex.quote'd; they contain only safe chars so no quotes are added
    assert "/usr/share/seclists/Discovery/Web-Content" in remote_cmd
    assert "head -n 2000" in remote_cmd


def test_discover_wordlists_drops_malformed_and_out_of_allowlist(tmp_path):
    class _W:
        def run(self, argv):
            return CommandResult(
                0,
                b"12\t/etc/passwd\n"  # not under an allowlist root
                b"12\t/usr/share/wordlists/dirb/ok.txt\n"
                b"12\t/usr/share/wordlists/dirb/we ird.txt\n"  # space in path
                b"x\t/usr/share/wordlists/dirb/bad.txt\n"  # non-numeric size
                b"12\t/usr/share/wordlists/dirb/ctrl\x01.txt\n"  # control char
                b"garbage-line-no-tab\n",
                b"",
                7,
                False,
                False,
            )

    runner = RemoteRunner(_cfg(tmp_path), runner=_W(), ssh_path="/usr/bin/ssh")
    entries = runner.discover_wordlists()
    assert entries == (WordlistEntry("/usr/share/wordlists/dirb/ok.txt", 12),)


def test_discover_wordlists_empty_stdout(tmp_path):
    class _W:
        def run(self, argv):
            return CommandResult(0, b"", b"", 1, False, False)

    runner = RemoteRunner(_cfg(tmp_path), runner=_W(), ssh_path="/usr/bin/ssh")
    assert runner.discover_wordlists() == ()


def test_discover_wordlists_wraps_runner_error(tmp_path):
    from hackbot.tools.runner import RunnerError

    class _W:
        def run(self, argv):
            raise RunnerError("ssh boom")

    runner = RemoteRunner(_cfg(tmp_path), runner=_W(), ssh_path="/usr/bin/ssh")
    with pytest.raises(RemoteError):
        runner.discover_wordlists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/tools/test_remote.py -q -k discover_wordlists`
Expected: FAIL (`ImportError: cannot import name 'WordlistEntry'` / `AttributeError: discover_wordlists`).

- [ ] **Step 3: Implement in `src/hackbot/tools/remote.py`**

Add the constants near the top (after `_TOOL_RE`):

```python
_WORDLIST_ROOTS: tuple[str, ...] = (
    "/usr/share/seclists/Discovery/Web-Content",
    "/usr/share/seclists/Discovery/DNS",
    "/usr/share/wordlists/dirb",
    "/usr/share/wordlists/dirbuster",
)
_MAX_WORDLIST_LINES = 2000
_WORDLIST_PATH_RE = re.compile(r"[A-Za-z0-9._/-]+")
```

Add the dataclass (next to `RemoteConfig`):

```python
@dataclass(frozen=True, slots=True)
class WordlistEntry:
    path: str
    size_bytes: int
```

Add the method to `RemoteRunner` (after `probe`):

```python
def discover_wordlists(self) -> tuple["WordlistEntry", ...]:
    """List *.txt wordlist files under a fixed code-owned allowlist of roots.

    Infra introspection of the operator's own host (not a gated action). The
    command is code-owned (fixed ``find`` over ``_WORDLIST_ROOTS``); each root
    is quoted. Stdout is untrusted: only ``<int>\\t<allowlisted-path>`` lines
    with a safe path charset are kept; anything else is dropped.
    """
    per_root = "; ".join(
        f"find {shlex.quote(root)} -maxdepth 4 -type f -name '*.txt' "
        r"-printf '%s\t%p\n' 2>/dev/null"
        for root in _WORDLIST_ROOTS
    )
    script = f"({per_root}) | head -n {_MAX_WORDLIST_LINES}"
    try:
        result = self._runner.run(self._ssh_argv(script))  # type: ignore[attr-defined]
    except RunnerError as exc:
        raise RemoteError(str(exc)) from exc
    seen: dict[str, int] = {}
    for line in result.stdout.decode("latin-1").splitlines():
        size_str, tab, path = line.partition("\t")
        if not tab or not size_str.isdigit():
            continue
        if _WORDLIST_PATH_RE.fullmatch(path) is None:
            continue
        if not any(path.startswith(root + "/") for root in _WORDLIST_ROOTS):
            continue
        seen.setdefault(path, int(size_str))
    return tuple(WordlistEntry(path, seen[path]) for path in sorted(seen))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/tools/test_remote.py -q -k discover_wordlists`
Expected: PASS (4 tests).

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff format src/hackbot/tools/remote.py tests/tools/test_remote.py && .venv/bin/ruff check src/hackbot/tools/remote.py && .venv/bin/mypy src`
Expected: no issues.

- [ ] **Step 6: Commit**

```bash
git add src/hackbot/tools/remote.py tests/tools/test_remote.py
git commit -m "feat: RemoteRunner.discover_wordlists over fixed allowlist"
```

---

### Task 2: `hackbot wordlists` CLI subcommand

**Files:**
- Create: `src/hackbot/cli/wordlists_cmd.py`
- Modify: `src/hackbot/cli/main.py`
- Test: `tests/tools/test_cli.py`

**Interfaces:**
- Consumes: `WordlistEntry`, `RemoteRunner`, `RemoteError`, `load_remote_config` from `hackbot.tools.remote`.
- Produces: `wordlists_cmd.cmd_list(*, engagement: str | None, runner: str = "remote", as_json: bool = False) -> int` (exit 0 on success, 2 on error).

- [ ] **Step 1: Write the failing tests**

Add to `tests/tools/test_cli.py`. Use `monkeypatch` to replace `RemoteRunner` and `load_remote_config` so no real SSH runs:

```python
def test_wordlists_list_remote_prints_entries(tmp_path, capsys, monkeypatch):
    import json as _json

    from hackbot.cli import wordlists_cmd
    from hackbot.tools.remote import WordlistEntry

    eng = tmp_path / "eng"
    (eng).mkdir()
    (eng / "runner.json").write_text("{}")

    class _R:
        def __init__(self, *a, **k):
            pass

        def discover_wordlists(self):
            return (
                WordlistEntry("/usr/share/wordlists/dirb/common.txt", 4614),
                WordlistEntry("/usr/share/seclists/Discovery/DNS/n.txt", 10),
            )

    monkeypatch.setattr(wordlists_cmd, "load_remote_config", lambda p: object())
    monkeypatch.setattr(wordlists_cmd, "RemoteRunner", _R)

    rc = wordlists_cmd.cmd_list(engagement=str(eng), runner="remote", as_json=True)
    assert rc == 0
    payload = _json.loads(capsys.readouterr().out)
    assert payload["wordlists"] == [
        {"path": "/usr/share/seclists/Discovery/DNS/n.txt", "size_bytes": 10},
        {"path": "/usr/share/wordlists/dirb/common.txt", "size_bytes": 4614},
    ]


def test_wordlists_list_requires_engagement(capsys):
    from hackbot.cli import wordlists_cmd

    rc = wordlists_cmd.cmd_list(engagement=None, runner="remote", as_json=False)
    assert rc == 2
    assert "engagement" in capsys.readouterr().err.lower()


def test_wordlists_list_rejects_non_remote_runner(capsys):
    from hackbot.cli import wordlists_cmd

    rc = wordlists_cmd.cmd_list(engagement="x", runner="local", as_json=False)
    assert rc == 2
    assert "runner" in capsys.readouterr().err.lower()


def test_wordlists_list_reports_remote_error(tmp_path, capsys, monkeypatch):
    from hackbot.cli import wordlists_cmd
    from hackbot.tools.remote import RemoteError

    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "runner.json").write_text("{}")

    def _boom(_p):
        raise RemoteError("bad config")

    monkeypatch.setattr(wordlists_cmd, "load_remote_config", _boom)
    rc = wordlists_cmd.cmd_list(engagement=str(eng), runner="remote", as_json=False)
    assert rc == 2
    assert "bad config" in capsys.readouterr().err
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/tools/test_cli.py -q -k wordlists`
Expected: FAIL (`ModuleNotFoundError: hackbot.cli.wordlists_cmd`).

- [ ] **Step 3: Create `src/hackbot/cli/wordlists_cmd.py`**

```python
"""Remote-only enumeration of wordlist files under a fixed code-owned allowlist.

Discovery only: paths are display-only. When an operator later uses one as a
``{wordlist}``, the risk model re-validates it (absolute, no control chars) and
the gate runs as usual. Nothing here selects, ranks, or runs a wordlist.
"""

from __future__ import annotations

import json
import os
import sys

from hackbot.tools.remote import RemoteError, RemoteRunner, load_remote_config


def cmd_list(*, engagement: str | None, runner: str = "remote", as_json: bool = False) -> int:
    if runner != "remote":
        print(f"error: unknown runner: {runner} (wordlists is remote-only)", file=sys.stderr)
        return 2
    if not engagement:
        print("error: --runner remote requires --engagement", file=sys.stderr)
        return 2
    try:
        config = load_remote_config(os.path.join(engagement, "runner.json"))
        entries = RemoteRunner(config).discover_wordlists()
    except RemoteError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if as_json:
        print(
            json.dumps(
                {"wordlists": [{"path": e.path, "size_bytes": e.size_bytes} for e in entries]},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        if not entries:
            print("no wordlists found under known roots")
        else:
            print(f"{len(entries)} wordlist(s):")
            for e in entries:
                print(f"  {e.size_bytes:>12}  {e.path}")
    return 0
```

- [ ] **Step 4: Wire into `src/hackbot/cli/main.py`**

Add a subparser next to the `skills` one (after the `sk.set_defaults(func=_cmd_skills)` block), matching the existing style:

```python
    wl = sub.add_parser("wordlists", help="enumerate wordlist files on a remote host")
    wl_sub = wl.add_subparsers(dest="wlaction", required=True)
    wl_list = wl_sub.add_parser("list", help="list wordlist paths under known roots (remote)")
    wl_list.add_argument("--engagement", help="engagement dir (reads runner.json)")
    wl_list.add_argument("--runner", default="remote", help="remote-only (reads the host)")
    wl_list.add_argument("--json", action="store_true")
    wl.set_defaults(func=_cmd_wordlists)
```

Add the dispatcher near `_cmd_skills`:

```python
def _cmd_wordlists(args: argparse.Namespace) -> int:
    from hackbot.cli import wordlists_cmd

    if args.wlaction == "list":
        return wordlists_cmd.cmd_list(
            engagement=args.engagement, runner=args.runner, as_json=args.json
        )
    return 2
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/tools/test_cli.py -q -k wordlists`
Expected: PASS (4 tests).

- [ ] **Step 6: Lint/type**

Run: `.venv/bin/ruff format src/hackbot/cli/wordlists_cmd.py src/hackbot/cli/main.py tests/tools/test_cli.py && .venv/bin/ruff check src/hackbot/cli && .venv/bin/mypy src`
Expected: no issues.

- [ ] **Step 7: Commit**

```bash
git add src/hackbot/cli/wordlists_cmd.py src/hackbot/cli/main.py tests/tools/test_cli.py
git commit -m "feat: hackbot wordlists --runner remote (wordlist discovery CLI)"
```

---

### Task 3: Docs + real Kali verification

**Files:**
- Modify: `docs/remote-runner.md`
- Modify: `docs/next-steps.md`
- Modify: `README.md` (test count)

- [ ] **Step 1: Real verification on Kali**

The remote host (`192.168.64.4`, existing `runner.json`) has SecLists installed. Confirm discovery finds a known list:

```bash
.venv/bin/python -c "
from hackbot.tools.remote import RemoteConfig, RemoteRunner
cfg = RemoteConfig(host='192.168.64.4', user='kali', port=22, key_path='/Users/clivoa/.ssh/hackbot_remote', connect_timeout=10)
entries = RemoteRunner(cfg).discover_wordlists()
hits = [e for e in entries if e.path.endswith('/Discovery/Web-Content/common.txt')]
print('total:', len(entries))
for e in hits: print(e.path, e.size_bytes)
assert hits and hits[0].size_bytes > 0
print('OK')
"
```
Expected: prints the `common.txt` path with a positive size and `OK`.

- [ ] **Step 2: Update `docs/remote-runner.md`**

Replace the closing "Remote tool/wordlist *discovery* ... is a later increment" wording in the Boundary section, and add a new section after "Remote tool discovery":

```markdown
## Remote wordlist discovery

```bash
hackbot wordlists list --engagement <name> --runner remote
```

SSHes to the host once (infra introspection, not a gated action) and lists
`*.txt` wordlist files under a **fixed code-owned allowlist** of roots
(`/usr/share/seclists/Discovery/{Web-Content,DNS}`, `/usr/share/wordlists/{dirb,dirbuster}`),
each entry as `<size_bytes> <path>`. Output is untrusted and parsed defensively
(only allowlisted, safe-charset paths survive). Paths are **display-only**: copy
one into a request's `wordlist` field, where the risk model re-validates it before
`web.dir-enum-gobuster` can run. Verified on Kali against SecLists.
```

- [ ] **Step 3: Update `docs/next-steps.md`**

Move item 1 ("Remote wordlist discovery") into the "Done" paragraph and renumber the remaining items (report templates → 1, streaming caps → 2, internal-recon → 3, provider gateway → 4). Bump the test count in the status snapshot to the new total.

- [ ] **Step 4: Update `README.md` test count**

Update `# full safety suite (NNN tests)` to the new total from `.venv/bin/pytest -q`.

- [ ] **Step 5: Full gates**

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
bash scripts/smoke_test.sh
git diff --check
```
Expected: all green; note the exact `N passed, 1 skipped` count and confirm README/next-steps match it.

- [ ] **Step 6: Commit**

```bash
git add docs/remote-runner.md docs/next-steps.md README.md
git commit -m "docs: document remote wordlist discovery; bump test count"
```

---

## Completion

After all tasks: use superpowers:finishing-a-development-branch to verify gates and merge `feat/remote-wordlist-discovery` into `main` with `--no-ff`, then delete the branch.
