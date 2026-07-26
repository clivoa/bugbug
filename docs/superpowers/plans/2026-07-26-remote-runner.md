# Linux SSH Remote Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Run gated actions on a configured remote host over SSH (gate stays
local), plus a remote-only gobuster action. Generic for any machine.

**Architecture:** `RemoteConfig` (per-engagement JSON) + `RemoteRunner` (same
`run(argv)` interface as `CommandRunner`, builds a safe shlex-quoted ssh
invocation, delegates to a local `CommandRunner`); a bare-name arsenal action;
`hackbot tool run --runner remote`.

**Tech Stack:** Python 3.11+ stdlib (`shlex`, `json`, `os`), existing
`hackbot.tools`, pytest, Ruff, mypy. SSH key `~/.ssh/hackbot_remote` installed on
Kali.

## Global Constraints

- Gate is unchanged and local; only execution is remote.
- SSH argv is built from a code-owned action argv with each token `shlex.quote`d;
  `argv[0]` → basename; key-based auth (`BatchMode`), no shell injection.
- Remote host is an operator-controlled authorized machine; key is a local file.
- Test-first; real Kali run is a documented manual step, not in the suite.

---

### Task 1: RemoteConfig and RemoteRunner

**Files:**
- Create: `src/hackbot/tools/remote.py`
- Create: `tests/tools/test_remote.py`

**Interfaces:**
- Produces: `RemoteConfig`, `load_remote_config`, `RemoteRunner`, `RemoteError`.

- [ ] **Step 1: Write failing tests**

```python
import json

import pytest

from hackbot.tools.remote import RemoteConfig, RemoteError, RemoteRunner, load_remote_config
from hackbot.tools.runner import CommandResult


def _cfg(tmp_path):
    key = tmp_path / "id"
    key.write_text("KEY")
    key.chmod(0o600)
    return RemoteConfig(host="192.168.64.4", user="kali", port=22, key_path=str(key))


def test_load_remote_config_parses(tmp_path):
    key = tmp_path / "id"
    key.write_text("KEY")
    key.chmod(0o600)
    path = tmp_path / "runner.json"
    path.write_text(json.dumps({"host": "h", "user": "u", "port": 2222, "key_path": str(key)}))
    cfg = load_remote_config(path)
    assert cfg.host == "h" and cfg.user == "u" and cfg.port == 2222
    assert cfg.key_path == str(key)


def test_load_remote_config_rejects_bad_port(tmp_path):
    key = tmp_path / "id"
    key.write_text("KEY")
    path = tmp_path / "runner.json"
    path.write_text(json.dumps({"host": "h", "user": "u", "port": 0, "key_path": str(key)}))
    with pytest.raises(RemoteError):
        load_remote_config(path)


def test_load_remote_config_requires_existing_key(tmp_path):
    path = tmp_path / "runner.json"
    path.write_text(json.dumps({"host": "h", "user": "u", "port": 22, "key_path": "/nope/key"}))
    with pytest.raises(RemoteError):
        load_remote_config(path)


class _Fake:
    def __init__(self):
        self.argv = None

    def run(self, argv):
        self.argv = tuple(argv)
        return CommandResult(0, b"remote-ok", b"", 5, False, False)


def test_remote_runner_builds_safe_ssh_argv(tmp_path):
    fake = _Fake()
    runner = RemoteRunner(_cfg(tmp_path), runner=fake, ssh_path="/usr/bin/ssh")
    result = runner.run(("/opt/homebrew/bin/curl", "-sS", "http://in-scope/; rm -rf /"))
    assert result.stdout == b"remote-ok"
    argv = fake.argv
    assert argv[0] == "/usr/bin/ssh"
    assert "-i" in argv and str(_cfg(tmp_path).key_path) in argv
    assert "BatchMode=yes" in argv
    assert "kali@192.168.64.4" in argv
    remote_cmd = argv[-1]
    assert remote_cmd.startswith("curl ")  # basename, not the local abs path
    assert "'http://in-scope/; rm -rf /'" in remote_cmd  # metachars stay one quoted token


def test_remote_runner_rejects_empty_argv(tmp_path):
    with pytest.raises(RemoteError):
        RemoteRunner(_cfg(tmp_path), runner=_Fake(), ssh_path="/usr/bin/ssh").run(())
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_remote.py -q`
Expected: `ModuleNotFoundError: hackbot.tools.remote`.

- [ ] **Step 3: Implement remote.py**

```python
"""Run a code-owned action argv on a remote host over SSH (gate stays local)."""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from hackbot.tools.runner import CommandResult, CommandRunner, RunnerError

_SSH_CANDIDATES: tuple[str, ...] = ("/usr/bin/ssh", "/opt/homebrew/bin/ssh", "/usr/local/bin/ssh")
_CONFIG_KEYS = frozenset({"host", "user", "port", "key_path", "connect_timeout"})


class RemoteError(Exception):
    """Raised for an invalid remote config or a malformed remote invocation."""


@dataclass(frozen=True, slots=True)
class RemoteConfig:
    host: str
    user: str
    port: int
    key_path: str
    connect_timeout: int = 10


def _clean(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(
        c.isspace() or ord(c) < 0x20 for c in value
    ):
        raise RemoteError(f"{name}: expected a non-empty token with no whitespace/control chars")
    return value


def load_remote_config(path: str | Path) -> RemoteConfig:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RemoteError(f"cannot read runner config: {exc}") from exc
    if not isinstance(value, dict) or set(value) - _CONFIG_KEYS:
        raise RemoteError("runner config must be a JSON object with known keys")
    host = _clean(value.get("host"), name="host")
    user = _clean(value.get("user"), name="user")
    port = value.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise RemoteError("port: expected an integer 1..65535")
    key_path = value.get("key_path")
    if not isinstance(key_path, str) or not os.path.isabs(key_path) or not os.path.isfile(key_path):
        raise RemoteError("key_path: expected an absolute path to an existing key file")
    connect_timeout = value.get("connect_timeout", 10)
    if isinstance(connect_timeout, bool) or not isinstance(connect_timeout, int) or not 1 <= connect_timeout <= 120:
        raise RemoteError("connect_timeout: expected an integer 1..120")
    return RemoteConfig(host=host, user=user, port=port, key_path=key_path, connect_timeout=connect_timeout)


def _resolve_ssh(explicit: str | None) -> str:
    if explicit is not None:
        return explicit
    for candidate in _SSH_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    raise RemoteError("ssh executable not found")


class RemoteRunner:
    def __init__(
        self,
        config: RemoteConfig,
        *,
        runner: object | None = None,
        ssh_path: str | None = None,
    ) -> None:
        self._config = config
        self._ssh = _resolve_ssh(ssh_path)
        self._runner = runner if runner is not None else CommandRunner()

    def run(self, argv: Sequence[str]) -> CommandResult:
        items = tuple(argv)
        if not items:
            raise RemoteError("argv must be non-empty")
        tool = os.path.basename(items[0])
        remote_cmd = " ".join(shlex.quote(t) for t in (tool, *items[1:]))
        cfg = self._config
        ssh_argv = (
            self._ssh,
            "-F",
            "/dev/null",
            "-i",
            cfg.key_path,
            "-p",
            str(cfg.port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={cfg.connect_timeout}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={cfg.key_path}.known_hosts",
            f"{cfg.user}@{cfg.host}",
            remote_cmd,
        )
        try:
            return self._runner.run(ssh_argv)  # type: ignore[attr-defined]
        except RunnerError as exc:
            raise RemoteError(str(exc)) from exc
```

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_remote.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/tools/remote.py tests/tools/test_remote.py
git commit -m "feat: add SSH RemoteConfig and RemoteRunner"
```

---

### Task 2: Remote-only gobuster arsenal action

**Files:**
- Modify: `src/hackbot/tools/actions.py`
- Modify: `src/hackbot/skills/promotion.py`
- Modify: `tests/tools/test_actions.py`
- Modify: `tests/skills/test_promotion.py`

- [ ] **Step 1: Write failing shape + provenance tests**

Add to `tests/tools/test_actions.py`:

```python
def test_web_dir_enum_gobuster_is_remote_only_l2():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("web.dir-enum-gobuster")
    assert d.effective_floor is RiskLevel.L2
    assert d.high_volume is True
    assert d.uses_external_tool is True
    assert d.executable == "gobuster"  # bare name -> remote-only
    assert "-u" in d.argv_template and "{target}" in d.argv_template
    assert "web.dir-enum-gobuster" in REGISTERED_ACTION_IDS
```

The existing provenance test `test_every_registered_bundle_action_has_provenance`
already covers that the new action needs an entry.

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py tests/skills/test_promotion.py -q`
Expected: `RegistryError`, then the provenance test fails.

- [ ] **Step 3: Register the action (unconditional, bare-name) and its provenance**

In `src/hackbot/tools/actions.py`, in `_build_definitions` after the ffuf block
(no tool resolution — it is remote-only):

```python
    definitions.append(
        ActionDefinition(
            "web.dir-enum-gobuster",
            RiskLevel.L0,
            network_access=True,
            uses_external_tool=True,
            high_volume=True,
            executable="gobuster",
            argv_template=(
                "gobuster", "dir", "-u", "{target}", "-w",
                "/usr/share/wordlists/dirb/common.txt", "-q",
            ),
        )
    )
```

In `src/hackbot/skills/promotion.py`, add to `PROMOTED_ACTIONS`:

```python
    "web.dir-enum-gobuster": _p("recon/parameter-discovery", "note-enumeracao-diretorios", "2", "explicit"),
```

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools tests/skills -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/tools/actions.py src/hackbot/skills/promotion.py \
  tests/tools/test_actions.py
git commit -m "feat: add remote-only web.dir-enum-gobuster arsenal action"
```

---

### Task 3: CLI --runner remote

**Files:**
- Modify: `src/hackbot/cli/tool_cmd.py`
- Modify: `src/hackbot/cli/main.py`
- Modify: `tests/tools/test_cli.py`

- [ ] **Step 1: Write failing CLI tests**

```python
def test_tool_run_remote_missing_config_is_invalid(lab_engagement, tmp_path, capsys):
    request = _write_request(tmp_path, "http://127.0.0.1/", "net.http-get")
    code = app(
        ["tool", "run", "net.http-get", str(request), "--engagement", str(lab_engagement),
         "--runner", "remote", "--json"]
    )
    assert code == 2
    assert "runner" in capsys.readouterr().err.lower()


def test_tool_run_remote_uses_remote_runner(lab_engagement, tmp_path, capsys, monkeypatch):
    import json as _json

    from hackbot.tools.runner import CommandResult

    (lab_engagement / "runner.json").write_text(
        _json.dumps({"host": "h", "user": "u", "port": 22, "key_path": str(tmp_path / "k")})
    )
    (tmp_path / "k").write_text("KEY")

    calls = {}

    class _FakeRemote:
        def __init__(self, *a, **k):
            calls["built"] = True

        def run(self, argv):
            calls["argv"] = tuple(argv)
            return CommandResult(0, b"remote", b"", 3, False, False)

    monkeypatch.setattr("hackbot.tools.remote.RemoteRunner", _FakeRemote)
    request = _write_request(tmp_path, "http://127.0.0.1/", "net.http-get")
    code = app(
        ["tool", "run", "net.http-get", str(request), "--engagement", str(lab_engagement),
         "--runner", "remote", "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0 and payload["executed"] is True
    assert calls.get("built") is True
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_cli.py -q`
Expected: `--runner` unrecognized.

- [ ] **Step 3: Wire the runner selection**

In `src/hackbot/cli/tool_cmd.py`, add a helper and thread `runner` through
`cmd_run`:

```python
def _make_runner(engagement: str, name: str):
    from hackbot.tools.runner import CommandRunner

    if name == "local":
        return CommandRunner()
    if name == "remote":
        from hackbot.tools.remote import RemoteError, RemoteRunner, load_remote_config

        try:
            config = load_remote_config(str(Path(engagement) / "runner.json"))
        except RemoteError as exc:
            raise CliInputError(f"remote runner config: {exc}") from exc
        return RemoteRunner(config)
    raise CliInputError(f"unknown runner: {name}")
```

Change `cmd_run(..., approve=False, runner="local")`. Build the runner once
(replacing `runner = CommandRunner()`), catching `CliInputError` → print + return
`EXIT_INVALID`. Pass this `runner` to both `run_action` calls.

In `src/hackbot/cli/main.py`, add to the `tool run` subparser:

```python
    tl_run.add_argument("--runner", default="local", help="where to execute: local|remote")
```

and pass `runner=args.runner` in `_cmd_tool`.

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_cli.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/cli/tool_cmd.py src/hackbot/cli/main.py tests/tools/test_cli.py
git commit -m "feat: add hackbot tool run --runner remote"
```

---

### Task 4: Documentation, real Kali verification, and final regression

**Files:**
- Create: `docs/remote-runner.md`
- Modify: `README.md`
- Modify: `docs/next-steps.md`
- Modify: `scripts/smoke_test.sh`

- [ ] **Step 1: Document the remote runner (generic)**

`docs/remote-runner.md`: the `runner.json` format (host/user/port/key_path,
generic for ANY machine), the key-setup steps (ssh-keygen + install the public
key with your own method), that the gate runs locally and only execution is
remote, remote-only bare-name actions (gobuster), `--runner remote`, and a worked
example. Update README (test count; `--runner`; note remote execution) and
`docs/next-steps.md` (mark the SSH runner done; next = remote tool/wordlist
discovery and custom-wordlist placeholder).

- [ ] **Step 2: Extend the offline smoke test**

```bash
( cd /tmp && "$HACKBOT" tool run --help | grep -q -- --runner ) && echo "tool run --runner present"
```

- [ ] **Step 3: Real Kali verification (manual; record the result in the report)**

With Kali reachable and the key installed, from the repo:

```bash
# start a server on Kali, run gobuster there via the gate, then clean up
ssh -i ~/.ssh/hackbot_remote kali@192.168.64.4 'nohup python3 -m http.server 8000 >/dev/null 2>&1 & echo started'
# create engagements/kali-lab with scope cidrs 127.0.0.0/8 + confirmed authorization + runner.json
.venv/bin/hackbot tool run web.dir-enum-gobuster kali-req.json --engagement engagements/kali-lab --runner remote --approve --json
```

Confirm gobuster ran on Kali and redacted evidence was captured. This step is not
in the automated suite (it needs Kali up).

- [ ] **Step 4: Run all verification gates**

```bash
.venv/bin/python -m pytest -q -ra
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
scripts/smoke_test.sh
git diff --check
```

Expected: green; refresh the README/next-steps test count.

- [ ] **Step 5: Commit**

```bash
git add docs/remote-runner.md README.md docs/next-steps.md scripts/smoke_test.sh
git commit -m "docs: document the SSH remote runner and verify on Kali"
```

---

## Plan self-review

- **Spec coverage:** RemoteConfig/RemoteRunner (Task 1), remote-only gobuster +
  provenance (Task 2), CLI `--runner` (Task 3), docs + real verification (Task 4).
- **Placeholder scan:** none.
- **Type consistency:** `RemoteConfig`/`load_remote_config`/`RemoteRunner`/
  `RemoteError`, `web.dir-enum-gobuster`, and `cmd_run(..., runner=...)` match.
- **Safety boundary:** gate local + unchanged; ssh argv code-owned + shlex-quoted;
  key a local file; remote host operator-controlled; output untrusted, evidence
  redacted.
```
