# Linux SSH remote runner — design

**Status:** approved (2026-07-26)

**Goal:** Execute gated actions on a configured remote Linux host over SSH — using
that host's tool arsenal — while the gate (scope + risk + approval) still runs
**locally**. Generic: any SSH host, documented so the operator can swap machines.

**Safety boundary:** the gate is unchanged and local; only *execution* is remote.
The remote host must be an authorized machine the operator controls. Output is
untrusted data; evidence is redacted; audit is secret-free. SSH argv is built
from a **code-owned** action argv with each token `shlex.quote`d (no shell
injection). The SSH private key is a local file (0600), never embedded.

## Context

`run_action(runner=…)` already injects a runner with `run(argv) -> CommandResult`.
`CommandRunner` runs locally. Kali (`192.168.64.4`) is reachable via a dedicated
key (`~/.ssh/hackbot_remote`) and has `/usr/bin/{curl,dig,nmap,ffuf,gobuster,…}`
and `/usr/share/wordlists/dirb/common.txt`. `sshpass` was used once to install
the key; runtime SSH is key-based (`BatchMode`).

## Architecture

### 1. `RemoteConfig` — `src/hackbot/tools/remote.py`

```python
@dataclass(frozen=True, slots=True)
class RemoteConfig:
    host: str
    user: str
    port: int
    key_path: str
    connect_timeout: int = 10


def load_remote_config(path: str | Path) -> RemoteConfig: ...
```

Read from `<engagement>/runner.json` (strict JSON, known keys). Validates host and
user (non-empty, no whitespace/control chars), port (1..65535), `key_path`
(absolute, existing regular file), `connect_timeout` (1..120). Generic — the file
names any host.

### 2. `RemoteRunner` — same interface as `CommandRunner`

```python
class RemoteRunner:
    def __init__(
        self,
        config: RemoteConfig,
        *,
        runner: CommandRunner | None = None,
        ssh_path: str | None = None,
    ) -> None: ...
    def run(self, argv: Sequence[str]) -> CommandResult: ...
```

`run(argv)`:
- `remote_cmd = " ".join(shlex.quote(t) for t in (os.path.basename(argv[0]), *argv[1:]))`
  — each token quoted; `argv[0]` reduced to its basename so the remote `PATH`
  resolves the tool.
- Builds `ssh -i <key> -p <port> -o BatchMode=yes -o ConnectTimeout=<n>
  -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=<key_path>.known_hosts
  <user>@<host> <remote_cmd>` and executes it via an injected local
  `CommandRunner` (so timeout, sanitized env, ephemeral HOME, and output caps all
  apply). Returns the `CommandResult` (SSH's exit code is the remote command's exit
  code; SSH itself uses 255 for connection errors).
- `ssh` is resolved from an absolute-path allowlist; fails closed if absent.

### 3. Remote-only ("arsenal") actions

An action whose `executable` is a **bare tool name** (a code identity like
`gobuster`, valid per the model) registers unconditionally and runs **only** via
the `RemoteRunner` (the local `CommandRunner` rejects a non-absolute executable).
Add:

- `web.dir-enum-gobuster` — `gobuster dir -u {target} -w
  /usr/share/wordlists/dirb/common.txt -q`. `high_volume` → **L2**. From
  `recon/parameter-discovery`; provenance recorded.

Existing local actions (curl/dig/ffuf) also run remotely (their basename resolves
on the remote).

### 4. CLI

`hackbot tool run ACTION REQUEST --engagement DIR [--runner local|remote] [--approve] [--json]`.
`--runner remote` loads `<engagement>/runner.json`, builds a `RemoteRunner`, and
passes it to `run_action`; default is `local`. The gate, approval, audit, and
evidence are unchanged.

## Error handling

- Missing/invalid `runner.json` → exit 2, guidance, no traceback.
- Remote-only action with `--runner local` → the local runner refuses a
  non-absolute executable (exit 2/1), no execution.
- SSH connection failure → SSH exit 255 → reported as a failed run (exit 1), no
  traceback; captured stderr is redacted evidence.
- The gate is unchanged: no `ALLOW` → no execution; L2 → TTY approval; out-of-scope
  → `DENY_SCOPE`.

## Testing strategy (test-first)

- **`RemoteConfig`**: valid file parses; bad port/host/missing key → error.
- **`RemoteRunner`**: with an injected fake local runner, assert the ssh argv is
  built correctly — `-i key`, `-p port`, `BatchMode`, `ConnectTimeout`,
  `UserKnownHostsFile`, `user@host`, and a single `remote_cmd` whose tokens are
  shlex-quoted and whose tool is the basename; a target with shell metacharacters
  stays a single quoted token (no injection). Returns the fake `CommandResult`.
- **arsenal action**: `web.dir-enum-gobuster` registered, L2, `high_volume`,
  bare-name executable, argv `-u {target}`; provenance validates against the
  manifest.
- **CLI routing**: `--runner remote` with a missing `runner.json` → exit 2;
  `--runner remote` builds a `RemoteRunner` (monkeypatched to a fake) and runs it.
- **Regression**: full suite, Ruff, format, mypy, offline smoke.
- **Manual (documented, not in the suite):** a real run on Kali — start a server
  on Kali, `hackbot tool run web.dir-enum-gobuster … --runner remote --approve`,
  confirm gobuster runs on Kali and evidence is captured.

## Boundary

Execution is remote; the gate is local and unchanged. The remote host is an
operator-controlled, authorized machine; SSH argv is code-owned and per-token
quoted; the key is a local 0600 file; output is untrusted and evidence is
redacted. `docs/remote-runner.md` documents pointing at **any** machine.
