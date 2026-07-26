# Remote tool discovery — design

**Status:** approved (2026-07-26)

**Goal:** Report which tools a remote SSH host actually has, so `hackbot skills
list --runner remote` shows true remote availability (e.g. gobuster/nmap present
on Kali) instead of only local registration.

**Safety:** the probe queries the operator's own remote host (infra
introspection), not a target — it does not go through the risk gate. The probe
command is code-owned (fixed `command -v` checks over registered tool basenames),
each token `shlex.quote`d; no target/model content.

## Architecture

### 1. `RemoteRunner.probe`

Extract `RemoteRunner._ssh_argv(remote_cmd)` (already used by `run`) and add:

```python
def probe(self, tools: Iterable[str]) -> set[str]: ...
```

- Validates each tool as a safe basename (`[A-Za-z0-9._-]+`).
- Builds one code-owned script: for each tool,
  `command -v <tool> >/dev/null 2>&1 && printf '%s\n' <tool>` (tokens quoted).
- Runs it via the same ssh mechanism (one connection) and returns the set of
  tools the remote reported.

### 2. CLI — `hackbot skills list [--engagement DIR --runner {local,remote}]`

- Default (`local`): unchanged listing (local availability).
- `--runner remote` (needs `--engagement`): load `<engagement>/runner.json`, build
  a `RemoteRunner`, collect the tool basename of each **registered** action
  (`os.path.basename(definition.executable)`), probe the host once, and add a
  `remote_available` boolean per action. `bundle_risk_level`/attribution stay.

## Error handling

- `--runner remote` without `--engagement`, or a bad `runner.json`, or an SSH
  failure → exit 2 with guidance, no traceback.

## Testing strategy (test-first)

- **`probe`**: with a fake local runner, the ssh argv carries a `command -v`
  script for each tool with quoted tokens; the returned set matches the fake
  stdout; a tool with unsafe characters is rejected.
- **CLI**: `skills list --runner remote` (with a monkeypatched `RemoteRunner`
  returning a fixed probe set) marks `remote_available` per action;
  `--runner remote` without `--engagement` → exit 2.
- **Regression**: full suite, Ruff, format, mypy, offline smoke.
- **Manual (documented):** probe Kali and confirm curl/dig/nmap/ffuf/gobuster.

## Boundary

The probe is infra introspection of an operator-controlled host, not a gated
action; the probe command is code-owned and per-token quoted; it only reports
tool presence. It changes no scope, risk, or approval behavior.
