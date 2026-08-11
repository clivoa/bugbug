# Remote runner (SSH)

`hackbot tool run --runner remote` executes a gated action on a **remote Linux
host** over SSH, using that host's tool arsenal. The risk gate (scope + risk +
approval) still runs **locally**, exactly as for a local run — only *execution*
is remote. This works with **any** SSH host you control, not just one machine.

## Safety

- The gate is unchanged and local: no `ALLOW` → no execution; L2 → TTY approval;
  out-of-scope → `DENY_SCOPE`.
- The SSH command is built from the **code-owned** action argv with every token
  `shlex.quote`d and `argv[0]` reduced to its basename (resolved on the remote
  `PATH`). A scope-validated target with shell metacharacters stays a single
  quoted token — no injection.
- The remote host must be a machine you **own or are authorized to use**. Output
  is untrusted data; evidence is stored redacted; the audit line is secret-free.
- The SSH private key is a local file (keep it `0600`); it is never embedded in
  config, argv, logs, or evidence.

## Configuring a host (`<engagement>/runner.json`)

```json
{
  "host": "192.168.64.4",
  "user": "kali",
  "port": 22,
  "key_path": "/Users/you/.ssh/hackbot_remote",
  "connect_timeout": 10
}
```

- `host`, `user`, `port`, `key_path` (absolute path to an existing private key),
  optional `connect_timeout` (seconds). To point at a **different machine**, just
  edit this file — nothing in the code is host-specific.

## One-time key setup

Use a dedicated key (not your personal one):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/hackbot_remote -N "" -C "hackbot-remote-runner"
# install the public key on the host by your preferred method, e.g.:
ssh-copy-id -i ~/.ssh/hackbot_remote.pub user@host      # prompts for the host password once
# verify key-based access:
ssh -i ~/.ssh/hackbot_remote -o BatchMode=yes user@host 'uname -a; command -v ffuf gobuster nmap'
```

Runtime SSH is key-based (`BatchMode`), pins the host key to
`<key_path>.known_hosts`, ignores your `~/.ssh/config` (`-F /dev/null`), and uses
only the configured key (`IdentitiesOnly=yes`).

## Remote-only ("arsenal") actions

An action whose executable is a **bare tool name** (e.g. `gobuster`) registers
unconditionally and runs **only** via `--runner remote` — the local runner
refuses a non-absolute executable. Example:

- `web.dir-enum-gobuster` — `gobuster dir -u {target} -w {wordlist} -q` (L2,
  `high_volume`). The `{wordlist}` is an **operator-supplied absolute path on the
  remote host** — e.g. a [SecLists](https://github.com/danielmiessler/SecLists)
  list such as `/usr/share/seclists/Discovery/Web-Content/common.txt`. It is
  lexically validated (absolute, no control characters) and never opened by the
  engine; an empty `{wordlist}` is denied (`DENY_ARGV_TEMPLATE_MISMATCH`).
  Provenance: `recon/parameter-discovery` ().

Local-tool actions (curl/dig/ffuf) also run remotely — their basename resolves on
the remote `PATH`.

## Remote tool discovery

```bash
hackbot skills list --engagement <name> --runner remote
```

SSHes to the host once (infra introspection, not a gated action — the command is
a code-owned `command -v` check) and marks each action `remote` / `no-remote`
(its tool is / isn't on the host), or `unknown` for an action not registered
locally (so its tool basename can't be determined here). Use it to confirm, e.g.,
that gobuster/nmap are present on the remote before running them.

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

## Example

```bash
# request.json: action_id web.dir-enum-gobuster, target http://<in-scope>/,
#   wordlist /usr/share/seclists/Discovery/Web-Content/common.txt,
#   argv [gobuster, dir, -u, http://<in-scope>/, -w,
#         /usr/share/seclists/Discovery/Web-Content/common.txt, -q],
#   rate 1, concurrency 1, ...
hackbot tool run web.dir-enum-gobuster request.json \
  --engagement engagements/<name> --runner remote --approve --json
```

Evaluates locally (L2 → TTY approval), then runs gobuster on the remote host
against the in-scope target; redacted evidence is captured under
`<engagement>/evidence/<run_id>/`.

## Boundary

Execution is remote; the gate is local and unchanged. The remote host is an
operator-controlled, authorized machine. SSH argv is code-owned and per-token
quoted; the key is a local file; output is untrusted and evidence redacted.
The `{wordlist}` is the one operator-supplied argv token, lexically validated and
never dereferenced locally. Remote tool discovery and remote wordlist discovery
(enumerating which lists a host actually has, under a fixed code-owned allowlist
of roots) are both implemented and display-only — neither auto-populates or
authorizes a request's `{wordlist}` field; the risk model re-validates it before
any action runs.
