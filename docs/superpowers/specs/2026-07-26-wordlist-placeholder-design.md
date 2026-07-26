# Custom wordlists ({wordlist} placeholder) — design

**Status:** approved (2026-07-26)

**Goal:** Let a code-owned action take an operator-chosen wordlist path (e.g. a
SecLists path on the remote host) via a new `{wordlist}` argv placeholder, so
directory/parameter fuzzing isn't limited to one bundled or hard-coded list.

**Safety:** the wordlist is an operator-supplied **value** rendered into a
**code-owned** argv template; it is lexically validated (absolute path, bounded,
no control chars), never derived from model/target content. The gate is
unchanged; the risk-model change is additive and backward-compatible.

## Context

`ActionDefinition.render_argv` only substitutes whole-token placeholders
`{target}`, `{rate}`, `{concurrency}`; any other `{…}` token is rejected by
`_argv_template`. Fuzzing tools need a wordlist path that varies per host/run.
`web.dir-enum` uses a bundled wordlist; `web.dir-enum-gobuster` hard-codes
`/usr/share/wordlists/dirb/common.txt`. SecLists (installable at
`/usr/share/seclists/` on the remote) is the natural source.

## Architecture

### 1. Risk model (`src/hackbot/risk/models.py`) — additive

- Add `"{wordlist}"` to `_ARGV_PLACEHOLDERS`.
- `ActionRequest` gains `wordlist: str = ""` (last field, default empty).
  Validation in `__post_init__`: if non-empty, it must be an **absolute** path,
  ≤ 2048 chars, no control chars / surrogates. **No filesystem check** (a remote
  path need not exist locally), keeping the model pure.
- `render_argv` substitutes `{wordlist}` → `request.wordlist`. If the template
  contains `{wordlist}` but `request.wordlist` is empty → return `None` (the gate
  then denies with `DENY_ARGV_TEMPLATE_MISMATCH`), mirroring the rate/concurrency
  rule.

### 2. Approval binding (`src/hackbot/risk/approvals.py`)

- `_challenge_fields` request block includes `"wordlist": request.wordlist`.
- `_request_from_binding` reconstructs `wordlist=block.get("wordlist", "")`.

### 3. CLI (`src/hackbot/cli/risk_cmd.py`)

- `wordlist` is an **optional** request key (default `""`), like other optional
  descriptor fields; `_build_request` passes it through.

### 4. Action

- `web.dir-enum-gobuster` becomes `gobuster dir -u {target} -w {wordlist} -q`
  (operator supplies the wordlist, e.g. a SecLists path on the remote). Remains
  remote-only (bare-name `gobuster`), L2, same provenance.

## Error handling

- A template needing `{wordlist}` with an empty request wordlist → `render_argv`
  returns `None` → `DENY_ARGV_TEMPLATE_MISMATCH`, no execution.
- A non-absolute or control-char wordlist → `ActionRequest` construction fails →
  CLI exit 2.
- Gate, scope, and approval behavior are otherwise unchanged.

## Testing strategy (test-first)

- **model**: `{wordlist}` renders into argv; an empty wordlist with a
  `{wordlist}` template → `render_argv` is `None`; a non-absolute wordlist →
  `ValueError`; a request without `{wordlist}` still works (default `""`).
- **approvals**: a challenge built for a `{wordlist}` action round-trips the
  wordlist (rebuild digest matches); a different wordlist changes the digest.
- **CLI**: a request with a `wordlist` field builds and runs; omitting it still
  works for non-wordlist actions.
- **action**: `web.dir-enum-gobuster` argv ends `-w {wordlist} -q`; still L2,
  remote-only, provenance intact.
- **Regression**: full suite, Ruff, format, mypy, offline smoke.
- **Manual (documented):** run `web.dir-enum-gobuster` on Kali with a real
  wordlist path (dirb, and SecLists once installed) via the remote runner.

## Boundary

The wordlist is an operator-supplied, lexically-validated path substituted into a
code-owned argv template — not shell, not model/target content. The model change
is additive and backward-compatible; the gate is unchanged.
