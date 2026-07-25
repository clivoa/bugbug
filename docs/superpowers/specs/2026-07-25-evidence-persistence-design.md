# Evidence persistence (redacted, run-linked) — design

**Status:** approved (2026-07-25)

**Goal:** Complete the `context → evaluate → allow → run → evidence` path by
persisting the untrusted output of an executed action, redacted of known
secrets, per engagement, linked to the run and its recorded hypothesis.

**Non-goals:** No raw-secret storage, no cloud upload, no evidence viewer CLI, no
findings/report generation, no capture for non-executed (deny / requires-approval)
decisions. The reviewed `hackbot.risk` package is not modified.

## Context

`run_action` (`src/hackbot/tools/adapter.py`) executes a code-owned action only
after a `RiskEngine` `ALLOW` and records a secret-free audit line (digests and
sizes only — never raw output). `src/hackbot/evidence/` is an empty stub. The
approval store already has secret-detection patterns
(`hackbot.risk.approvals._SECRET_MATERIAL_RE`, `_SECRET_ASSIGNMENT_RE`,
`_reject_secrets`) which this phase reuses.

CLAUDE.md rule 7 requires redacting secrets (cookies, tokens, keys, PII) **before
storing** or sending to any cloud model. Evidence is therefore stored redacted,
never raw.

## Architecture

Two units, an adapter integration, and a CLI report field.

### 1. `src/hackbot/evidence/redact.py` — `redact_bytes`

`redact_bytes(data: bytes) -> bytes`: best-effort secret redaction over untrusted
tool output.

- Decode with `latin-1` (round-trips every byte losslessly), apply the ASCII
  secret patterns reused from the approval store plus secret-name assignments
  (`name=value` / `name: value` where `name` is a known secret name), replace
  each match with `[REDACTED]`, re-encode with `latin-1`.
- Non-matching bytes are preserved exactly. This is **defense in depth, not a
  guarantee**: it catches known formats (private keys, `Authorization`/`Cookie`
  headers, JWTs, `AKIA…`, `sk_…`, secret-name assignments), not every possible
  secret or PII.

### 2. `src/hackbot/evidence/store.py` — `EvidenceStore`

`EvidenceStore(engagement_dir: str | Path)` with:

```python
def record(
    self,
    *,
    action_id: str,
    request: ActionRequest,
    result: CommandResult,
    decision_kind: str,
    reason_code: str,
    now: datetime,
) -> str: ...  # returns run_id
```

Writes under `<engagement>/evidence/<run_id>/` (dir `0700`, files `0600`):

- `stdout` — `redact_bytes(result.stdout)`.
- `stderr` — `redact_bytes(result.stderr)`.
- `meta.json` — `action_id`, `target`, `argv` (code-owned), `hypothesis_id`,
  `rationale`, `expected_impact` (links evidence to the recorded hypothesis),
  `exit_code`, `timed_out`, `truncated`, `stdout_sha256` (of the **redacted**
  stdout), `stdout_bytes`, `stderr_bytes`, `decision`, `reason_code`,
  `timestamp`, `run_id`.

`meta.json` is scanned with `_reject_secrets` before writing; a secret-bearing
field (e.g. an operator `rationale` containing a token) raises `EvidenceError`
and nothing is persisted. `run_id = f"{now:%Y%m%dT%H%M%SZ}-{sha256(redacted
stdout)[:12]}"` (filesystem-safe, UTC).

### 3. `run_action` integration

Add an optional `evidence: EvidenceStore | None = None` parameter and an
`evidence_run_id: str | None = None` field on `ActionOutcome`. Order inside a
successful (executed) run: **audit first, then evidence**, so the audit trail
exists even if evidence capture fails. `EvidenceError` propagates to the caller;
non-executed decisions capture no evidence.

### 4. CLI

`hackbot tool run` constructs `EvidenceStore(engagement)`, passes it to
`run_action`, and reports `evidence_run_id` in the output. Raw output is still
never printed — the redacted bytes go only to the on-disk evidence file. If
`EvidenceError` is raised, the CLI reports that the run executed and was audited
but evidence capture failed, and returns exit `2`.

## Data flow

```
tool run → load context → strict-parse request → run_action:
    RiskEngine.evaluate → ALLOW
      → CommandRunner.run
      → AuditSink.record_run        (secret-free digests/sizes)
      → EvidenceStore.record        (redacted stdout/stderr + meta) → run_id
    → ActionOutcome(decision, result, evidence_run_id)
```

## Error handling (fail-closed)

- No `ALLOW` → no execution, no evidence.
- Deny / requires-approval → no evidence (`evidence_run_id` absent).
- Evidence write failure (`meta.json` secret-scan rejection, or I/O) →
  `EvidenceError` propagates; the CLI reports it and exits `2`; the run is already
  in the audit log.
- Evidence directories/files are `0700`/`0600` and live under `engagements/**`
  (git-ignored). Evidence files are sensitive and must be treated as such.

## Redaction is lossy

`redact_bytes` is best-effort. It reduces but does not eliminate the risk of a
secret or PII persisting in evidence. It is a layer on top of: raw output is
never printed; evidence is local and git-ignored. Documented as such.

## Testing strategy (test-first)

- **`redact_bytes`**: cookies / `Authorization` headers / JWTs / `AKIA…` /
  `sk_…` / `password=…` become `[REDACTED]`; benign text is unchanged;
  non-UTF-8 / arbitrary bytes are preserved except where a match is replaced.
- **`EvidenceStore`**: writes redacted `stdout`/`stderr` + `meta.json` with the
  expected keys and `0600`/`0700` modes; returns a `run_id`; a secret in the tool
  body is `[REDACTED]` on disk; a secret-bearing `rationale` raises
  `EvidenceError` and writes nothing.
- **`run_action` integration**: an executed run yields an `evidence_run_id` and
  on-disk files; a denied action yields no evidence.
- **CLI `tool run`**: reports `evidence_run_id`; the evidence file exists and is
  redacted; raw output is not printed.
- **Regression**: full suite, Ruff, format, mypy, offline smoke (no
  target/provider request).

## Boundary

Evidence is stored redacted, locally, per engagement, only for actions that
passed the gate and executed. Raw output is never printed and never stored
un-redacted. The audit trail is written before evidence so it always exists.
