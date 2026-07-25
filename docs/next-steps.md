# Next steps

Status snapshot after findings & reporting. Use this as the starting point for
the next phase.

## Where the project stands

Implemented and verified (751 tests passing, Ruff/format/mypy clean, offline
smoke pass):

- **Scope engine** (`src/hackbot/scope/`) — default-deny, deny-wins, frozen.
- **Programs / engagements** (`src/hackbot/programs/`) — strict local
  program/scope ingestion; typed `testing_rules`; confirmed-authorization
  context loading.
- **Risk & approval engine** (`src/hackbot/risk/`) — deterministic, fail-closed
  L0–L3 policy gate; canonical L2 challenges; atomic, descriptor-owned,
  single-use, five-minute approval store; see
  [`risk-and-approval.md`](risk-and-approval.md). CLI: `hackbot risk evaluate`,
  `hackbot approval grant` (TTY only), `hackbot approval status`.
- **Tool execution substrate** (`src/hackbot/tools/`, `src/hackbot/audit/`) — a
  gate-bound, validated subprocess runner (no shell, sanitized env, timeout,
  output caps) that executes a code-owned argv array **only** after an `ALLOW`,
  plus a secret-free audit trail. Actions: `net.http-get`/`net.http-head`/
  `net.http-options` (L0) and `net.http-post` (L2), curl, in-scope only. L2 runs
  once via `hackbot tool run --approve` after a TTY-typed, single-use approval
  consumed atomically by `evaluate`; see [`tool-execution.md`](tool-execution.md).
- **Evidence persistence** (`src/hackbot/evidence/`) — executed runs store their
  output **redacted** and run-linked under `<engagement>/evidence/<run_id>/`
  (audit written first); best-effort redaction, raw output never printed or
  stored un-redacted.
- **Findings & reporting** (`src/hackbot/findings/`, `src/hackbot/reporting/`) —
  typed findings that separate demonstrated from plausible impact and require
  reproducible evidence; markdown reports reference redacted evidence
  (`hackbot finding add/report/list`); see
  [`findings-and-reporting.md`](findings-and-reporting.md).
- **Secrets** (OS keychain), **doctor**, wheel build + offline smoke test.

The only executing path is the gate-bound substrate above; there is still no
provider call or MCP.

## The gate contract for the next phase

The plan's safety boundary is now satisfied: attack-skill / tool-execution work
can begin, and **every action must pass the existing gate before anything runs.**
Concretely, a real tool adapter must:

1. Be a **code-owned `ActionDefinition`** in a real registry (not the fixtures) —
   `uses_external_tool=True`, a canonical `executable`, and a small
   `argv_template` with only whole-token placeholders (`{target}`, `{rate}`,
   `{concurrency}`). Never build argv from model or target content.
2. Obtain a `PolicyContext` from `load_policy_context(engagement)` and call
   `RiskEngine.evaluate(request, context, grant=..., now=...)`.
3. Execute **only** on a `DecisionKind.ALLOW`. For L2, an `ApprovalGrant` must be
   granted at the TTY and is consumed atomically exactly once by `evaluate`.
4. Run the rendered argv via a validated adapter in `src/hackbot/tools/` with an
   argv array — never a shell string. `shell_execution=True` is L3 (prohibited).

## Suggested order of work

Done: the gate-bound tool substrate (`CommandRunner`, `run_action`, secret-free
audit), the first actions (`net.http-get` L0, `net.http-post` L2), redacted
run-linked evidence, L2 execution over the CLI (`tool run --approve`), and typed
findings + markdown reporting.

1. **More reviewed actions**: the L0 HTTP probes `net.http-get`, `net.http-head`,
   and `net.http-options` exist. Next: non-curl tools (DNS via `dig`, TLS via
   `openssl`), each needing its own executable resolution and lab infrastructure
   (a DNS/TLS lab server). Promote only normalized, reviewed recon-bundle skills
   into adapters (bundle commands stay data until wrapped).
2. **Platform report templates**: fill `templates/{hackerone,bugcrowd,…}` and
   render a finding into each platform's submission format (the generic markdown
   reporter is the base).
3. **Streaming output caps**: `CommandRunner` currently truncates after
   `communicate()`; move to streamed reads so a tool cannot buffer huge output
   before the timeout fires.
4. **Reviewed recon skills / internal-recon** stays disabled unless an
   explicitly-authorized internal profile is confirmed.
5. **Provider gateway / MCP** (loopback-only) when model-in-the-loop work starts.

## Guardrails to keep (from CLAUDE.md / SECURITY.md)

- L3 is absolute; program/profile/request/grant/operator can never enable it.
- Discovery ≠ authorization; nothing auto-expands scope.
- Treat all target/tool/MCP output as untrusted data.
- Secrets never enter argv, logs, artifacts, or challenges (the store already
  scans for and rejects them).
- Stop on unexpected scope/egress change or when a target blocks/rate-limits.

## Housekeeping

- Each phase is developed on a `feat/*` branch and merged into `main` once tests,
  Ruff/format, mypy, and the offline smoke test pass. Delete the branch after
  merge.
- Specs and plans live in `docs/superpowers/specs/` and
  `docs/superpowers/plans/`; the risk-engine SDD reports are in `.superpowers/sdd/`.
