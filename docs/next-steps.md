# Next steps

Status snapshot after the SSH remote runner. Use this as the starting point for
the next phase.

## Where the project stands

Implemented and verified (905 tests passing; 906 collected with 1 known nmap
skip; Ruff/format/mypy clean; offline smoke pass):

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
  output caps enforced during streaming capture) that executes a code-owned argv
  array **only** after an `ALLOW`, plus a secret-free audit trail. Actions are
  promoted from reviewed recon-bundle skills (with `@reeshasx` attribution;
  `hackbot skills list`): HTTP probes, DNS record lookups, TLS cert (L0),
  `net.port-scan` (nmap), and `web.dir-enum` (ffuf directory fuzzing) (L2),
  in-scope only. L2 runs once via
  `hackbot tool run --approve` after a TTY-typed, single-use approval consumed
  atomically by `evaluate`. Actions can run locally or on a remote SSH host
  (`--runner remote`, e.g. Kali) with the gate still local; see
  [`tool-execution.md`](tool-execution.md), [`skill-promotion.md`](skill-promotion.md),
  and [`remote-runner.md`](remote-runner.md).
- **Evidence persistence** (`src/hackbot/evidence/`) — executed runs store their
  output **redacted** and run-linked under `<engagement>/evidence/<run_id>/`
  (audit written first); best-effort redaction, raw output never printed or
  stored un-redacted.
- **Findings & reporting** (`src/hackbot/findings/`, `src/hackbot/reporting/`) —
  typed findings that separate demonstrated from plausible impact and require
  reproducible evidence; per-platform markdown reports
  (`generic`/`hackerone`/`bugcrowd`/`yeswehack`/`intigriti`/`immunefi`) reference
  redacted evidence (`hackbot finding add/report/list`), including
  operator-customizable templates through explicit `--templates-dir`, strict
  allowlisted placeholders, and fail-before-output validation; see
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

Done: the gate-bound tool substrate with streaming output caps, actions promoted
from reviewed recon-bundle skills (HTTP/DNS/TLS L0 + nmap port-scan & ffuf dir-enum L2, with attribution +
`skills list`),
redacted run-linked evidence, L2 execution over the CLI (`tool run --approve`),
typed findings, per-platform markdown reporting, a remote SSH runner
(`--runner remote`, verified on Kali with gobuster), and **custom operator
wordlists** — the `{wordlist}` argv placeholder (a reviewed risk-model extension)
lets `web.dir-enum-gobuster` take an operator-supplied absolute path such as a
[SecLists](https://github.com/danielmiessler/SecLists) list, verified end-to-end
on Kali with `/usr/share/seclists/Discovery/Web-Content/common.txt`, and **remote
wordlist discovery** — `hackbot wordlists list --runner remote` lists `*.txt`
files under a fixed code-owned allowlist of remote roots, display-only, verified
on Kali against SecLists, and **operator-customizable report templates** —
explicit `--templates-dir`, strict allowlisted placeholders, and
fail-before-output validation.

1. **Reviewed recon skills / internal-recon** stays disabled unless an
   explicitly-authorized internal profile is confirmed.
2. **Provider gateway / MCP** (loopback-only) when model-in-the-loop work starts.

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
