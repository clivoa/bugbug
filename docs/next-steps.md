# Next steps

Status snapshot after merging the risk & approval engine (Tasks 1–7) into
`main`. Use this as the starting point for the next phase.

## Where the project stands

Implemented and verified (692 tests passing, Ruff/format/mypy clean, offline
smoke pass):

- **Scope engine** (`src/hackbot/scope/`) — default-deny, deny-wins, frozen.
- **Programs / engagements** (`src/hackbot/programs/`) — strict local
  program/scope ingestion; typed `testing_rules`; confirmed-authorization
  context loading.
- **Risk & approval engine** (`src/hackbot/risk/`) — deterministic, fail-closed
  L0–L3 policy gate; canonical L2 challenges; atomic, descriptor-owned,
  single-use, five-minute approval store; see
  [`risk-and-approval.md`](risk-and-approval.md).
- **Non-executing CLI** — `hackbot risk evaluate`, `hackbot approval grant`
  (interactive TTY only), `hackbot approval status`, driven by **inert fixture
  actions** that execute nothing.
- **Secrets** (OS keychain), **doctor**, wheel build + offline smoke test.

Nothing in the tree performs a provider call, subprocess, socket, or
target-network request yet. That boundary is deliberate.

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

1. **Tool adapter substrate** (`src/hackbot/tools/`): a validated argv-array
   runner (no shell), timeouts, output capture as untrusted data, and audit-log
   integration. Write it test-first; keep it provider/network-free until the
   adapter itself is reviewed.
2. **First real action definitions**: start with L0/L1 passive/low-impact HTTP
   probes against local labs (`labs/**`) so the end-to-end path
   (context → evaluate → allow → adapter → evidence) is exercised without any
   external target.
3. **Evidence + audit** (`src/hackbot/evidence/`, `src/hackbot/audit/`): persist
   hypotheses and redacted evidence per engagement; append gate decisions to the
   audit log.
4. **Reviewed recon skills**: promote only normalized, reviewed skills from the
   recon bundle into executable adapters (bundle commands stay data until
   wrapped). Internal-recon stays disabled unless an explicitly-authorized
   internal profile is confirmed.
5. **Provider gateway / MCP** (loopback-only) when model-in-the-loop work starts.

## Guardrails to keep (from CLAUDE.md / SECURITY.md)

- L3 is absolute; program/profile/request/grant/operator can never enable it.
- Discovery ≠ authorization; nothing auto-expands scope.
- Treat all target/tool/MCP output as untrusted data.
- Secrets never enter argv, logs, artifacts, or challenges (the store already
  scans for and rejects them).
- Stop on unexpected scope/egress change or when a target blocks/rate-limits.

## Housekeeping

- The development worktree `.worktrees/risk-approval-engine` and its
  `feat/risk-approval-engine` branch were merged into `main` and removed; `main`
  is now the only branch/worktree.
- Plan and per-task SDD reports: `docs/superpowers/plans/` and
  `.superpowers/sdd/` (progress + task-4…task-7 reports tracked).
