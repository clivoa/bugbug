# Task 6 report — non-executing risk and approval CLI

Commit: `de09c3d..64abe9d` (`feat: expose non-executing risk approval CLI`).

## Scope delivered

Implemented the local, non-executing CLI surface for the risk/approval gate,
following the refinements in `task-6-brief.md` (digest-only pending lookup, not
the plan's obsolete challenge-file path).

Files:

- `src/hackbot/risk/fixtures.py` (new) — immutable `FIXTURE_ACTIONS` registry of
  four inert probes (`fixture.passive` L0, `fixture.low-impact` L1,
  `fixture.intrusive` L2, `fixture.prohibited` L3). No tool/executable/shell/argv.
- `src/hackbot/cli/risk_cmd.py` (new) — strict request parsing + `cmd_evaluate`,
  `cmd_grant`, `cmd_status`. Engagement identity is taken from the loaded
  context, never the request file.
- `src/hackbot/cli/main.py` — `risk` and `approval` subparsers;
  `_read_approval_from_tty` (/dev/tty-only confirmation) and `_render_challenge`.
- `src/hackbot/risk/approvals.py` — `ApprovalStore.challenge_for_pending`
  (digest-only reconstruction from the descriptor-owned pending binding;
  code-owned registry resolution; current-clock preflight;
  `_request_from_binding` helper) and top-level `ActionRegistry`/`RegistryError`
  import.
- Tests: `tests/risk/test_fixtures.py`, `tests/risk/test_cli.py`,
  `tests/risk/test_challenge_lookup.py`, request fixtures
  `tests/risk/fixtures/l{0,2,3}-request.json`, and three offline-install cases in
  `tests/packaging/test_offline_install.py`.

## Exit codes

`0` allow/grant/status · `1` deny/persistence failure · `2` invalid
input/context/digest or missing `config` extra · `3` TTY unavailable/mismatch ·
`4` L2 persisted as pending.

## TDD RED→GREEN evidence

- `test_fixtures.py`: RED `ModuleNotFoundError: hackbot.risk.fixtures`; GREEN
  after adding the registry.
- `test_cli.py`: RED `SystemExit: 2` (unknown `risk`/`approval` subcommands);
  GREEN after wiring parsers + `risk_cmd`.
- `test_challenge_lookup.py`: RED `AttributeError` (no `challenge_for_pending`);
  GREEN after implementing it.

### Notable RED diagnosis

- L0 fixture is `network_access=True`, so an inactive request tripped
  `DENY_RATE`; the L0 fixture request was made active (rate/concurrency = 1).
- `test_risk_evaluate_l2_*` intermittently hit `DENY_APPROVAL_SECRET`: the
  pytest tmp path embedded the test-function name, and `test_ri`+`sk_evaluate…`
  matched the Stripe-style `sk_[…]{12,}` secret pattern that `build_challenge`
  scans over the engagement path. Root cause is the test name, not the code;
  the L2-reaching tests were renamed to drop the `risk_` adjacency. (Observation
  for maintainers: the fail-closed secret scan covers the absolute engagement
  path, so an operator path containing such a token would also be refused —
  pre-existing behavior, out of scope for this task.)

## Verification

- `pytest tests/risk tests/packaging` — all pass (CLI, fixtures, challenge
  lookup, offline install incl. `risk`/`approval --help` and clean
  missing-`config` failure).
- Full suite `pytest -q` — 692 passed.
- `ruff check .` clean; `ruff format --check` clean for changed files; `mypy src`
  clean.
