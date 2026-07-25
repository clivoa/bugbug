# Task 7 report — documentation, packaging, and final safety regression

Commit: `64abe9d..8d04dad` (`docs: verify risk and approval safety gate`).

## Scope delivered

- `docs/risk-and-approval.md` (new) — evaluation order and reason codes, L0–L3
  semantics, the program restrictions approval cannot override, the five-minute
  single-use action-bound grant lifecycle, exit codes, the on-disk approval
  layout, TTY-only confirmation, the inert fixture actions, and worked examples
  using only `example.com` / the sanitized sample engagement.
- `README.md` — status refreshed; test count updated to 692; `risk`/`approval`
  added to the command list and quick-start; new engine bullet.
- `SECURITY.md` — distinguishes the implemented, code-enforced approval gate
  (against inert fixtures today) from future, separately reviewed tool execution.
- `scripts/smoke_test.sh` — added offline `risk --help`, `risk evaluate --help`,
  and `approval --help` checks; no smoke step performs a target/provider request.
- `conftest.py` — ruff-formatted (blank line after the module docstring).

## Verification gates (all green)

```
.venv/bin/python -m pytest -q -ra      # 692 passed
.venv/bin/ruff check .                  # All checks passed!
.venv/bin/ruff format --check .         # 82 files already formatted
.venv/bin/mypy src                      # Success: no issues found in 35 source files
scripts/smoke_test.sh                   # SMOKE TEST PASSED (incl. risk/approval help)
git diff --check                        # clean
```

## Outcome

The deterministic L0–L3 policy gate and single-use, five-minute L2 approval
lifecycle are implemented, exercised end to end against inert fixtures, and
documented. No provider call, subprocess, socket, target-network request, or
real tool adapter was added. Attack-skill / tool-execution work remains a
separate, later phase that must pass this gate.
