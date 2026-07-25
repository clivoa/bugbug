# Passive HTTP Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add two L0 passive HTTP probes (`net.http-head`, `net.http-options`) to
the code-owned action registry, exercised through the existing substrate.

**Architecture:** Extend `_build_actions` with two curl-backed L0 definitions;
add `do_HEAD`/`do_OPTIONS` to the lab server fixture; cover registry shape and
end-to-end execution.

**Tech Stack:** Python 3.11+ stdlib, existing `hackbot.tools`/`hackbot.risk`,
pytest, Ruff, mypy. curl is the only external tool.

## Global Constraints

- No new external tool; both actions are L0, curl-backed, in-scope only.
- OPTIONS is not `state_changing` (L0). No shell, no argv from model/target.
- Test-first; each test observed failing for the intended reason first.

---

### Task 1: Register net.http-head and net.http-options

**Files:**
- Modify: `src/hackbot/tools/actions.py`
- Modify: `tests/tools/test_actions.py`
- Modify: `tests/tools/conftest.py`
- Modify: `tests/tools/test_http_get_e2e.py`

- [ ] **Step 1: Write failing registry + e2e tests**

Add to `tests/tools/test_actions.py`:

```python
@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_http_head_and_options_are_registered_l0():
    from hackbot.risk.models import RiskLevel

    for action_id, extra in (("net.http-head", ()), ("net.http-options", ("-X", "OPTIONS"))):
        definition = REAL_ACTIONS.require(action_id)
        assert definition.minimum_risk is RiskLevel.L0
        assert definition.effective_floor is RiskLevel.L0
        assert definition.network_access is True
        assert definition.uses_external_tool is True
        assert definition.state_changing is False
        assert definition.argv_template[-1] == "{target}"
        for token in extra:
            assert token in definition.argv_template
```

Add `do_HEAD` / `do_OPTIONS` to `_Handler` in `tests/tools/conftest.py`:

```python
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("X-Lab", "head-ok")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET,HEAD,OPTIONS,POST")
        self.end_headers()
```

Add to `tests/tools/test_http_get_e2e.py` (reuse its `_request` by generalizing it
to take an `action_id`/`argv`; or add a small local helper):

```python
import pytest as _pytest


@_pytest.mark.parametrize(
    "action_id,argv_tail",
    [
        ("net.http-head", ("-sS", "-I", "--max-time", "10")),
        ("net.http-options", ("-sS", "-i", "-X", "OPTIONS", "--max-time", "10")),
    ],
)
def test_passive_probe_executes_in_scope(lab_engagement, local_server, action_id, argv_tail):
    from datetime import UTC, datetime

    from hackbot.audit.tool_runs import AuditSink
    from hackbot.evidence.store import EvidenceStore
    from hackbot.risk.context import load_policy_context
    from hackbot.risk.models import ActionRequest, DecisionKind
    from hackbot.tools.adapter import run_action

    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require(action_id)
    argv = (curl_path(), *argv_tail, local_server)
    request = ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id=action_id,
        target=local_server,
        argv=argv,
        hypothesis_id="hyp-1",
        rationale="Probe one in-scope lab URL once.",
        rate=1,
        concurrency=1,
        data_touched="Public lab response.",
        expected_impact="One low-rate passive probe.",
        stop_condition="Stop on any error.",
        cleanup_plan="No state created.",
        program_rule="Authorized lab probe.",
        required_headers=(),
        requested_risk=None,
    )
    outcome = run_action(
        definition, request, context, now=datetime.now(UTC),
        runner=CommandRunner(), audit=AuditSink(lab_engagement),
        evidence=EvidenceStore(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert outcome.command_result.exit_code == 0
    assert outcome.evidence_run_id
```

(`REAL_ACTIONS`, `curl_path`, `CommandRunner` are already imported in the e2e
file; add any missing imports at the top.)

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py tests/tools/test_http_get_e2e.py -q`
Expected: `RegistryError` for the new ids.

- [ ] **Step 3: Register the actions**

In `src/hackbot/tools/actions.py`, inside `_build_actions` (after the http-post
append), add:

```python
        definitions.append(
            ActionDefinition(
                "net.http-head",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=curl,
                argv_template=(curl, "-sS", "-I", "--max-time", "10", "{target}"),
            )
        )
        definitions.append(
            ActionDefinition(
                "net.http-options",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=curl,
                argv_template=(curl, "-sS", "-i", "-X", "OPTIONS", "--max-time", "10", "{target}"),
            )
        )
```

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools -q`
Expected: all pass (curl-gated cases skip when curl is absent).

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/tools/actions.py tests/tools/test_actions.py \
  tests/tools/conftest.py tests/tools/test_http_get_e2e.py
git commit -m "feat: add net.http-head and net.http-options L0 probes"
```

---

### Task 2: Documentation and final regression

**Files:**
- Modify: `docs/tool-execution.md`
- Modify: `README.md`
- Modify: `docs/next-steps.md`

- [ ] **Step 1: Document the new probes**

In `docs/tool-execution.md`, extend the actions list to name `net.http-head` and
`net.http-options` (L0 passive, curl, in-scope only). Update README (test count,
mention the probes in the tool line) and `docs/next-steps.md` (note the added
probes; DNS/TLS via new tools remains a follow-up).

- [ ] **Step 2: Run all verification gates**

```bash
.venv/bin/python -m pytest -q -ra
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
scripts/smoke_test.sh
git diff --check
```

Expected: zero failures, Ruff clean, formatting clean, mypy clean, offline smoke
pass, no whitespace errors. Refresh the README/next-steps test count.

- [ ] **Step 3: Commit**

```bash
git add docs/tool-execution.md README.md docs/next-steps.md
git commit -m "docs: document net.http-head and net.http-options"
```

---

## Plan self-review

- **Spec coverage:** both L0 probes registered + shape-tested (Task 1), end-to-end
  execution (Task 1), docs + regression (Task 2). All spec sections map to a task.
- **Placeholder scan:** none.
- **Type consistency:** action ids and argv templates match spec and tests.
- **Safety boundary:** L0 passive, curl-backed, in-scope only, no new tool, no
  shell, no model/target-built argv.
```
