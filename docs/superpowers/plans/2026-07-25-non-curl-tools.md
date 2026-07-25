# Non-curl Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add `dns.lookup` (dig) and `tls.cert` (openssl s_client) L0 actions,
proving the substrate generalizes beyond curl.

**Architecture:** Add `dig`/`openssl` path resolution and two conditional L0
definitions; extend the lab fixtures (scope `domains: [localhost]`, a throwaway
`tls_server`); cover registry shape and end-to-end execution.

**Tech Stack:** Python 3.11+ stdlib (`ssl`, `subprocess`, `http.server`),
existing `hackbot.tools`/`hackbot.risk`, pytest, Ruff, mypy. Tools: dig, openssl.

## Global Constraints

- Both actions are L0 passive, tool-backed, in-scope only; registered only when
  the tool resolves.
- No shell, no argv from model/target content. The TLS test key is a throwaway
  generated at test time and never committed.
- Test-first; each test observed failing for the intended reason first.

---

### Task 1: Resolve dig/openssl and register the actions

**Files:**
- Modify: `src/hackbot/tools/actions.py`
- Modify: `tests/tools/test_actions.py`
- Modify: `tests/tools/conftest.py`

- [ ] **Step 1: Write failing registry-shape tests**

Add to `tests/tools/test_actions.py`:

```python
from hackbot.tools.actions import dig_path, openssl_path


@pytest.mark.skipif(dig_path() is None, reason="dig not installed")
def test_dns_lookup_is_registered_l0():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("dns.lookup")
    assert d.effective_floor is RiskLevel.L0
    assert d.network_access is True and d.uses_external_tool is True
    assert d.state_changing is False
    assert d.argv_template[-1] == "{target}" and "+short" in d.argv_template


@pytest.mark.skipif(openssl_path() is None, reason="openssl not installed")
def test_tls_cert_is_registered_l0():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("tls.cert")
    assert d.effective_floor is RiskLevel.L0
    assert d.network_access is True and d.uses_external_tool is True
    assert d.state_changing is False
    assert d.argv_template[-1] == "{target}" and "s_client" in d.argv_template
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py -q`
Expected: `ImportError` for `dig_path`/`openssl_path`, then `RegistryError`.

- [ ] **Step 3: Add resolution helpers and register the actions**

In `src/hackbot/tools/actions.py`, add candidate tuples and helpers beside the
curl ones:

```python
_DIG_CANDIDATES: tuple[str, ...] = ("/usr/bin/dig", "/opt/homebrew/bin/dig", "/usr/local/bin/dig")
_OPENSSL_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/openssl",
    "/opt/homebrew/bin/openssl",
    "/usr/local/bin/openssl",
)


def dig_path() -> str | None:
    return resolve_executable(_DIG_CANDIDATES)


def openssl_path() -> str | None:
    return resolve_executable(_OPENSSL_CANDIDATES)
```

Inside `_build_actions`, after the curl block, add:

```python
    dig = dig_path()
    if dig is not None:
        definitions.append(
            ActionDefinition(
                "dns.lookup",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=dig,
                argv_template=(dig, "+short", "{target}"),
            )
        )
    openssl = openssl_path()
    if openssl is not None:
        definitions.append(
            ActionDefinition(
                "tls.cert",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=openssl,
                argv_template=(openssl, "s_client", "-connect", "{target}"),
            )
        )
```

Update `__all__` to include `dig_path` and `openssl_path`.

- [ ] **Step 4: Extend the lab fixtures**

In `tests/tools/conftest.py`, add `localhost` to the lab scope:

```python
    "scope": {"in_scope": {"cidrs": ["127.0.0.0/8"], "domains": ["localhost"]}},
```

and add a throwaway TLS server fixture (import `ssl`, `subprocess`, and
`openssl_path` at the top of the file):

```python
@pytest.fixture
def tls_server(tmp_path):
    openssl = openssl_path()
    if openssl is None:
        pytest.skip("openssl not installed")
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
         "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
```

- [ ] **Step 5: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py -q`
Expected: all pass (per-tool cases skip when the tool is absent).

- [ ] **Step 6: Commit**

```bash
git add src/hackbot/tools/actions.py tests/tools/test_actions.py tests/tools/conftest.py
git commit -m "feat: add dns.lookup (dig) and tls.cert (openssl) L0 actions"
```

---

### Task 2: End-to-end DNS and TLS

**Files:**
- Create: `tests/tools/test_non_curl_e2e.py`

- [ ] **Step 1: Write failing end-to-end tests**

```python
"""End-to-end: dns.lookup and tls.cert run through the substrate."""

from datetime import UTC, datetime

from hackbot.audit.tool_runs import AuditSink
from hackbot.evidence.store import EvidenceStore
from hackbot.risk.context import load_policy_context
from hackbot.risk.models import ActionRequest, DecisionKind
from hackbot.tools.actions import REAL_ACTIONS, dig_path, openssl_path
from hackbot.tools.adapter import run_action
from hackbot.tools.runner import CommandRunner


def _request(context, action_id, target, argv):
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id=action_id,
        target=target,
        argv=argv,
        hypothesis_id="hyp-1",
        rationale="Probe one in-scope lab asset once.",
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


def _run(lab_engagement, request, definition, timeout=15.0):
    context = load_policy_context(lab_engagement)
    return run_action(
        definition,
        request,
        context,
        now=datetime.now(UTC),
        runner=CommandRunner(timeout_seconds=timeout),
        audit=AuditSink(lab_engagement),
        evidence=EvidenceStore(lab_engagement),
    )


@pytest.mark.skipif(dig_path() is None, reason="dig not installed")
def test_dns_lookup_executes_in_scope(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("dns.lookup")
    argv = (dig_path(), "+short", "localhost")
    outcome = _run(lab_engagement, _request(context, "dns.lookup", "localhost", argv), definition)
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert outcome.command_result.exit_code == 0
    assert outcome.evidence_run_id


@pytest.mark.skipif(openssl_path() is None, reason="openssl not installed")
def test_tls_cert_captures_certificate_in_scope(lab_engagement, tls_server):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("tls.cert")
    argv = (openssl_path(), "s_client", "-connect", tls_server)
    outcome = _run(lab_engagement, _request(context, "tls.cert", tls_server, argv), definition)
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert b"CERTIFICATE" in outcome.command_result.stdout or b"subject=" in outcome.command_result.stdout
    assert outcome.evidence_run_id


@pytest.mark.skipif(openssl_path() is None, reason="openssl not installed")
def test_tls_cert_out_of_scope_is_denied(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("tls.cert")
    argv = (openssl_path(), "s_client", "-connect", "10.0.0.5:443")
    outcome = _run(lab_engagement, _request(context, "tls.cert", "10.0.0.5:443", argv), definition)
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.reason_code == "DENY_SCOPE"
    assert outcome.executed is False
```

Add `import pytest` at the top.

- [ ] **Step 2: Run and verify RED, then GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_non_curl_e2e.py -q`
Expected: initially fails if Task 1 is incomplete; otherwise passes (or skips when
a tool is absent). Since Task 1 registered the actions, this task adds coverage
only — if a test fails, fix the responsible unit in Task 1's files.

- [ ] **Step 3: Commit**

```bash
git add tests/tools/test_non_curl_e2e.py
git commit -m "test: cover dns.lookup and tls.cert end to end"
```

---

### Task 3: Documentation and final regression

**Files:**
- Modify: `docs/tool-execution.md`
- Modify: `README.md`
- Modify: `docs/next-steps.md`

- [ ] **Step 1: Document the new tools**

In `docs/tool-execution.md`, add `dns.lookup` (dig) and `tls.cert` (openssl
s_client) to the actions description (L0 passive, in-scope only; note the TLS
probe exits non-zero on a self-signed certificate but still captures it). Update
README (test count; mention DNS/TLS actions) and `docs/next-steps.md` (mark the
non-curl tools done; next = platform report templates).

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
git commit -m "docs: document dns.lookup and tls.cert"
```

---

## Plan self-review

- **Spec coverage:** dig/openssl resolution + both actions registered + shape
  tests (Task 1), DNS and TLS end-to-end + out-of-scope deny (Task 2), docs +
  regression (Task 3). All spec sections map to a task.
- **Placeholder scan:** none.
- **Type consistency:** `dig_path`/`openssl_path`, action ids, and argv templates
  match spec and tests.
- **Safety boundary:** L0 passive, tool-backed, in-scope only, no shell, no
  model/target-built argv; TLS test key is a throwaway, never committed.
```
