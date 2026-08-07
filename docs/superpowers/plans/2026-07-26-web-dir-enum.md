# Web Directory Enumeration (ffuf) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a gated `web.dir-enum` (ffuf) action with a bundled code-owned
wordlist, tested end to end against a local lab.

**Architecture:** Bundle a wordlist + ffuf resolver in `tools/actions.py` (the
existing `{target}` placeholder carries the FUZZ URL); package `*.txt` in the
wheel; record provenance; drive execution through the gate (`tool run --approve`).

**Tech Stack:** Python 3.11+ stdlib, existing `hackbot.tools`/`hackbot.risk`,
pytest, Ruff, mypy. ffuf installed at `/opt/homebrew/bin/ffuf`.

## Global Constraints

- `web.dir-enum` is L2 (high_volume) → TTY approval; in-scope only; recon only.
- No reviewed risk-model change (FUZZ lives in `{target}`; wordlist is bundled).
- Attribution `CyberNeon Recon Bundle`; no internal-recon; nothing L3.
- Test-first.

---

### Task 1: Bundled wordlist, ffuf resolver, web.dir-enum action, wheel packaging

**Files:**
- Create: `src/hackbot/tools/wordlists/web-content.txt`
- Modify: `src/hackbot/tools/actions.py`
- Modify: `scripts/build_wheel.py`
- Modify: `tests/tools/test_actions.py`
- Modify: `tests/tools/test_adapter.py`

- [ ] **Step 1: Add the bundled wordlist**

Create `src/hackbot/tools/wordlists/web-content.txt` with common paths, one per
line:

```
admin
login
robots.txt
.git/config
.env
api
api/v1
dashboard
config
backup
uploads
.well-known/security.txt
index.php
wp-admin
phpmyadmin
server-status
actuator
swagger
graphql
```

- [ ] **Step 2: Write failing shape + gate tests**

Add to `tests/tools/test_actions.py`:

```python
from hackbot.tools.actions import ffuf_path, web_content_wordlist


@pytest.mark.skipif(ffuf_path() is None, reason="ffuf not installed")
def test_web_dir_enum_is_registered_l2_high_volume():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("web.dir-enum")
    assert d.effective_floor is RiskLevel.L2
    assert d.high_volume is True
    assert d.network_access is True and d.uses_external_tool is True
    assert "-u" in d.argv_template and "{target}" in d.argv_template
    assert web_content_wordlist() in d.argv_template


def test_web_content_wordlist_exists():
    import os

    assert os.path.isfile(web_content_wordlist())
```

Add to `tests/tools/test_adapter.py` a gate test (ffuf-gated) proving L2 is not
executed without approval:

```python
@pytest.mark.skipif(_ffuf() is None, reason="ffuf not installed")
def test_web_dir_enum_requires_approval(lab_engagement):
    from hackbot.tools.actions import REAL_ACTIONS, ffuf_path, web_content_wordlist

    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("web.dir-enum")
    target = "http://127.0.0.1/FUZZ"
    argv = (ffuf_path(), "-s", "-u", target, "-w", web_content_wordlist())
    request = ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id="web.dir-enum",
        target=target,
        argv=argv,
        hypothesis_id="hyp-1",
        rationale="Enumerate one in-scope lab path set once.",
        rate=1,
        concurrency=1,
        data_touched="Public lab responses.",
        expected_impact="One low-rate directory sweep.",
        stop_condition="Stop on any error.",
        cleanup_plan="No state created.",
        program_rule="Authorized lab enumeration.",
        required_headers=(),
        requested_risk=None,
    )
    outcome = run_action(
        definition,
        request,
        context,
        now=datetime.now(UTC),
        runner=FakeRunner(),
        audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert outcome.executed is False
```

Add `from hackbot.tools.actions import ffuf_path as _ffuf` (or a small local
import) near the top of `test_adapter.py`.

- [ ] **Step 3: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py tests/tools/test_adapter.py -q`
Expected: `ImportError` for `ffuf_path`/`web_content_wordlist`, then `RegistryError`.

- [ ] **Step 4: Implement resolver, wordlist accessor, and action**

In `src/hackbot/tools/actions.py`, add near the top:

```python
from pathlib import Path

_FFUF_CANDIDATES: tuple[str, ...] = (
    "/opt/homebrew/bin/ffuf",
    "/usr/local/bin/ffuf",
    "/usr/bin/ffuf",
)
_WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"


def ffuf_path() -> str | None:
    return resolve_executable(_FFUF_CANDIDATES)


def web_content_wordlist() -> str:
    return str(_WORDLIST_DIR / "web-content.txt")
```

In `_build_definitions`, after the nmap block:

```python
    ffuf = ffuf_path()
    if ffuf is not None and Path(web_content_wordlist()).is_file():
        definitions.append(
            ActionDefinition(
                "web.dir-enum",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                high_volume=True,
                executable=ffuf,
                argv_template=(ffuf, "-s", "-u", "{target}", "-w", web_content_wordlist()),
            )
        )
```

Update `__all__` to add `ffuf_path` and `web_content_wordlist`.

- [ ] **Step 5: Package `*.txt` in the wheel**

In `scripts/build_wheel.py`, after the `*.py` collection loop, add:

```python
    for data in sorted((SRC / name).rglob("*.txt")):
        if "__pycache__" in data.parts:
            continue
        members.append((str(data.relative_to(SRC)), data.read_bytes()))
```

- [ ] **Step 6: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py tests/tools/test_adapter.py -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/hackbot/tools/wordlists/web-content.txt src/hackbot/tools/actions.py \
  scripts/build_wheel.py tests/tools/test_actions.py tests/tools/test_adapter.py
git commit -m "feat: add gated web.dir-enum ffuf action with bundled wordlist"
```

---

### Task 2: Provenance, end-to-end run, and packaging

**Files:**
- Modify: `src/hackbot/skills/promotion.py`
- Modify: `tests/tools/test_cli.py`
- Modify: `tests/packaging/test_offline_install.py`

- [ ] **Step 1: Write failing e2e + packaging tests**

Add to `tests/tools/test_cli.py`:

```python
from hackbot.tools.actions import ffuf_path, web_content_wordlist


def _write_dir_enum_request(path: Path, target: str) -> Path:
    request = path / "request.json"
    request.write_text(
        json.dumps(
            {
                "action_id": "web.dir-enum",
                "target": target,
                "argv": [
                    ffuf_path() or "/opt/homebrew/bin/ffuf",
                    "-s",
                    "-u",
                    target,
                    "-w",
                    web_content_wordlist(),
                ],
                "hypothesis_id": "hyp-1",
                "rationale": "Enumerate one in-scope lab path set once.",
                "rate": 1,
                "concurrency": 1,
                "data_touched": "Public lab responses.",
                "expected_impact": "One low-rate directory sweep.",
                "stop_condition": "Stop on any error.",
                "cleanup_plan": "No state created.",
                "program_rule": "Authorized lab enumeration.",
                "required_headers": [],
                "requested_risk": None,
            }
        )
    )
    return request


@pytest.mark.skipif(ffuf_path() is None, reason="ffuf not installed")
def test_tool_run_web_dir_enum_approve_executes(
    lab_engagement, tmp_path, capsys, monkeypatch, local_server
):
    monkeypatch.setattr("hackbot.cli.main._read_approval_from_tty", lambda _c: None)
    target = local_server.rstrip("/") + "/FUZZ"
    request = _write_dir_enum_request(tmp_path, target)
    code = app(
        [
            "tool",
            "run",
            "web.dir-enum",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--approve",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["executed"] is True
    assert payload["exit_code"] == 0
    assert payload["evidence_run_id"]
    run_dir = lab_engagement / "evidence" / payload["evidence_run_id"]
    assert b"admin" in (run_dir / "stdout").read_bytes()  # lab returns 200 for all paths
```

Add to `tests/packaging/test_offline_install.py`:

```python
def test_wordlist_is_packaged(offline_venv):
    import glob

    hits = glob.glob(
        str(
            offline_venv
            / "lib"
            / "python*"
            / "site-packages"
            / "hackbot"
            / "tools"
            / "wordlists"
            / "web-content.txt"
        )
    )
    assert hits, "bundled wordlist missing from the installed wheel"
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_cli.py tests/packaging/test_offline_install.py -q`
Expected: provenance/e2e/packaging failures.

- [ ] **Step 3: Add provenance**

In `src/hackbot/skills/promotion.py`, add to `PROMOTED_ACTIONS`:

```python
    "web.dir-enum": _p("recon/parameter-discovery", "note-enumeracao-diretorios", "2", "explicit"),
```

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools tests/skills tests/packaging/test_offline_install.py -q`
Expected: all pass (the e2e runs ffuf against the loopback lab).

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/skills/promotion.py tests/tools/test_cli.py tests/packaging/test_offline_install.py
git commit -m "feat: run web.dir-enum end to end and record provenance"
```

---

### Task 3: Documentation and final regression

**Files:**
- Modify: `docs/skill-promotion.md`
- Modify: `README.md`
- Modify: `docs/next-steps.md`

- [ ] **Step 1: Document web.dir-enum**

In `docs/skill-promotion.md`, add `web.dir-enum` (ffuf, L2, bundled wordlist,
FUZZ in the target URL) to the promoted-actions table and note it needs ffuf +
TTY approval. Update README (test count; mention dir enumeration) and
`docs/next-steps.md` (mark ffuf dir-enum done; next = custom-wordlist `{wordlist}`
placeholder and the Kali SSH runner).

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
git add docs/skill-promotion.md README.md docs/next-steps.md
git commit -m "docs: document web.dir-enum"
```

---

## Plan self-review

- **Spec coverage:** wordlist + resolver + action + wheel packaging (Task 1),
  provenance + e2e + packaging test (Task 2), docs + regression (Task 3).
- **Placeholder scan:** none.
- **Type consistency:** `ffuf_path`/`web_content_wordlist`, `web.dir-enum`, and the
  provenance entry match across tasks.
- **Safety boundary:** L2 gated, in-scope only, recon only, attributed; no
  model change; no internal-recon; no L3.
```
