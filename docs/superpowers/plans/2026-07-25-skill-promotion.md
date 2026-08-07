# Recon-bundle Skill Promotion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Promote reviewed recon-bundle skills into code-owned, gated actions
(L0 DNS record lookups; an L2 nmap port scan) with recorded provenance and
attribution, plus a `hackbot skills` listing.

**Architecture:** New code-owned actions in `tools/actions.py` (nmap resolver +
conditional registration; expose registered ids); a provenance table in
`skills/promotion.py` validated against the generated manifest; a stdlib-only
`hackbot skills list` CLI.

**Tech Stack:** Python 3.11+ stdlib, existing `hackbot.tools`/`hackbot.risk`,
PyYAML (tests only, to read the manifest), pytest, Ruff, mypy. Tools: dig
(present), nmap (conditional).

## Global Constraints

- Every promoted action stays gated (scope + risk + approval); L2 needs TTY
  approval; runs only in-scope.
- Recon only. No internal-recon, no exploitation, nothing L3.
- The raw bundle HTML is never read; only the generated manifest/notes.
- Attribution `CyberNeon Recon Bundle (public source; no formal license)` recorded for every
  bundle-derived action.
- Test-first; each test observed failing for the intended reason first.

---

### Task 1: Promote DNS record and port-scan actions

**Files:**
- Modify: `src/hackbot/tools/actions.py`
- Modify: `tests/tools/test_actions.py`
- Modify: `tests/tools/test_non_curl_e2e.py`

**Interfaces:**
- Produces: `nmap_path()`, `REGISTERED_ACTION_IDS`; new actions `dns.txt`,
  `dns.mx`, `dns.ns` (L0), `net.port-scan` (L2, conditional).

- [ ] **Step 1: Write failing shape + e2e tests**

Add to `tests/tools/test_actions.py`:

```python
from hackbot.tools.actions import REGISTERED_ACTION_IDS, nmap_path


@pytest.mark.skipif(dig_path() is None, reason="dig not installed")
@pytest.mark.parametrize(
    "action_id,record", [("dns.txt", "TXT"), ("dns.mx", "MX"), ("dns.ns", "NS")]
)
def test_dns_record_actions_are_registered_l0(action_id, record):
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require(action_id)
    assert d.effective_floor is RiskLevel.L0
    assert d.network_access is True and d.uses_external_tool is True
    assert d.argv_template[-1] == record and "{target}" in d.argv_template


@pytest.mark.skipif(nmap_path() is None, reason="nmap not installed")
def test_port_scan_is_registered_l2_high_volume():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("net.port-scan")
    assert d.effective_floor is RiskLevel.L2
    assert d.high_volume is True
    assert d.network_access is True and d.uses_external_tool is True
    assert d.argv_template[-1] == "{target}"


def test_registered_action_ids_lists_only_available_actions():
    assert "dns.txt" in REGISTERED_ACTION_IDS  # dig present in this environment
    if nmap_path() is None:
        assert "net.port-scan" not in REGISTERED_ACTION_IDS
```

Add to `tests/tools/test_non_curl_e2e.py`:

```python
@pytest.mark.skipif(dig_path() is None, reason="dig not installed")
@pytest.mark.parametrize(
    "action_id,record", [("dns.txt", "TXT"), ("dns.mx", "MX"), ("dns.ns", "NS")]
)
def test_dns_record_lookup_executes_in_scope(lab_engagement, action_id, record):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require(action_id)
    argv = (dig_path(), "+short", "127.0.0.1", record)
    outcome = _run(lab_engagement, _request(context, action_id, "127.0.0.1", argv), definition)
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert outcome.command_result.exit_code == 0
    assert outcome.evidence_run_id
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/tools/test_actions.py tests/tools/test_non_curl_e2e.py -q`
Expected: `ImportError` for `nmap_path`/`REGISTERED_ACTION_IDS`, then `RegistryError`.

- [ ] **Step 3: Add the nmap resolver, promote actions, expose ids**

In `src/hackbot/tools/actions.py`, add candidates + resolver beside the others:

```python
_NMAP_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/nmap",
    "/opt/homebrew/bin/nmap",
    "/usr/local/bin/nmap",
)


def nmap_path() -> str | None:
    return resolve_executable(_NMAP_CANDIDATES)
```

Refactor `_build_actions` to build a list and expose ids. Rename it to
`_build_definitions` returning `list[ActionDefinition]`, and at module level:

```python
def _build_definitions() -> list[ActionDefinition]:
    definitions: list[ActionDefinition] = []
    curl = curl_path()
    if curl is not None:
        # ... existing curl definitions unchanged ...
    dig = dig_path()
    if dig is not None:
        # ... existing dns.lookup unchanged ...
        for action_id, record in (("dns.txt", "TXT"), ("dns.mx", "MX"), ("dns.ns", "NS")):
            definitions.append(
                ActionDefinition(
                    action_id,
                    RiskLevel.L0,
                    network_access=True,
                    uses_external_tool=True,
                    executable=dig,
                    argv_template=(dig, "+short", "{target}", record),
                )
            )
    openssl = openssl_path()
    if openssl is not None:
        # ... existing tls.cert unchanged ...
    nmap = nmap_path()
    if nmap is not None:
        definitions.append(
            ActionDefinition(
                "net.port-scan",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                high_volume=True,
                executable=nmap,
                argv_template=(nmap, "-Pn", "-T3", "--top-ports", "100", "{target}"),
            )
        )
    return definitions


_DEFINITIONS = _build_definitions()
REAL_ACTIONS = ActionRegistry(_DEFINITIONS)
REGISTERED_ACTION_IDS: tuple[str, ...] = tuple(d.action_id for d in _DEFINITIONS)
```

Update `__all__` to add `nmap_path` and `REGISTERED_ACTION_IDS`. (Fold the
existing curl/dig/openssl append blocks into `_build_definitions` unchanged.)

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/tools -q`
Expected: all pass (nmap cases skip when nmap is absent).

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/tools/actions.py tests/tools/test_actions.py tests/tools/test_non_curl_e2e.py
git commit -m "feat: promote dns record and nmap port-scan actions"
```

---

### Task 2: Provenance and attribution

**Files:**
- Create: `src/hackbot/skills/promotion.py`
- Create: `tests/skills/__init__.py`
- Create: `tests/skills/test_promotion.py`

**Interfaces:**
- Produces: `SkillProvenance`, `PROMOTED_ACTIONS`, `ATTRIBUTION`.

- [ ] **Step 1: Write failing provenance tests**

```python
import yaml

from hackbot.skills.promotion import PROMOTED_ACTIONS
from hackbot.tools.actions import REGISTERED_ACTION_IDS

_MANIFEST = "generated/recon-bundle/manifest.yaml"


def _manifest_pairs():
    m = yaml.safe_load(open(_MANIFEST, encoding="utf-8"))
    pairs, internal = set(), set()
    for s in m["skills"]:
        pairs.add((s["skill"], s["source_note"]))
        if s.get("internal_pack"):
            internal.add(s["skill"])
    return pairs, internal


def test_every_promotion_maps_to_a_real_reviewed_skill():
    pairs, internal = _manifest_pairs()
    for action_id, prov in PROMOTED_ACTIONS.items():
        assert (prov.skill_id, prov.source_note) in pairs, action_id
        assert prov.skill_id not in internal  # internal-recon is never promoted
        assert "CyberNeon Recon Bundle" in prov.attribution


def test_every_registered_bundle_action_has_provenance():
    for action_id in REGISTERED_ACTION_IDS:
        if action_id in ("net.http-post",):  # generic, not bundle-derived
            continue
        assert action_id in PROMOTED_ACTIONS, action_id
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/skills/test_promotion.py -q`
Expected: `ModuleNotFoundError: hackbot.skills.promotion`.

- [ ] **Step 3: Implement the provenance table**

```python
"""Provenance linking code-owned actions to reviewed recon-bundle skills.

Bundle commands stay data; only generic single-tool argv subsets become
code-owned actions. Attribution to CyberNeon Recon Bundle is recorded per the bundle's
local-reuse-with-attribution terms. internal-recon skills are never promoted.
"""

from __future__ import annotations

from dataclasses import dataclass

ATTRIBUTION = "CyberNeon Recon Bundle (public source; no formal license)"


@dataclass(frozen=True, slots=True)
class SkillProvenance:
    skill_id: str
    source_note: str
    bundle_risk_level: str
    approval_level: str
    attribution: str = ATTRIBUTION


def _p(skill_id: str, note: str, risk: str, approval: str) -> SkillProvenance:
    return SkillProvenance(skill_id, note, risk, approval)


PROMOTED_ACTIONS: dict[str, SkillProvenance] = {
    "tls.cert": _p("recon/tls-certificate-recon", "note-consulta-certificado-tls", "0", "none"),
    "dns.lookup": _p("recon/dns-recon", "note-consulta-dns", "1", "auto-if-in-scope"),
    "dns.txt": _p("recon/dns-recon", "note-consulta-dns", "1", "auto-if-in-scope"),
    "dns.mx": _p("recon/dns-recon", "note-consulta-dns", "1", "auto-if-in-scope"),
    "dns.ns": _p("recon/dns-recon", "note-consulta-dns", "1", "auto-if-in-scope"),
    "net.http-get": _p("recon/web-crawling", "note-web-crawling", "1", "auto-if-in-scope"),
    "net.http-head": _p("recon/web-crawling", "note-web-crawling", "1", "auto-if-in-scope"),
    "net.http-options": _p("recon/web-crawling", "note-web-crawling", "1", "auto-if-in-scope"),
    "net.port-scan": _p("recon/service-fingerprinting", "note-port-scanning-bash", "2", "explicit"),
}

__all__ = ["ATTRIBUTION", "PROMOTED_ACTIONS", "SkillProvenance"]
```

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/skills/test_promotion.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/skills/promotion.py tests/skills/__init__.py tests/skills/test_promotion.py
git commit -m "feat: record recon-bundle provenance and attribution for actions"
```

---

### Task 3: hackbot skills list

**Files:**
- Create: `src/hackbot/cli/skills_cmd.py`
- Modify: `src/hackbot/cli/main.py`
- Create: `tests/skills/test_cli.py`

**Interfaces:**
- Produces: `cmd_list`; a `skills` subparser.

- [ ] **Step 1: Write failing CLI tests**

```python
import json

from hackbot.cli.main import app


def test_skills_list_shows_attribution_and_availability(capsys):
    code = app(["skills", "list", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    by_id = {row["action_id"]: row for row in payload["skills"]}
    dns = by_id["dns.txt"]
    assert dns["available"] is True
    assert dns["skill"] == "recon/dns-recon"
    assert "CyberNeon Recon Bundle" in dns["attribution"]
    assert dns["bundle_risk_level"] == "1"


def test_skills_list_marks_non_bundle_actions(capsys):
    app(["skills", "list", "--json"])
    payload = json.loads(capsys.readouterr().out)
    by_id = {row["action_id"]: row for row in payload["skills"]}
    if "net.http-post" in by_id:
        assert by_id["net.http-post"]["skill"] is None
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/skills/test_cli.py -q`
Expected: `SystemExit: 2` — no `skills` subcommand.

- [ ] **Step 3: Implement the CLI**

```python
"""Local, stdlib-only listing of code-owned actions and bundle provenance."""

from __future__ import annotations

import json


def cmd_list(*, as_json: bool) -> int:
    from hackbot.skills.promotion import PROMOTED_ACTIONS
    from hackbot.tools.actions import REGISTERED_ACTION_IDS

    ids = sorted(set(REGISTERED_ACTION_IDS) | set(PROMOTED_ACTIONS))
    rows: list[dict[str, object]] = []
    for action_id in ids:
        prov = PROMOTED_ACTIONS.get(action_id)
        rows.append(
            {
                "action_id": action_id,
                "available": action_id in REGISTERED_ACTION_IDS,
                "skill": prov.skill_id if prov else None,
                "source_note": prov.source_note if prov else None,
                "bundle_risk_level": prov.bundle_risk_level if prov else None,
                "approval_level": prov.approval_level if prov else None,
                "attribution": prov.attribution if prov else None,
            }
        )
    if as_json:
        print(json.dumps({"skills": rows}, indent=2, sort_keys=True))
    else:
        for row in rows:
            mark = "available" if row["available"] else "unavailable"
            skill = row["skill"] or "(not bundle-derived)"
            print(f"  {row['action_id']:<18} [{mark:<11}] {skill}")
    return 0
```

Wire in `src/hackbot/cli/main.py`:

```python
def _cmd_skills(args: argparse.Namespace) -> int:
    from hackbot.cli import skills_cmd

    if args.saction == "list":
        return skills_cmd.cmd_list(as_json=args.json)
    return 2
```

```python
    sk = sub.add_parser("skills", help="list code-owned actions and recon-bundle provenance")
    sk_sub = sk.add_subparsers(dest="saction", required=True)
    sk_list = sk_sub.add_parser("list", help="list actions, availability, and attribution")
    sk_list.add_argument("--json", action="store_true")
    sk.set_defaults(func=_cmd_skills)
```

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/skills -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/cli/skills_cmd.py src/hackbot/cli/main.py tests/skills/test_cli.py
git commit -m "feat: add hackbot skills list"
```

---

### Task 4: Documentation and final regression

**Files:**
- Create: `docs/skill-promotion.md`
- Modify: `README.md`
- Modify: `docs/next-steps.md`
- Modify: `scripts/smoke_test.sh`

- [ ] **Step 1: Document skill promotion**

`docs/skill-promotion.md`: the provenance model and mandatory attribution, that
promoted actions are recon-only single-tool argv subsets of reviewed skills and
stay gated (L2 → approval), that internal-recon is never promoted and the raw
HTML is never loaded, the promoted actions (DNS records L0; nmap port-scan L2,
requires nmap + TTY approval), and `hackbot skills list`. Update README (test
count; `skills` command; note nmap must be installed for `net.port-scan`) and
`docs/next-steps.md` (mark this done; next = argv-placeholder extension for
fuzzing tools).

- [ ] **Step 2: Extend the offline smoke test**

```bash
( cd /tmp && "$HACKBOT" skills --help >/dev/null ) && echo "skills help ok"
( cd /tmp && "$HACKBOT" skills list >/dev/null ) && echo "skills list ok"
```

- [ ] **Step 3: Run all verification gates**

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

- [ ] **Step 4: Commit**

```bash
git add docs/skill-promotion.md README.md docs/next-steps.md scripts/smoke_test.sh
git commit -m "docs: document recon-bundle skill promotion"
```

---

## Plan self-review

- **Spec coverage:** promoted DNS + port-scan actions (Task 1), provenance +
  manifest validation (Task 2), `skills list` CLI (Task 3), docs + regression
  (Task 4). All spec sections map to a task.
- **Placeholder scan:** none.
- **Type consistency:** `nmap_path`/`REGISTERED_ACTION_IDS`, `SkillProvenance`/
  `PROMOTED_ACTIONS`, and `cmd_list` match across tasks.
- **Safety boundary:** recon-only, gated, attributed; no internal-recon, no L3;
  raw HTML never read; L2 port-scan needs nmap + TTY approval + in-scope.
```
