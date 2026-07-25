# Platform Report Renderers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Render a finding into each supported platform's submission format,
structured around the vulnerability scenario, for authorized reporting.

**Architecture:** Extend `Finding` with optional `vulnerability_type` /
`reproduction_steps`; add a data-driven, code-owned per-platform renderer registry
in `reporting/render.py`; expose `hackbot finding report --platform NAME`.

**Tech Stack:** Python 3.11+ stdlib, existing `hackbot.findings`/`reporting`,
pytest, Ruff, mypy. No template engine.

## Global Constraints

- Renderers are code-owned (no `.tmpl` engine, no injection surface).
- Every platform keeps Demonstrated vs Plausible impact separate (rule 10) and
  references evidence by `run_id` (never raw output).
- New Finding fields are additive and optional (default `""`); backward compatible.
- Test-first; each test observed failing for the intended reason first.

---

### Task 1: Extend Finding with vulnerability_type and reproduction_steps

**Files:**
- Modify: `src/hackbot/findings/models.py`
- Modify: `src/hackbot/findings/store.py`
- Modify: `src/hackbot/cli/finding_cmd.py`
- Modify: `tests/findings/test_models.py`
- Modify: `tests/findings/test_store.py`
- Modify: `tests/findings/test_cli.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/findings/test_models.py`:

```python
def test_optional_fields_default_empty():
    f = _finding()
    assert f.vulnerability_type == "" and f.reproduction_steps == ""


def test_optional_fields_round_trip_values():
    f = _finding(vulnerability_type="reflected-xss", reproduction_steps="GET /x?q=<t>")
    assert f.vulnerability_type == "reflected-xss"
    assert f.reproduction_steps == "GET /x?q=<t>"
```

Add to `tests/findings/test_store.py`:

```python
def test_store_round_trips_optional_fields(tmp_path):
    store = FindingStore(tmp_path)
    finding = _finding(tmp_path, vulnerability_type="sqli", reproduction_steps="' OR 1=1 -- ")
    store.add(finding)
    loaded = store.load_all()[0]
    assert loaded.vulnerability_type == "sqli"
    assert loaded.reproduction_steps == "' OR 1=1 -- "
```

Add to `tests/findings/test_cli.py`:

```python
def test_finding_add_accepts_optional_fields(tmp_path, capsys):
    desc = tmp_path / "f.json"
    desc.write_text(
        '{"title":"IDOR on /orders","severity":"high","status":"untested",'
        '"target":"http://127.0.0.1/orders","action_id":"net.http-get",'
        '"evidence_run_id":null,"summary":"Sequential ids.",'
        '"demonstrated_impact":"","plausible_impact":"Read others orders.",'
        '"vulnerability_type":"idor","reproduction_steps":"GET /orders/1002"}'
    )
    code = app(["finding", "add", str(desc), "--engagement", str(tmp_path), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["finding_id"]
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/findings -q`
Expected: failures — `Finding` has no `vulnerability_type`/`reproduction_steps`.

- [ ] **Step 3: Add the fields to the model**

In `src/hackbot/findings/models.py`, append to the dataclass (after `created_at`):

```python
    vulnerability_type: str = ""
    reproduction_steps: str = ""
```

and in `__post_init__` add:

```python
        _text(self.vulnerability_type, name="vulnerability_type", limit=128, allow_empty=True)
        _text(self.reproduction_steps, name="reproduction_steps", limit=8_192, allow_empty=True)
```

- [ ] **Step 4: Carry them in the store**

In `src/hackbot/findings/store.py`, add to `_to_dict`:

```python
        "vulnerability_type": finding.vulnerability_type,
        "reproduction_steps": finding.reproduction_steps,
```

and in `_from_dict`'s `Finding(...)` call:

```python
            vulnerability_type=value.get("vulnerability_type", ""),
            reproduction_steps=value.get("reproduction_steps", ""),
```

- [ ] **Step 5: Accept them (optionally) in the CLI descriptor**

In `src/hackbot/cli/finding_cmd.py`, split the key sets:

```python
_REQUIRED_FINDING_KEYS = frozenset(
    {
        "title",
        "severity",
        "status",
        "target",
        "action_id",
        "evidence_run_id",
        "summary",
        "demonstrated_impact",
        "plausible_impact",
    }
)
_OPTIONAL_FINDING_KEYS = frozenset({"vulnerability_type", "reproduction_steps"})
```

Replace the key checks in `cmd_add`:

```python
        for key in value:
            if key not in _REQUIRED_FINDING_KEYS and key not in _OPTIONAL_FINDING_KEYS:
                raise CliInputError(f"unknown field {key!r}")
        for key in _REQUIRED_FINDING_KEYS:
            if key not in value:
                raise CliInputError(f"missing field {key!r}")
```

and pass the optional fields to `Finding(...)`:

```python
            vulnerability_type=value.get("vulnerability_type", ""),  # type: ignore[arg-type]
            reproduction_steps=value.get("reproduction_steps", ""),  # type: ignore[arg-type]
```

- [ ] **Step 6: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/findings -q`
Expected: all pass (including the existing finding tests).

- [ ] **Step 7: Commit**

```bash
git add src/hackbot/findings/models.py src/hackbot/findings/store.py \
  src/hackbot/cli/finding_cmd.py tests/findings
git commit -m "feat: add vulnerability_type and reproduction_steps to findings"
```

---

### Task 2: Code-owned per-platform renderers

**Files:**
- Modify: `src/hackbot/reporting/render.py`
- Modify: `tests/reporting/test_render.py`

**Interfaces:**
- Produces: `PLATFORMS`, `render(findings, *, engagement_id, platform="generic")`;
  `render_markdown` stays as a generic wrapper.

- [ ] **Step 1: Write failing renderer tests**

Add to `tests/reporting/test_render.py`:

```python
from hackbot.reporting.render import PLATFORMS, render


def _vuln(**over):
    base = dict(
        vulnerability_type="reflected-xss",
        reproduction_steps="GET /search?q=<script>",
        demonstrated_impact="Script executes in the victim session.",
        plausible_impact="Session theft with a missing HttpOnly flag.",
    )
    base.update(over)
    return _finding(**base)


def test_all_platforms_are_supported():
    assert set(PLATFORMS) == {
        "generic",
        "hackerone",
        "bugcrowd",
        "yeswehack",
        "intigriti",
        "immunefi",
    }


@pytest.mark.parametrize("platform", PLATFORMS)
def test_each_platform_keeps_impact_separate_and_names_the_scenario(platform):
    out = render([_vuln()], engagement_id="local-lab", platform=platform)
    assert "reflected-xss" in out
    assert "GET /search?q=<script>" in out  # reproduction steps
    assert "Script executes in the victim session." in out  # demonstrated
    assert "Session theft with a missing HttpOnly flag." in out  # plausible
    lower = out.lower()
    assert "demonstrated" in lower and "plausible" in lower  # separated sections
    assert "20260725T120000Z-0123456789ab" in out  # evidence pointer
    assert "stdout" not in lower  # no raw output


def test_platform_specific_headings():
    h1 = render([_vuln()], engagement_id="e", platform="hackerone")
    assert "Steps To Reproduce" in h1 and "Weakness" in h1
    bc = render([_vuln()], engagement_id="e", platform="bugcrowd")
    assert "Description" in bc and "Bug type" in bc


def test_unknown_platform_raises():
    with pytest.raises(ValueError):
        render([_vuln()], engagement_id="e", platform="nope")
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/reporting/test_render.py -q`
Expected: `ImportError` for `PLATFORMS`/`render`.

- [ ] **Step 3: Implement the data-driven renderers**

Replace `src/hackbot/reporting/render.py` with:

```python
"""Render findings to per-platform markdown reports; never embed raw evidence."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from hackbot.findings.models import Finding, Severity

_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


@dataclass(frozen=True, slots=True)
class _PlatformSpec:
    label: str
    weakness_label: str
    summary_heading: str
    steps_heading: str
    impact_heading: str
    plausible_heading: str


_SPECS: dict[str, _PlatformSpec] = {
    "generic": _PlatformSpec(
        "Generic", "Vulnerability type", "", "**Steps to reproduce**",
        "**Demonstrated impact**", "**Plausible additional impact (untested)**",
    ),
    "hackerone": _PlatformSpec(
        "HackerOne", "Weakness", "### Summary", "### Steps To Reproduce",
        "### Impact", "### Additional impact (plausible, untested)",
    ),
    "bugcrowd": _PlatformSpec(
        "Bugcrowd", "Bug type", "### Description", "### Steps to reproduce",
        "### Impact", "### Additional context (plausible, untested)",
    ),
    "yeswehack": _PlatformSpec(
        "YesWeHack", "Bug type", "### Description", "### Steps to reproduce",
        "### Impact", "### Additional impact (plausible, untested)",
    ),
    "intigriti": _PlatformSpec(
        "Intigriti", "Vulnerability type", "### Description", "### Proof of concept",
        "### Impact", "### Additional impact (plausible, untested)",
    ),
    "immunefi": _PlatformSpec(
        "Immunefi", "Vulnerability type", "### Summary", "### Proof of Concept",
        "### Impact", "### Additional impact (plausible, untested)",
    ),
}

PLATFORMS = tuple(_SPECS)


def _section(heading: str, body: str) -> list[str]:
    body = body.strip() or "_Not provided._"
    return ([heading, "", body, ""] if heading else [body, ""])


def _steps_body(finding: Finding) -> str:
    if finding.reproduction_steps.strip():
        return finding.reproduction_steps
    if finding.evidence_run_id:
        return (
            f"Reproduce via evidence run `{finding.evidence_run_id}` "
            f"(action `{finding.action_id}` against `{finding.target}`)."
        )
    return ""


def _finding_block(finding: Finding, spec: _PlatformSpec) -> str:
    evidence = finding.evidence_run_id or "none"
    lines = [
        f"## {finding.title}",
        "",
        f"- **Severity:** {finding.severity.value}",
        f"- **Status:** {finding.status.value}",
        f"- **{spec.weakness_label}:** {finding.vulnerability_type or 'unspecified'}",
        f"- **Target:** {finding.target}",
        f"- **Action:** {finding.action_id}",
        f"- **Evidence:** {evidence} (redacted, under `evidence/{evidence}/`)",
        "",
    ]
    lines += _section(spec.summary_heading, finding.summary)
    lines += _section(spec.steps_heading, _steps_body(finding))
    lines += _section(spec.impact_heading, finding.demonstrated_impact or "_None demonstrated._")
    lines += _section(spec.plausible_heading, finding.plausible_impact or "_None stated._")
    return "\n".join(lines).rstrip()


def render(findings: Sequence[Finding], *, engagement_id: str, platform: str = "generic") -> str:
    try:
        spec = _SPECS[platform]
    except KeyError as exc:
        raise ValueError(f"unknown platform: {platform}") from exc
    header = [
        f"# Findings — {engagement_id} ({spec.label})",
        "",
        (
            "Claims require reproducible evidence. Demonstrated impact is listed "
            "separately from plausible, untested impact."
        ),
        "",
    ]
    if not findings:
        return "\n".join([*header, "No findings recorded.", ""])
    ordered = sorted(findings, key=lambda f: (_ORDER.index(f.severity), f.finding_id))
    blocks = [f"{len(findings)} finding(s).", ""]
    for finding in ordered:
        blocks.append(_finding_block(finding, spec))
        blocks.append("")
    return "\n".join(header + blocks)


def render_markdown(findings: Sequence[Finding], *, engagement_id: str) -> str:
    return render(findings, engagement_id=engagement_id, platform="generic")
```

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/reporting -q`
Expected: all pass, including the pre-existing generic assertions.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/reporting/render.py tests/reporting/test_render.py
git commit -m "feat: add per-platform report renderers"
```

---

### Task 3: hackbot finding report --platform

**Files:**
- Modify: `src/hackbot/cli/finding_cmd.py`
- Modify: `src/hackbot/cli/main.py`
- Modify: `tests/findings/test_cli.py`

- [ ] **Step 1: Write failing CLI tests**

Add to `tests/findings/test_cli.py`:

```python
def test_finding_report_platform_selects_renderer(tmp_path, capsys):
    app(["finding", "add", str(FIX / "untested.json"), "--engagement", str(tmp_path), "--json"])
    capsys.readouterr()
    code = app(["finding", "report", "--engagement", str(tmp_path), "--platform", "hackerone"])
    out = capsys.readouterr().out
    assert code == 0
    assert "HackerOne" in out and "Steps To Reproduce" in out


def test_finding_report_unknown_platform_is_invalid(tmp_path, capsys):
    code = app(["finding", "report", "--engagement", str(tmp_path), "--platform", "nope"])
    assert code == 2
```

- [ ] **Step 2: Run and verify RED**

Run: `.venv/bin/python -m pytest tests/findings/test_cli.py -q`
Expected: `--platform` is unrecognized / renders generic.

- [ ] **Step 3: Wire the flag**

In `src/hackbot/cli/finding_cmd.py`, change `cmd_report`:

```python
def cmd_report(engagement: str, *, platform: str = "generic") -> int:
    from hackbot.findings.store import FindingError, FindingStore
    from hackbot.reporting.render import render

    try:
        findings = FindingStore(engagement).load_all()
    except FindingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    try:
        report = render(findings, engagement_id=Path(engagement).name, platform=platform)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    print(report)
    return EXIT_OK
```

In `src/hackbot/cli/main.py`, add the argument and pass it (do NOT use argparse
`choices`, so an unknown value returns exit 2 rather than raising):

```python
    fd_report.add_argument(
        "--platform",
        default="generic",
        help="report format: generic|hackerone|bugcrowd|yeswehack|intigriti|immunefi",
    )
```

and in `_cmd_finding`:

```python
    if args.faction == "report":
        return finding_cmd.cmd_report(args.engagement, platform=args.platform)
```

- [ ] **Step 4: Run and verify GREEN**

Run: `.venv/bin/python -m pytest tests/findings/test_cli.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/cli/finding_cmd.py src/hackbot/cli/main.py tests/findings/test_cli.py
git commit -m "feat: add hackbot finding report --platform"
```

---

### Task 4: Documentation and final regression

**Files:**
- Modify: `docs/findings-and-reporting.md`
- Modify: `README.md`
- Modify: `docs/next-steps.md`
- Modify: `scripts/smoke_test.sh`

- [ ] **Step 1: Document platform reports**

In `docs/findings-and-reporting.md`, document the two new Finding fields, the
supported platforms, and `finding report --platform`, noting reports keep
demonstrated/plausible separate and reference redacted evidence. Update README
(test count; mention platform reports) and `docs/next-steps.md` (mark platform
reports done; next = operator-customizable templates / streaming caps / provider
gateway).

- [ ] **Step 2: Extend the offline smoke test**

In `scripts/smoke_test.sh`, alongside the finding help check:

```bash
( cd /tmp && "$HACKBOT" finding report --help | grep -q -- --platform ) && echo "finding report --platform present"
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
git add docs/findings-and-reporting.md README.md docs/next-steps.md scripts/smoke_test.sh
git commit -m "docs: document platform report renderers"
```

---

## Plan self-review

- **Spec coverage:** Finding fields (Task 1), per-platform renderers + all six
  platforms + scenario coverage (Task 2), CLI `--platform` + unknown→exit 2
  (Task 3), docs + regression (Task 4). All spec sections map to a task.
- **Placeholder scan:** none.
- **Type consistency:** `vulnerability_type`/`reproduction_steps`, `PLATFORMS`,
  `render(...)`, `render_markdown`, and `cmd_report(..., platform=...)` match.
- **Safety boundary:** reports keep demonstrated vs plausible separate, reference
  redacted evidence (never raw), are code-owned (no template engine), and stay
  local.
```
