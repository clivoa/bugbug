# Findings & Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn run-linked evidence into typed, reproducible findings and a
markdown report, completing `context → evaluate → allow → run → evidence →
finding → report`.

**Architecture:** A frozen `Finding` model that structurally separates
demonstrated vs plausible impact and requires reproducible evidence for
`demonstrated`; a secret-scanned per-engagement `FindingStore` with evidence
linkage verification; a markdown reporter that references redacted evidence; and
`hackbot finding add/report/list` commands.

**Tech Stack:** Python 3.11+ standard library (`dataclasses`, `enum`, `hashlib`,
`json`, `os`, `re`, `pathlib`, `datetime`), the approval store's `_reject_secrets`,
the CLI's strict parser, pytest, Ruff, mypy. No YAML — finding commands are
stdlib-only.

## Global Constraints

- Core package stays standard-library only; finding commands need no `config` extra.
- CLAUDE.md rule 10: never exaggerate impact; keep demonstrated and plausible
  impact in separate fields/sections; a `demonstrated` finding requires existing,
  reproducible evidence.
- Findings and reports are secret-free (scanned before writing); reports never
  embed raw output — only a redacted-evidence `run_id` pointer.
- `evidence_run_id` is format-validated (no path traversal).
- The reviewed `hackbot.risk`/`hackbot.tools`/`hackbot.evidence` packages are not
  modified.
- Production behavior is written test-first; each test is observed failing for the
  intended reason before implementation.

---

### Task 1: Finding model

**Files:**
- Create: `src/hackbot/findings/models.py`
- Create: `tests/findings/__init__.py`
- Create: `tests/findings/test_models.py`

**Interfaces:**
- Produces: `Severity`, `FindingStatus`, `Finding`, `make_finding_id`.

- [ ] **Step 1: Write failing model tests**

```python
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from hackbot.findings.models import Finding, FindingStatus, Severity, make_finding_id

_NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)
_RUN = "20260725T120000Z-0123456789ab"


def _finding(**over):
    base = dict(
        finding_id=make_finding_id("Reflected XSS on /search", _NOW),
        title="Reflected XSS on /search",
        severity=Severity.HIGH,
        status=FindingStatus.DEMONSTRATED,
        target="http://127.0.0.1/search",
        action_id="net.http-get",
        evidence_run_id=_RUN,
        summary="A reflected parameter is echoed unescaped.",
        demonstrated_impact="Arbitrary script executes in the victim's session.",
        plausible_impact="Session theft if combined with a missing HttpOnly flag.",
        created_at=_NOW,
    )
    base.update(over)
    return Finding(**base)


def test_finding_is_frozen():
    finding = _finding()
    with pytest.raises(FrozenInstanceError):
        finding.title = "changed"


def test_make_finding_id_is_filesystem_safe():
    fid = make_finding_id("Reflected XSS on /search", _NOW)
    assert "/" not in fid and ":" not in fid
    assert fid.startswith("20260725T120000Z-")


def test_demonstrated_requires_evidence_and_impact():
    with pytest.raises(ValueError):
        _finding(evidence_run_id=None)
    with pytest.raises(ValueError):
        _finding(demonstrated_impact="")


def test_plausible_and_untested_may_omit_evidence():
    _finding(status=FindingStatus.PLAUSIBLE, evidence_run_id=None, demonstrated_impact="")
    _finding(status=FindingStatus.UNTESTED, evidence_run_id=None, demonstrated_impact="")


def test_bad_run_id_is_rejected():
    with pytest.raises(ValueError):
        _finding(evidence_run_id="../escape")


def test_severity_and_status_must_be_enums():
    with pytest.raises(ValueError):
        _finding(severity="high")
    with pytest.raises(ValueError):
        _finding(status="demonstrated")
```

- [ ] **Step 2: Run the model tests and verify RED**

Run: `.venv/bin/python -m pytest tests/findings/test_models.py -q`
Expected: collection fails — `hackbot.findings.models` does not exist.

- [ ] **Step 3: Implement the model**

```python
"""Frozen finding model: separates demonstrated vs plausible impact (rule 10)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
_RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{12}$")


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    DEMONSTRATED = "demonstrated"
    PLAUSIBLE = "plausible"
    UNTESTED = "untested"


def _text(value: object, *, name: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if not allow_empty and not value.strip():
        raise ValueError(f"{name} must not be empty")
    if len(value) > limit:
        raise ValueError(f"{name} exceeds {limit} characters")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ValueError(f"{name} contains invalid Unicode")
    return value


def make_finding_id(title: str, created_at: datetime) -> str:
    digest = hashlib.sha256(title.encode("utf-8")).hexdigest()[:8]
    return f"{created_at:%Y%m%dT%H%M%SZ}-{digest}"


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    title: str
    severity: Severity
    status: FindingStatus
    target: str
    action_id: str
    evidence_run_id: str | None
    summary: str
    demonstrated_impact: str
    plausible_impact: str
    created_at: datetime

    def __post_init__(self) -> None:
        _text(self.title, name="title", limit=512)
        _text(self.target, name="target", limit=2_048)
        _text(self.action_id, name="action_id", limit=128)
        _text(self.summary, name="summary", limit=8_192)
        _text(self.demonstrated_impact, name="demonstrated_impact", limit=8_192, allow_empty=True)
        _text(self.plausible_impact, name="plausible_impact", limit=8_192, allow_empty=True)
        if type(self.severity) is not Severity:
            raise ValueError("severity must be a Severity member")
        if type(self.status) is not FindingStatus:
            raise ValueError("status must be a FindingStatus member")
        if _ID_RE.fullmatch(self.finding_id) is None:
            raise ValueError("finding_id is malformed")
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None:
            raise ValueError("created_at must be an aware datetime")
        if self.evidence_run_id is not None and (
            not isinstance(self.evidence_run_id, str)
            or _RUN_ID_RE.fullmatch(self.evidence_run_id) is None
        ):
            raise ValueError("evidence_run_id is malformed")
        if self.status is FindingStatus.DEMONSTRATED and (
            not self.evidence_run_id or not self.demonstrated_impact.strip()
        ):
            raise ValueError("a demonstrated finding requires evidence and demonstrated_impact")
```

- [ ] **Step 4: Run the model tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/findings/test_models.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/findings/models.py tests/findings/__init__.py tests/findings/test_models.py
git commit -m "feat: add frozen finding model"
```

---

### Task 2: FindingStore

**Files:**
- Create: `src/hackbot/findings/store.py`
- Create: `tests/findings/test_store.py`

**Interfaces:**
- Consumes: `Finding`, `Severity`, `FindingStatus` (Task 1),
  `hackbot.risk.approvals._reject_secrets`, `ApprovalError`.
- Produces: `FindingStore`, `FindingError` (with `.code`),
  `FindingStore.add(finding)`, `FindingStore.load_all()`.

- [ ] **Step 1: Write failing store tests**

```python
import stat
from datetime import UTC, datetime

import pytest

from hackbot.findings.models import Finding, FindingStatus, Severity, make_finding_id
from hackbot.findings.store import FindingError, FindingStore

_NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)


def _finding(engagement, **over):
    run_id = "20260725T120000Z-0123456789ab"
    (engagement / "evidence" / run_id).mkdir(parents=True, exist_ok=True)
    base = dict(
        finding_id=make_finding_id(over.get("title", "Finding A"), _NOW),
        title="Finding A",
        severity=Severity.HIGH,
        status=FindingStatus.DEMONSTRATED,
        target="http://127.0.0.1/",
        action_id="net.http-get",
        evidence_run_id=run_id,
        summary="A summary.",
        demonstrated_impact="Shown to execute.",
        plausible_impact="Maybe worse.",
        created_at=_NOW,
    )
    base.update(over)
    base["finding_id"] = make_finding_id(base["title"], base["created_at"])
    return Finding(**base)


def test_add_writes_a_secret_free_0600_file(tmp_path):
    store = FindingStore(tmp_path)
    finding = _finding(tmp_path)
    store.add(finding)
    path = tmp_path / "findings" / f"{finding.finding_id}.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "findings").stat().st_mode) == 0o700
    loaded = store.load_all()
    assert len(loaded) == 1 and loaded[0].title == "Finding A"


def test_demonstrated_without_existing_evidence_is_rejected(tmp_path):
    store = FindingStore(tmp_path)
    finding = _finding(tmp_path, evidence_run_id="20260725T120000Z-ffffffffffff")
    with pytest.raises(FindingError):
        store.add(finding)
    assert not (tmp_path / "findings").exists() or not any((tmp_path / "findings").iterdir())


def test_secret_bearing_finding_is_rejected(tmp_path):
    store = FindingStore(tmp_path)
    finding = _finding(tmp_path, summary="leak aws_secret_access_key=AKIAIOSFODNN7EXAMPLEabcd")
    with pytest.raises(FindingError):
        store.add(finding)


def test_duplicate_finding_id_is_rejected(tmp_path):
    store = FindingStore(tmp_path)
    finding = _finding(tmp_path)
    store.add(finding)
    with pytest.raises(FindingError):
        store.add(finding)
```

- [ ] **Step 2: Run the store tests and verify RED**

Run: `.venv/bin/python -m pytest tests/findings/test_store.py -q`
Expected: collection fails — `hackbot.findings.store` does not exist.

- [ ] **Step 3: Implement FindingStore**

```python
"""Secret-scanned, per-engagement finding storage with evidence linkage."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from hackbot.findings.models import Finding, FindingStatus, Severity
from hackbot.risk.approvals import ApprovalError, _reject_secrets


class FindingError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _to_dict(finding: Finding) -> dict[str, object]:
    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "target": finding.target,
        "action_id": finding.action_id,
        "evidence_run_id": finding.evidence_run_id,
        "summary": finding.summary,
        "demonstrated_impact": finding.demonstrated_impact,
        "plausible_impact": finding.plausible_impact,
        "created_at": finding.created_at.isoformat(),
    }


def _from_dict(value: object) -> Finding:
    if not isinstance(value, dict):
        raise FindingError("MALFORMED", "malformed finding record")
    try:
        return Finding(
            finding_id=value["finding_id"],
            title=value["title"],
            severity=Severity(value["severity"]),
            status=FindingStatus(value["status"]),
            target=value["target"],
            action_id=value["action_id"],
            evidence_run_id=value["evidence_run_id"],
            summary=value["summary"],
            demonstrated_impact=value["demonstrated_impact"],
            plausible_impact=value["plausible_impact"],
            created_at=datetime.fromisoformat(value["created_at"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise FindingError("MALFORMED", "malformed finding record") from exc


class FindingStore:
    def __init__(self, engagement_dir: str | Path) -> None:
        self._engagement = Path(engagement_dir)
        self._dir = self._engagement / "findings"

    def add(self, finding: Finding) -> None:
        if finding.evidence_run_id is not None:
            evidence = self._engagement / "evidence" / finding.evidence_run_id
            if not evidence.is_dir():
                raise FindingError("EVIDENCE_NOT_FOUND", "referenced evidence run does not exist")
        payload = _to_dict(finding)
        try:
            _reject_secrets(payload)
        except ApprovalError as exc:
            raise FindingError("SECRET", "refusing to store a secret-bearing finding") from exc
        self._dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self._dir, 0o700)
        path = self._dir / f"{finding.finding_id}.json"
        data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise FindingError("EXISTS", "a finding with this id already exists") from exc
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)

    def load_all(self) -> list[Finding]:
        if not self._dir.is_dir():
            return []
        findings: list[Finding] = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise FindingError("MALFORMED", f"could not read {path.name}") from exc
            findings.append(_from_dict(value))
        return sorted(findings, key=lambda f: f.finding_id)
```

- [ ] **Step 4: Run the store tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/findings/test_store.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/findings/store.py tests/findings/test_store.py
git commit -m "feat: add evidence-linked finding store"
```

---

### Task 3: Markdown reporter

**Files:**
- Create: `src/hackbot/reporting/render.py`
- Create: `tests/reporting/__init__.py`
- Create: `tests/reporting/test_render.py`

**Interfaces:**
- Consumes: `Finding`, `Severity`, `FindingStatus`.
- Produces: `render_markdown(findings, *, engagement_id) -> str`.

- [ ] **Step 1: Write failing render tests**

```python
from datetime import UTC, datetime

from hackbot.findings.models import Finding, FindingStatus, Severity, make_finding_id
from hackbot.reporting.render import render_markdown

_NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)


def _finding(**over):
    base = dict(
        finding_id=make_finding_id("Finding A", _NOW),
        title="Finding A",
        severity=Severity.HIGH,
        status=FindingStatus.DEMONSTRATED,
        target="http://127.0.0.1/",
        action_id="net.http-get",
        evidence_run_id="20260725T120000Z-0123456789ab",
        summary="A summary.",
        demonstrated_impact="Shown to execute.",
        plausible_impact="Maybe worse.",
        created_at=_NOW,
    )
    base.update(over)
    return Finding(**base)


def test_render_separates_demonstrated_and_plausible():
    out = render_markdown([_finding()], engagement_id="local-lab")
    assert "# Findings — local-lab" in out
    assert "Demonstrated impact" in out
    assert "Plausible additional impact (untested)" in out
    assert "Shown to execute." in out
    assert "Maybe worse." in out


def test_render_references_evidence_not_raw_output():
    out = render_markdown([_finding()], engagement_id="local-lab")
    assert "20260725T120000Z-0123456789ab" in out  # evidence pointer
    assert "stdout" not in out.lower()


def test_render_orders_by_severity():
    low = _finding(title="Low one", severity=Severity.LOW)
    crit = _finding(title="Crit one", severity=Severity.CRITICAL)
    out = render_markdown([low, crit], engagement_id="e")
    assert out.index("Crit one") < out.index("Low one")


def test_render_handles_no_findings():
    out = render_markdown([], engagement_id="local-lab")
    assert "No findings recorded." in out
```

- [ ] **Step 2: Run the render tests and verify RED**

Run: `.venv/bin/python -m pytest tests/reporting/test_render.py -q`
Expected: collection fails — `hackbot.reporting.render` does not exist.

- [ ] **Step 3: Implement render_markdown**

```python
"""Render findings to a markdown report that never embeds raw evidence."""

from __future__ import annotations

from collections.abc import Sequence

from hackbot.findings.models import Finding, Severity

_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def _finding_block(finding: Finding) -> str:
    evidence = finding.evidence_run_id or "none"
    lines = [
        f"## {finding.title}",
        "",
        f"- **Severity:** {finding.severity.value}",
        f"- **Status:** {finding.status.value}",
        f"- **Target:** {finding.target}",
        f"- **Action:** {finding.action_id}",
        f"- **Evidence:** {evidence} (redacted, under `evidence/{evidence}/`)",
        "",
        finding.summary,
        "",
        "**Demonstrated impact**",
        "",
        finding.demonstrated_impact.strip() or "_None demonstrated._",
        "",
        "**Plausible additional impact (untested)**",
        "",
        finding.plausible_impact.strip() or "_None stated._",
    ]
    return "\n".join(lines)


def render_markdown(findings: Sequence[Finding], *, engagement_id: str) -> str:
    header = [
        f"# Findings — {engagement_id}",
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
        blocks.append(_finding_block(finding))
        blocks.append("")
    return "\n".join(header + blocks)
```

- [ ] **Step 4: Run the render tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/reporting/test_render.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hackbot/reporting/render.py tests/reporting/__init__.py tests/reporting/test_render.py
git commit -m "feat: render findings to markdown"
```

---

### Task 4: hackbot finding CLI

**Files:**
- Create: `src/hackbot/cli/finding_cmd.py`
- Modify: `src/hackbot/cli/main.py`
- Create: `tests/findings/test_cli.py`
- Create: `tests/findings/fixtures/demonstrated.json`
- Create: `tests/findings/fixtures/untested.json`

**Interfaces:**
- Consumes: `risk_cmd._strict_parse`, `CliInputError`; `Finding`, `Severity`,
  `FindingStatus`, `make_finding_id`; `FindingStore`, `FindingError`;
  `render_markdown`.
- Produces: `cmd_add`, `cmd_report`, `cmd_list`; a `finding` subparser.

- [ ] **Step 1: Write descriptor fixtures**

`tests/findings/fixtures/demonstrated.json` (references a run id the test creates):

```json
{
  "title": "Reflected value on /echo",
  "severity": "medium",
  "status": "demonstrated",
  "target": "http://127.0.0.1/echo",
  "action_id": "net.http-get",
  "evidence_run_id": "20260725T120000Z-0123456789ab",
  "summary": "The q parameter is reflected unescaped.",
  "demonstrated_impact": "The response echoes attacker-controlled text.",
  "plausible_impact": "Script execution if a sink is reachable."
}
```

`tests/findings/fixtures/untested.json`:

```json
{
  "title": "Missing security headers",
  "severity": "low",
  "status": "untested",
  "target": "http://127.0.0.1/",
  "action_id": "net.http-get",
  "evidence_run_id": null,
  "summary": "No CSP observed.",
  "demonstrated_impact": "",
  "plausible_impact": "Weaker defense in depth."
}
```

- [ ] **Step 2: Write failing CLI tests**

```python
import json
from pathlib import Path

from hackbot.cli.main import app

FIX = Path(__file__).parent / "fixtures"


def test_finding_add_untested_and_report(tmp_path, capsys):
    code = app(
        ["finding", "add", str(FIX / "untested.json"), "--engagement", str(tmp_path), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["finding_id"]

    code = app(["finding", "report", "--engagement", str(tmp_path)])
    report = capsys.readouterr().out
    assert code == 0
    assert "Missing security headers" in report
    assert "Plausible additional impact (untested)" in report


def test_finding_add_demonstrated_requires_existing_evidence(tmp_path, capsys):
    code = app(
        ["finding", "add", str(FIX / "demonstrated.json"), "--engagement", str(tmp_path), "--json"]
    )
    assert code == 2  # evidence run does not exist
    (tmp_path / "evidence" / "20260725T120000Z-0123456789ab").mkdir(parents=True)
    code = app(
        ["finding", "add", str(FIX / "demonstrated.json"), "--engagement", str(tmp_path), "--json"]
    )
    assert json.loads(capsys.readouterr().out)["finding_id"]
    assert code == 0


def test_finding_list(tmp_path, capsys):
    app(["finding", "add", str(FIX / "untested.json"), "--engagement", str(tmp_path), "--json"])
    capsys.readouterr()
    code = app(["finding", "list", "--engagement", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["findings"][0]["title"] == "Missing security headers"


def test_finding_add_rejects_bad_status(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"title":"x","severity":"low","status":"nope","target":"t",'
                   '"action_id":"a","evidence_run_id":null,"summary":"s",'
                   '"demonstrated_impact":"","plausible_impact":""}')
    code = app(["finding", "add", str(bad), "--engagement", str(tmp_path), "--json"])
    assert code == 2
```

- [ ] **Step 3: Run the CLI tests and verify RED**

Run: `.venv/bin/python -m pytest tests/findings/test_cli.py -q`
Expected: `SystemExit: 2` — argparse has no `finding` subcommand.

- [ ] **Step 4: Implement finding_cmd**

```python
"""Local, stdlib-only CLI for recording and reporting findings."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from hackbot.cli.risk_cmd import CliInputError, _strict_parse

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_INVALID = 2

_FINDING_KEYS = frozenset(
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


def _emit(payload: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for key, item in payload.items():
            print(f"{key}: {item}")


def cmd_add(engagement: str, descriptor_path: str, *, as_json: bool) -> int:
    from hackbot.findings.models import Finding, FindingStatus, Severity, make_finding_id
    from hackbot.findings.store import FindingError, FindingStore

    try:
        raw = Path(descriptor_path).read_bytes()
        value = _strict_parse(raw)
        for key in value:
            if key not in _FINDING_KEYS:
                raise CliInputError(f"unknown field {key!r}")
        for key in _FINDING_KEYS:
            if key not in value:
                raise CliInputError(f"missing field {key!r}")
    except (CliInputError, OSError) as exc:
        print(f"invalid finding: {exc}", file=sys.stderr)
        return EXIT_INVALID
    created_at = datetime.now(UTC)
    try:
        finding = Finding(
            finding_id=make_finding_id(str(value["title"]), created_at),
            title=value["title"],  # type: ignore[arg-type]
            severity=Severity(value["severity"]),
            status=FindingStatus(value["status"]),
            target=value["target"],  # type: ignore[arg-type]
            action_id=value["action_id"],  # type: ignore[arg-type]
            evidence_run_id=value["evidence_run_id"],  # type: ignore[arg-type]
            summary=value["summary"],  # type: ignore[arg-type]
            demonstrated_impact=value["demonstrated_impact"],  # type: ignore[arg-type]
            plausible_impact=value["plausible_impact"],  # type: ignore[arg-type]
            created_at=created_at,
        )
    except (ValueError, TypeError) as exc:
        print(f"invalid finding: {exc}", file=sys.stderr)
        return EXIT_INVALID
    try:
        FindingStore(engagement).add(finding)
    except FindingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL if exc.code == "EXISTS" else EXIT_INVALID
    _emit({"finding_id": finding.finding_id, "status": finding.status.value}, as_json=as_json)
    return EXIT_OK


def cmd_report(engagement: str) -> int:
    from hackbot.findings.store import FindingError, FindingStore
    from hackbot.reporting.render import render_markdown

    try:
        findings = FindingStore(engagement).load_all()
    except FindingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    print(render_markdown(findings, engagement_id=Path(engagement).name))
    return EXIT_OK


def cmd_list(engagement: str, *, as_json: bool) -> int:
    from hackbot.findings.store import FindingError, FindingStore

    try:
        findings = FindingStore(engagement).load_all()
    except FindingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    rows = [
        {
            "finding_id": f.finding_id,
            "severity": f.severity.value,
            "status": f.status.value,
            "title": f.title,
        }
        for f in findings
    ]
    _emit({"findings": rows}, as_json=as_json)
    return EXIT_OK
```

- [ ] **Step 5: Wire the finding subparser in main.py**

```python
def _cmd_finding(args: argparse.Namespace) -> int:
    from hackbot.cli import finding_cmd

    if args.faction == "add":
        return finding_cmd.cmd_add(args.engagement, args.descriptor, as_json=args.json)
    if args.faction == "report":
        return finding_cmd.cmd_report(args.engagement)
    if args.faction == "list":
        return finding_cmd.cmd_list(args.engagement, as_json=args.json)
    return 2
```

```python
    fd = sub.add_parser("finding", help="record and report reproducible findings")
    fd_sub = fd.add_subparsers(dest="faction", required=True)
    fd_add = fd_sub.add_parser("add", help="add a finding from a local descriptor")
    fd_add.add_argument("descriptor", help="local finding JSON file")
    fd_add.add_argument("--engagement", required=True, help="engagement directory")
    fd_add.add_argument("--json", action="store_true")
    fd_report = fd_sub.add_parser("report", help="render all findings to markdown")
    fd_report.add_argument("--engagement", required=True, help="engagement directory")
    fd_list = fd_sub.add_parser("list", help="list findings")
    fd_list.add_argument("--engagement", required=True, help="engagement directory")
    fd_list.add_argument("--json", action="store_true")
    fd.set_defaults(func=_cmd_finding)
```

- [ ] **Step 6: Run the CLI tests and verify GREEN**

Run: `.venv/bin/python -m pytest tests/findings -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/hackbot/cli/finding_cmd.py src/hackbot/cli/main.py tests/findings
git commit -m "feat: add hackbot finding add/report/list CLI"
```

---

### Task 5: Documentation and final regression

**Files:**
- Create: `docs/findings-and-reporting.md`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `docs/next-steps.md`
- Modify: `scripts/smoke_test.sh`

- [ ] **Step 1: Document findings & reporting**

`docs/findings-and-reporting.md`: the Finding model (demonstrated vs plausible,
reproducible-evidence requirement), the store layout
(`<engagement>/findings/<id>.json`, secret-free, evidence linkage), the markdown
report (references redacted evidence, never raw), the CLI and exit codes, and a
worked example. Update README (test count, one-line note + doc link), SECURITY
(findings separate demonstrated from plausible impact and require reproducible
evidence; reports never embed raw output), and `docs/next-steps.md` (mark
findings/reporting done; next = more reviewed actions / platform templates).

- [ ] **Step 2: Extend the offline smoke test**

In `scripts/smoke_test.sh`, alongside the tool help checks:

```bash
( cd /tmp && "$HACKBOT" finding --help >/dev/null ) && echo "finding help ok"
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
git add docs/findings-and-reporting.md README.md SECURITY.md docs/next-steps.md scripts/smoke_test.sh
git commit -m "docs: document findings and reporting and verify"
```

---

## Plan self-review

- **Spec coverage:** Finding model (Task 1), evidence-linked secret-scanned store
  (Task 2), markdown reporter (Task 3), CLI add/report/list + exit codes (Task 4),
  docs + regression (Task 5). All spec sections map to a task.
- **Placeholder scan:** none — every step carries real code or an exact command.
- **Type consistency:** `Severity`/`FindingStatus`/`Finding`/`make_finding_id`,
  `FindingStore.add`/`load_all`/`FindingError.code`, `render_markdown`, and the
  `cmd_add`/`cmd_report`/`cmd_list` signatures match across tasks.
- **Safety boundary:** a demonstrated finding needs existing reproducible
  evidence; findings/reports are secret-free; reports reference redacted evidence,
  never raw output; demonstrated and plausible impact stay separate.
```
