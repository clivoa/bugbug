# Operator-customizable Report Templates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators explicitly select global, per-platform Markdown
templates that can reorder report content without omitting evidence or merging
demonstrated and plausible impact.

**Architecture:** Add a focused stdlib-only loader/validator for a fixed
`report.md` + `finding.md` pair, then add a separate custom rendering path over
the existing typed `Finding` data. The CLI opts into that path only through
`--templates-dir`; the native renderer remains unchanged.

**Tech Stack:** Python 3.11+ standard library (`dataclasses`, `pathlib`, `stat`,
`string`), existing `hackbot.findings` / `hackbot.reporting`, pytest, Ruff,
mypy, Bash offline smoke test.

## Global Constraints

- Templates live at `DIR/<platform>/report.md` and
  `DIR/<platform>/finding.md`; both are required after explicit opt-in.
- Each template is a regular, non-symlink, strict UTF-8 file no larger than
  64 KiB.
- No per-engagement overrides, implicit discovery, loops, conditionals,
  includes, external engines, code execution, arbitrary file reads, HTML
  rendering, or network I/O.
- `report.md` accepts only `engagement_id`, `platform_label`, `finding_count`,
  and `findings`; `findings` occurs exactly once on its own line.
- `finding.md` accepts only the documented typed finding fields.
- `evidence`, `demonstrated_impact`, and `plausible_impact` each occur exactly
  once on separate lines containing no other non-whitespace text.
- Placeholder conversions, format specs, attribute access, index access, and
  malformed braces are invalid. Doubled braces remain the literal-brace escape.
- Invalid custom templates fail before report output with exit code `2`,
  concise `stderr`, and empty `stdout`; there is no fallback after explicit
  opt-in.
- Native report output remains byte-for-byte unchanged without
  `--templates-dir`.
- Raw evidence is never read or embedded. `{evidence}` is a code-owned redacted
  run reference.
- Implement test-first and observe every new test fail for the intended reason
  before production changes.

---

## File structure

- Create `src/hackbot/reporting/templates.py`: immutable template pair, bounded
  file loading, placeholder parsing, and structural validation.
- Create `tests/reporting/test_templates.py`: grammar, mandatory-field, file
  type, size, and UTF-8 tests for the template component.
- Modify `src/hackbot/reporting/render.py`: custom rendering entry point and
  typed placeholder mappings; preserve the native path.
- Modify `tests/reporting/test_render.py`: ordering, empty-report, inert-value,
  and evidence-boundary tests for custom rendering.
- Modify `src/hackbot/cli/finding_cmd.py`: select native versus custom renderer
  and map template errors to existing invalid-input semantics.
- Modify `src/hackbot/cli/main.py`: expose and pass `--templates-dir`.
- Modify `tests/findings/test_cli.py`: CLI opt-in, default compatibility, and
  fail-before-output tests.
- Modify `scripts/smoke_test.sh`: installed-package help gate for the new flag.
- Modify `README.md`, `docs/findings-and-reporting.md`, and
  `docs/next-steps.md`: usage, contract, status, and roadmap.

---

### Task 1: Bounded template loading and structural validation

**Files:**

- Create: `src/hackbot/reporting/templates.py`
- Create: `tests/reporting/test_templates.py`

**Interfaces:**

- Produces: `TemplateError(ValueError)`.
- Produces: immutable
  `ReportTemplates(report: str, finding: str)`.
- Produces:
  `load_report_templates(root: str | Path, *, platform: str) -> ReportTemplates`.
- Consumes: a platform name already validated by the renderer against
  `PLATFORMS`.

- [ ] **Step 1: Write the valid-pair and grammar rejection tests**

Create `tests/reporting/test_templates.py`:

```python
from pathlib import Path

import pytest

from hackbot.reporting.templates import TemplateError, load_report_templates


REPORT = """# {engagement_id} ({platform_label})
{finding_count} finding(s)
{findings}
"""

FINDING = """## {title}

Evidence
{evidence}

Plausible
{plausible_impact}

Demonstrated
{demonstrated_impact}
"""


def _pair(root: Path, *, report: str = REPORT, finding: str = FINDING) -> Path:
    platform_dir = root / "generic"
    platform_dir.mkdir(parents=True)
    (platform_dir / "report.md").write_text(report, encoding="utf-8")
    (platform_dir / "finding.md").write_text(finding, encoding="utf-8")
    return root


def test_load_report_templates_accepts_valid_pair_and_literal_braces(tmp_path):
    root = _pair(tmp_path, report=REPORT.replace("# ", "# {{draft}} "))
    pair = load_report_templates(root, platform="generic")
    assert "{{draft}}" in pair.report
    assert pair.finding == FINDING


@pytest.mark.parametrize(
    ("finding", "message"),
    [
        (FINDING + "\n{unknown}\n", "unknown placeholder"),
        (FINDING.replace("{title}", "{title!r}"), "conversions are not allowed"),
        (FINDING.replace("{title}", "{title:>20}"), "format specs are not allowed"),
        (FINDING.replace("{title}", "{finding.title}"), "unknown placeholder"),
        (FINDING.replace("{title}", "{finding[title]}"), "unknown placeholder"),
        (FINDING + "\n{\n", "malformed"),
        (FINDING.replace("{evidence}", ""), "evidence must occur exactly once"),
        (FINDING + "\n{evidence}\n", "evidence must occur exactly once"),
        (
            FINDING.replace("{evidence}", "Evidence: {evidence}"),
            "evidence must be alone on its line",
        ),
        (
            FINDING.replace(
                "{demonstrated_impact}",
                "{demonstrated_impact} {plausible_impact}",
            ).replace("\n{plausible_impact}\n", "\n"),
            "demonstrated_impact must be alone on its line",
        ),
    ],
)
def test_load_report_templates_rejects_invalid_finding_grammar(
    tmp_path, finding, message
):
    _pair(tmp_path, finding=finding)
    with pytest.raises(TemplateError, match=message):
        load_report_templates(tmp_path, platform="generic")


@pytest.mark.parametrize(
    ("report", "message"),
    [
        (REPORT.replace("{findings}", ""), "findings must occur exactly once"),
        (REPORT + "\n{findings}\n", "findings must occur exactly once"),
        (
            REPORT.replace("{findings}", "Results: {findings}"),
            "findings must be alone on its line",
        ),
        (REPORT + "\n{title}\n", "unknown placeholder"),
    ],
)
def test_load_report_templates_rejects_invalid_report_grammar(
    tmp_path, report, message
):
    _pair(tmp_path, report=report)
    with pytest.raises(TemplateError, match=message):
        load_report_templates(tmp_path, platform="generic")
```

- [ ] **Step 2: Run the grammar tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/reporting/test_templates.py -q
```

Expected: collection fails with
`ModuleNotFoundError: No module named 'hackbot.reporting.templates'`.

- [ ] **Step 3: Implement the immutable pair and placeholder validator**

Create `src/hackbot/reporting/templates.py` with:

```python
"""Load and validate inert operator-owned Markdown report templates."""

from __future__ import annotations

import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from string import Formatter

_MAX_TEMPLATE_BYTES = 64 * 1024
_REPORT_FIELDS = frozenset(
    {"engagement_id", "platform_label", "finding_count", "findings"}
)
_FINDING_FIELDS = frozenset(
    {
        "finding_id",
        "title",
        "severity",
        "status",
        "vulnerability_type",
        "target",
        "action_id",
        "evidence",
        "summary",
        "reproduction_steps",
        "demonstrated_impact",
        "plausible_impact",
    }
)
_REPORT_REQUIRED = frozenset({"findings"})
_FINDING_REQUIRED = frozenset(
    {"evidence", "demonstrated_impact", "plausible_impact"}
)


class TemplateError(ValueError):
    """A selected report template pair is missing, unsafe, or malformed."""


@dataclass(frozen=True, slots=True)
class ReportTemplates:
    report: str
    finding: str


def _validate_template(
    text: str,
    *,
    label: str,
    allowed: frozenset[str],
    required: frozenset[str],
) -> None:
    try:
        parsed = list(Formatter().parse(text))
    except ValueError as exc:
        raise TemplateError(f"{label} template is malformed: {exc}") from exc

    names: list[str] = []
    for _literal, field_name, format_spec, conversion in parsed:
        if field_name is None:
            continue
        if field_name not in allowed:
            raise TemplateError(
                f"{label} template has unknown placeholder {field_name!r}"
            )
        if conversion is not None:
            raise TemplateError(
                f"{label} template placeholder conversions are not allowed"
            )
        if format_spec:
            raise TemplateError(
                f"{label} template placeholder format specs are not allowed"
            )
        names.append(field_name)

    counts = Counter(names)
    stripped_lines = [line.strip() for line in text.splitlines()]
    for field_name in sorted(required):
        if counts[field_name] != 1:
            raise TemplateError(
                f"{label} template: {field_name} must occur exactly once"
            )
        if stripped_lines.count("{" + field_name + "}") != 1:
            raise TemplateError(
                f"{label} template: {field_name} must be alone on its line"
            )
```

- [ ] **Step 4: Run the grammar tests and verify the remaining RED**

Run:

```bash
.venv/bin/pytest tests/reporting/test_templates.py -q
```

Expected: valid-pair tests now fail because
`load_report_templates` is not defined.

- [ ] **Step 5: Add file-boundary tests**

Append to `tests/reporting/test_templates.py`:

```python
def test_load_report_templates_rejects_missing_or_partial_pair(tmp_path):
    with pytest.raises(TemplateError, match="report.md"):
        load_report_templates(tmp_path, platform="generic")

    platform_dir = tmp_path / "generic"
    platform_dir.mkdir()
    (platform_dir / "report.md").write_text(REPORT, encoding="utf-8")
    with pytest.raises(TemplateError, match="finding.md"):
        load_report_templates(tmp_path, platform="generic")


def test_load_report_templates_rejects_symlink(tmp_path):
    root = _pair(tmp_path)
    report = root / "generic" / "report.md"
    source = root / "source.md"
    source.write_text(REPORT, encoding="utf-8")
    report.unlink()
    report.symlink_to(source)
    with pytest.raises(TemplateError, match="regular non-symlink file"):
        load_report_templates(root, platform="generic")


def test_load_report_templates_rejects_directory_in_place_of_file(tmp_path):
    root = _pair(tmp_path)
    finding = root / "generic" / "finding.md"
    finding.unlink()
    finding.mkdir()
    with pytest.raises(TemplateError, match="regular non-symlink file"):
        load_report_templates(root, platform="generic")


def test_load_report_templates_rejects_oversized_file(tmp_path):
    root = _pair(tmp_path)
    (root / "generic" / "report.md").write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(TemplateError, match="exceeds 65536 bytes"):
        load_report_templates(root, platform="generic")


def test_load_report_templates_rejects_invalid_utf8(tmp_path):
    root = _pair(tmp_path)
    (root / "generic" / "finding.md").write_bytes(b"\xff")
    with pytest.raises(TemplateError, match="valid UTF-8"):
        load_report_templates(root, platform="generic")
```

- [ ] **Step 6: Run the expanded tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/reporting/test_templates.py -q
```

Expected: failures still report that `load_report_templates` is not defined.

- [ ] **Step 7: Implement bounded reads and pair loading**

Append to `src/hackbot/reporting/templates.py`:

```python
def _read_template(path: Path) -> str:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise TemplateError(f"template file unavailable: {path.name}: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(mode):
        raise TemplateError(
            f"template file must be a regular non-symlink file: {path.name}"
        )
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_TEMPLATE_BYTES + 1)
    except OSError as exc:
        raise TemplateError(f"template file unreadable: {path.name}: {exc}") from exc
    if len(raw) > _MAX_TEMPLATE_BYTES:
        raise TemplateError(
            f"template file {path.name} exceeds {_MAX_TEMPLATE_BYTES} bytes"
        )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TemplateError(f"template file {path.name} is not valid UTF-8") from exc


def load_report_templates(
    root: str | Path, *, platform: str
) -> ReportTemplates:
    platform_dir = Path(root) / platform
    report = _read_template(platform_dir / "report.md")
    finding = _read_template(platform_dir / "finding.md")
    _validate_template(
        report,
        label="report",
        allowed=_REPORT_FIELDS,
        required=_REPORT_REQUIRED,
    )
    _validate_template(
        finding,
        label="finding",
        allowed=_FINDING_FIELDS,
        required=_FINDING_REQUIRED,
    )
    return ReportTemplates(report=report, finding=finding)
```

- [ ] **Step 8: Run the component tests and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/reporting/test_templates.py -q
.venv/bin/ruff check src/hackbot/reporting/templates.py tests/reporting/test_templates.py
.venv/bin/mypy src
```

Expected: all template tests pass, Ruff reports `All checks passed!`, and mypy
reports no issues.

- [ ] **Step 9: Commit the loader**

```bash
git add src/hackbot/reporting/templates.py tests/reporting/test_templates.py
git commit -m "feat: validate operator report templates"
```

---

### Task 2: Typed custom renderer

**Files:**

- Modify: `src/hackbot/reporting/render.py:82-138`
- Modify: `tests/reporting/test_render.py`

**Interfaces:**

- Consumes:
  `load_report_templates(root: str | Path, *, platform: str) -> ReportTemplates`.
- Produces:
  `render_custom(findings: Sequence[Finding], *, engagement_id: str,
  platform: str, templates_dir: str | Path) -> str`.
- Preserves:
  `render(...)` and `render_markdown(...)` native behavior.

- [ ] **Step 1: Write custom rendering tests**

Update the imports in `tests/reporting/test_render.py`:

```python
from pathlib import Path

from hackbot.reporting.render import PLATFORMS, render, render_custom, render_markdown
```

Append:

```python
CUSTOM_REPORT = """# CUSTOM {engagement_id} / {platform_label}
Count: {finding_count}
{findings}
"""

CUSTOM_FINDING = """## {title}
Plausible first
{plausible_impact}
Evidence second
{evidence}
Demonstrated third
{demonstrated_impact}
Target: {target}
"""


def _templates(root: Path) -> Path:
    platform_dir = root / "generic"
    platform_dir.mkdir()
    (platform_dir / "report.md").write_text(CUSTOM_REPORT, encoding="utf-8")
    (platform_dir / "finding.md").write_text(CUSTOM_FINDING, encoding="utf-8")
    return root


def test_native_render_output_is_byte_for_byte_unchanged():
    assert render([_finding()], engagement_id="local-lab") == (
        "# Findings — local-lab (Generic)\n\n"
        "Claims require reproducible evidence. Demonstrated impact is listed "
        "separately from plausible, untested impact.\n\n"
        "1 finding(s).\n\n"
        "## Finding A\n\n"
        "- **Severity:** high\n"
        "- **Status:** demonstrated\n"
        "- **Vulnerability type:** unspecified\n"
        "- **Target:** http://127.0.0.1/\n"
        "- **Action:** net.http-get\n"
        "- **Evidence:** 20260725T120000Z-0123456789ab "
        "(redacted, under `evidence/20260725T120000Z-0123456789ab/`)\n\n"
        "A summary.\n\n"
        "**Steps to reproduce**\n\n"
        "Reproduce via evidence run `20260725T120000Z-0123456789ab` "
        "(action `net.http-get` against `http://127.0.0.1/`).\n\n"
        "**Demonstrated impact**\n\n"
        "Shown to execute.\n\n"
        "**Plausible additional impact (untested)**\n\n"
        "Maybe worse.\n"
    )


def test_render_custom_reorders_fields_and_keeps_evidence_redacted(tmp_path):
    out = render_custom(
        [_finding()],
        engagement_id="local-lab",
        platform="generic",
        templates_dir=_templates(tmp_path),
    )
    assert "# CUSTOM local-lab / Generic" in out
    assert "Count: 1" in out
    assert out.index("Maybe worse.") < out.index("20260725T120000Z-0123456789ab")
    assert out.index("20260725T120000Z-0123456789ab") < out.index(
        "Shown to execute."
    )
    assert "redacted, under `evidence/20260725T120000Z-0123456789ab/`" in out
    assert "stdout" not in out.lower()


def test_render_custom_preserves_severity_order_and_keeps_braces_inert(tmp_path):
    low = _finding(title="Low {evidence}", severity=Severity.LOW)
    crit = _finding(title="Crit one", severity=Severity.CRITICAL)
    out = render_custom(
        [low, crit],
        engagement_id="e",
        platform="generic",
        templates_dir=_templates(tmp_path),
    )
    assert out.index("Crit one") < out.index("Low {evidence}")
    assert out.count("20260725T120000Z-0123456789ab") == 2


def test_render_custom_validates_templates_when_no_findings(tmp_path):
    out = render_custom(
        [],
        engagement_id="e",
        platform="generic",
        templates_dir=_templates(tmp_path),
    )
    assert "Count: 0" in out
    assert "No findings recorded." in out


def test_render_custom_validates_platform_before_reading_templates(tmp_path):
    with pytest.raises(ValueError, match="unknown platform"):
        render_custom(
            [],
            engagement_id="e",
            platform="nope",
            templates_dir=tmp_path / "missing",
        )
```

- [ ] **Step 2: Run custom renderer tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/reporting/test_render.py -q -k custom
```

Expected: collection fails because `render_custom` is not defined.

- [ ] **Step 3: Add typed mappings and custom rendering**

In `src/hackbot/reporting/render.py`, import `Path` and the loader:

```python
from pathlib import Path

from hackbot.reporting.templates import load_report_templates
```

Append before `render_markdown`:

```python
def _evidence_reference(finding: Finding) -> str:
    if finding.evidence_run_id:
        run_id = finding.evidence_run_id
        return f"{run_id} (redacted, under `evidence/{run_id}/`)"
    return "none (no reproducible evidence run)"


def _custom_finding_values(finding: Finding) -> dict[str, str]:
    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "vulnerability_type": finding.vulnerability_type or "unspecified",
        "target": finding.target,
        "action_id": finding.action_id,
        "evidence": _evidence_reference(finding),
        "summary": finding.summary.strip() or "_Not provided._",
        "reproduction_steps": _steps_body(finding).strip() or "_Not provided._",
        "demonstrated_impact": (
            finding.demonstrated_impact.strip() or "_None demonstrated._"
        ),
        "plausible_impact": finding.plausible_impact.strip() or "_None stated._",
    }


def render_custom(
    findings: Sequence[Finding],
    *,
    engagement_id: str,
    platform: str,
    templates_dir: str | Path,
) -> str:
    try:
        spec = _SPECS[platform]
    except KeyError as exc:
        raise ValueError(f"unknown platform: {platform}") from exc

    templates = load_report_templates(templates_dir, platform=platform)
    ordered = sorted(
        findings, key=lambda finding: (_ORDER.index(finding.severity), finding.finding_id)
    )
    if ordered:
        rendered_findings = "\n\n".join(
            templates.finding.format_map(_custom_finding_values(finding)).rstrip()
            for finding in ordered
        )
    else:
        rendered_findings = "No findings recorded."
    return templates.report.format_map(
        {
            "engagement_id": engagement_id,
            "platform_label": spec.label,
            "finding_count": str(len(findings)),
            "findings": rendered_findings,
        }
    )
```

Do not alter the bodies or signatures of `render` and `render_markdown`.

- [ ] **Step 4: Run renderer tests and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/reporting/test_render.py -q
.venv/bin/ruff check src/hackbot/reporting/render.py tests/reporting/test_render.py
.venv/bin/mypy src
```

Expected: native and custom renderer tests pass; Ruff and mypy are clean.

- [ ] **Step 5: Commit the renderer**

```bash
git add src/hackbot/reporting/render.py tests/reporting/test_render.py
git commit -m "feat: render findings with validated templates"
```

---

### Task 3: Explicit CLI opt-in and fail-before-output behavior

**Files:**

- Modify: `src/hackbot/cli/finding_cmd.py:85-100`
- Modify: `src/hackbot/cli/main.py:345-352,466-473`
- Modify: `tests/findings/test_cli.py`

**Interfaces:**

- Consumes:
  `render_custom(..., templates_dir: str | Path) -> str`.
- Produces:
  `cmd_report(engagement: str, *, platform: str = "generic",
  templates_dir: str | None = None) -> int`.
- Produces CLI option:
  `hackbot finding report --templates-dir DIR`.

- [ ] **Step 1: Write CLI opt-in and failure tests**

Append to `tests/findings/test_cli.py`:

```python
def _template_pair(root: Path, *, valid: bool = True) -> Path:
    platform_dir = root / "generic"
    platform_dir.mkdir(parents=True)
    (platform_dir / "report.md").write_text(
        "# CUSTOM {engagement_id}\n{findings}\n", encoding="utf-8"
    )
    finding = (
        "## {title}\n{evidence}\n{demonstrated_impact}\n{plausible_impact}\n"
        if valid
        else "## {title}\n"
    )
    (platform_dir / "finding.md").write_text(finding, encoding="utf-8")
    return root


def test_finding_report_uses_templates_only_after_explicit_opt_in(tmp_path, capsys):
    engagement = tmp_path / "engagement"
    templates = _template_pair(tmp_path / "templates")
    app(
        [
            "finding",
            "add",
            str(FIX / "untested.json"),
            "--engagement",
            str(engagement),
            "--json",
        ]
    )
    capsys.readouterr()

    code = app(["finding", "report", "--engagement", str(engagement)])
    native = capsys.readouterr()
    assert code == 0
    assert "# Findings" in native.out
    assert "# CUSTOM" not in native.out

    code = app(
        [
            "finding",
            "report",
            "--engagement",
            str(engagement),
            "--templates-dir",
            str(templates),
        ]
    )
    custom = capsys.readouterr()
    assert code == 0
    assert "# CUSTOM engagement" in custom.out
    assert custom.err == ""


def test_finding_report_invalid_template_has_no_partial_stdout(tmp_path, capsys):
    engagement = tmp_path / "engagement"
    templates = _template_pair(tmp_path / "templates", valid=False)
    code = app(
        [
            "finding",
            "report",
            "--engagement",
            str(engagement),
            "--templates-dir",
            str(templates),
        ]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "template" in captured.err
    assert "demonstrated_impact must occur exactly once" in captured.err
```

- [ ] **Step 2: Run the CLI tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/findings/test_cli.py -q -k 'templates or partial_stdout'
```

Expected: argparse rejects `--templates-dir` with `unrecognized arguments`.

- [ ] **Step 3: Add the CLI argument and pass it through**

In `_cmd_finding` within `src/hackbot/cli/main.py`, change the report call to:

```python
    if args.faction == "report":
        return finding_cmd.cmd_report(
            args.engagement,
            platform=args.platform,
            templates_dir=args.templates_dir,
        )
```

After the existing `--platform` argument, add:

```python
    fd_report.add_argument(
        "--templates-dir",
        help="explicit root containing <platform>/report.md and finding.md",
    )
```

- [ ] **Step 4: Select the renderer inside `cmd_report`**

Replace `cmd_report` in `src/hackbot/cli/finding_cmd.py` with:

```python
def cmd_report(
    engagement: str,
    *,
    platform: str = "generic",
    templates_dir: str | None = None,
) -> int:
    from hackbot.findings.store import FindingError, FindingStore
    from hackbot.reporting.render import render, render_custom

    try:
        findings = FindingStore(engagement).load_all()
    except FindingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    try:
        if templates_dir is None:
            report = render(
                findings,
                engagement_id=Path(engagement).name,
                platform=platform,
            )
        else:
            report = render_custom(
                findings,
                engagement_id=Path(engagement).name,
                platform=platform,
                templates_dir=templates_dir,
            )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    print(report)
    return EXIT_OK
```

The report string is constructed completely inside the `try` block; `print`
remains after successful rendering so invalid templates cannot emit partial
`stdout`.

- [ ] **Step 5: Run CLI and reporting regression tests**

Run:

```bash
.venv/bin/pytest tests/findings/test_cli.py tests/reporting -q
.venv/bin/ruff check src/hackbot/cli/main.py src/hackbot/cli/finding_cmd.py tests/findings/test_cli.py
.venv/bin/ruff format --check src/hackbot/cli/main.py src/hackbot/cli/finding_cmd.py tests/findings/test_cli.py
.venv/bin/mypy src
```

Expected: all tests pass, Ruff check/format are clean, and mypy reports no
issues.

- [ ] **Step 6: Commit the CLI integration**

```bash
git add src/hackbot/cli/main.py src/hackbot/cli/finding_cmd.py tests/findings/test_cli.py
git commit -m "feat: expose custom report templates in CLI"
```

---

### Task 4: Operator documentation, roadmap, smoke gate, and full verification

**Files:**

- Modify: `scripts/smoke_test.sh`
- Modify: `README.md`
- Modify: `docs/findings-and-reporting.md`
- Modify: `docs/next-steps.md`

**Interfaces:**

- Documents:
  `hackbot finding report --engagement DIR --platform NAME
  --templates-dir DIR`.
- Verifies the installed wheel exposes `--templates-dir`.
- Promotes streaming output caps to roadmap item 1 after this feature.

- [ ] **Step 1: Extend the installed-package smoke assertion**

Immediately after the existing `finding report --platform present` assertion in
`scripts/smoke_test.sh`, add:

```bash
( cd /tmp && "$HACKBOT" finding report --help | grep -q -- --templates-dir ) \
  && echo "finding report --templates-dir present"
```

- [ ] **Step 2: Update README usage and status**

In the Findings & reporting status bullet, state that reports optionally use
strict operator templates:

```markdown
  reports (`--platform generic|hackerone|bugcrowd|yeswehack|intigriti|immunefi`)
  reference redacted evidence, never raw output, and may explicitly use strict
  operator Markdown templates via `--templates-dir`. See
```

Add this command to Quick start:

```bash
.venv/bin/hackbot finding report --engagement engagements/local-lab \
  --platform hackerone --templates-dir templates
```

Do not guess the test count in the README status lines; Step 6 records the
freshly verified passing count.

- [ ] **Step 3: Document the complete template contract**

Replace the “There is no template engine” paragraph in
`docs/findings-and-reporting.md` with a native-default paragraph followed by an
“Operator templates” subsection containing:

````markdown
### Operator templates

Native code-owned renderers remain the default. To opt into a global
operator-owned template pair:

```text
hackbot finding report --engagement DIR --platform hackerone \
  --templates-dir templates
```

The command reads exactly:

```text
templates/hackerone/report.md
templates/hackerone/finding.md
```

`report.md` accepts `{engagement_id}`, `{platform_label}`, `{finding_count}`,
and `{findings}`. `{findings}` is required exactly once on its own line.

`finding.md` accepts `{finding_id}`, `{title}`, `{severity}`, `{status}`,
`{vulnerability_type}`, `{target}`, `{action_id}`, `{evidence}`, `{summary}`,
`{reproduction_steps}`, `{demonstrated_impact}`, and `{plausible_impact}`.
`{evidence}`, `{demonstrated_impact}`, and `{plausible_impact}` are each
required exactly once on separate lines.

Templates are strict UTF-8 regular files, not symlinks, and are limited to
64 KiB each. Unknown placeholders, conversions, format specs, attribute/index
access, malformed braces, missing files, and missing/repeated mandatory fields
fail with exit `2` before report output. Literal braces use `{{` and `}}`.
There are no loops, conditionals, includes, execution, implicit discovery, or
fallback after explicit opt-in.
````

Add this valid compact example:

````markdown
`report.md`:

```text
# {platform_label} submission — {engagement_id}
{finding_count} finding(s)
{findings}
```

`finding.md`:

```text
## {title} ({severity})

### Evidence
{evidence}

### Demonstrated impact
{demonstrated_impact}

### Plausible additional impact (untested)
{plausible_impact}

### Reproduction
{reproduction_steps}
```
````

Update the CLI synopsis to include `[--templates-dir DIR]`, and update the
boundary paragraph to state that custom templates remain inert Markdown and
cannot omit the three safety-critical fields.

- [ ] **Step 4: Advance the roadmap**

In `docs/next-steps.md`:

- add operator-customizable report templates to the “Done” paragraph, noting
  explicit `--templates-dir`, strict allowlisted placeholders, and
  fail-before-output validation;
- remove the operator-template item from the numbered pending list;
- renumber streaming output caps as item 1, internal-recon as item 2, and
  provider gateway/MCP as item 3.

- [ ] **Step 5: Run focused documentation and smoke checks**

Run:

```bash
rg -n -- '--templates-dir|report.md|finding.md|streaming output caps' \
  README.md docs/findings-and-reporting.md docs/next-steps.md scripts/smoke_test.sh
bash scripts/smoke_test.sh
```

Expected: every changed document contains the intended terms, and the smoke test
ends with `SMOKE TEST PASSED` including
`finding report --templates-dir present`.

- [ ] **Step 6: Run the full gates and record the verified test count**

Run:

```bash
.venv/bin/pytest -q -ra
.venv/bin/pytest --collect-only -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
bash scripts/smoke_test.sh
git diff --check
```

Expected: pytest exits `0` with only the repository’s existing intentional skip;
collection succeeds; Ruff check reports `All checks passed!`; Ruff format reports
all files already formatted; mypy reports no issues; smoke ends with
`SMOKE TEST PASSED`; and `git diff --check` is silent.

Use the collection total and pytest’s skip count to compute the exact passing
count. Replace both stale README counts and the status count in
`docs/next-steps.md` with that verified passing count, then rerun:

```bash
rg -n 'tests passing|automated tests passing|full safety suite' README.md docs/next-steps.md
.venv/bin/pytest -q -ra
git diff --check
```

Expected: every documented count matches the fresh suite evidence; pytest again
exits `0`; whitespace validation remains silent.

- [ ] **Step 7: Commit documentation and smoke coverage**

```bash
git add README.md docs/findings-and-reporting.md docs/next-steps.md scripts/smoke_test.sh
git commit -m "docs: document operator report templates"
```

- [ ] **Step 8: Verify the final branch state**

Run:

```bash
git status --short --branch
git log --oneline --decorate main..HEAD
git diff --check main...HEAD
```

Expected: the branch is `feat/operator-report-templates`, the worktree is clean,
all feature commits (including the design and this plan) are listed, and the
final diff has no whitespace errors.
