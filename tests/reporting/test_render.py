"""Markdown reporter: separates demonstrated vs plausible, references evidence."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from hackbot.findings.models import Finding, FindingStatus, Severity, make_finding_id
from hackbot.reporting.render import PLATFORMS, render, render_custom, render_markdown

_NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)


def _finding(**over):
    base = dict(
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
    return Finding(finding_id=make_finding_id(base["title"], base["created_at"]), **base)


def test_render_separates_demonstrated_and_plausible():
    out = render_markdown([_finding()], engagement_id="local-lab")
    assert "# Findings — local-lab" in out
    assert "Demonstrated impact" in out
    assert "Plausible additional impact (untested)" in out
    assert "Shown to execute." in out
    assert "Maybe worse." in out


def test_render_references_evidence_not_raw_output():
    out = render_markdown([_finding()], engagement_id="local-lab")
    assert "20260725T120000Z-0123456789ab" in out
    assert "stdout" not in out.lower()


def test_render_orders_by_severity():
    low = _finding(title="Low one", severity=Severity.LOW)
    crit = _finding(title="Crit one", severity=Severity.CRITICAL)
    out = render_markdown([low, crit], engagement_id="e")
    assert out.index("Crit one") < out.index("Low one")


def test_render_handles_no_findings():
    out = render_markdown([], engagement_id="local-lab")
    assert "No findings recorded." in out


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
    assert "GET /search?q=<script>" in out
    assert "Script executes in the victim session." in out
    assert "Session theft with a missing HttpOnly flag." in out
    lower = out.lower()
    assert "demonstrated" in lower and "plausible" in lower
    assert "20260725T120000Z-0123456789ab" in out
    assert "stdout" not in lower


def test_platform_specific_headings():
    h1 = render([_vuln()], engagement_id="e", platform="hackerone")
    assert "Steps To Reproduce" in h1 and "Weakness" in h1
    bc = render([_vuln()], engagement_id="e", platform="bugcrowd")
    assert "Description" in bc and "Bug type" in bc


def test_unknown_platform_raises():
    with pytest.raises(ValueError):
        render([_vuln()], engagement_id="e", platform="nope")


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
    assert out.index("20260725T120000Z-0123456789ab") < out.index("Shown to execute.")
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
    # Each finding's redacted evidence reference includes the ID in its label
    # and in its redacted evidence path.
    assert out.count("20260725T120000Z-0123456789ab") == 4


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
