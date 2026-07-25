"""Markdown reporter: separates demonstrated vs plausible, references evidence."""

from datetime import UTC, datetime

import pytest

from hackbot.findings.models import Finding, FindingStatus, Severity, make_finding_id
from hackbot.reporting.render import PLATFORMS, render, render_markdown

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
