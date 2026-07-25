"""Markdown reporter: separates demonstrated vs plausible, references evidence."""

from datetime import UTC, datetime

from hackbot.findings.models import Finding, FindingStatus, Severity, make_finding_id
from hackbot.reporting.render import render_markdown

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
