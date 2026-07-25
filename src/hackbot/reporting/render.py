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
