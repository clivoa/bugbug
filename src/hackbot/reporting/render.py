"""Render findings to per-platform markdown reports; never embed raw evidence."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from hackbot.findings.models import Finding, Severity
from hackbot.reporting.templates import load_report_templates

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
        "Generic",
        "Vulnerability type",
        "",
        "**Steps to reproduce**",
        "**Demonstrated impact**",
        "**Plausible additional impact (untested)**",
    ),
    "hackerone": _PlatformSpec(
        "HackerOne",
        "Weakness",
        "### Summary",
        "### Steps To Reproduce",
        "### Impact",
        "### Additional impact (plausible, untested)",
    ),
    "bugcrowd": _PlatformSpec(
        "Bugcrowd",
        "Bug type",
        "### Description",
        "### Steps to reproduce",
        "### Impact",
        "### Additional context (plausible, untested)",
    ),
    "yeswehack": _PlatformSpec(
        "YesWeHack",
        "Bug type",
        "### Description",
        "### Steps to reproduce",
        "### Impact",
        "### Additional impact (plausible, untested)",
    ),
    "intigriti": _PlatformSpec(
        "Intigriti",
        "Vulnerability type",
        "### Description",
        "### Proof of concept",
        "### Impact",
        "### Additional impact (plausible, untested)",
    ),
    "immunefi": _PlatformSpec(
        "Immunefi",
        "Vulnerability type",
        "### Summary",
        "### Proof of Concept",
        "### Impact",
        "### Additional impact (plausible, untested)",
    ),
}

PLATFORMS = tuple(_SPECS)


def _section(heading: str, body: str) -> list[str]:
    body = body.strip() or "_Not provided._"
    return [heading, "", body, ""] if heading else [body, ""]


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
        "demonstrated_impact": (finding.demonstrated_impact.strip() or "_None demonstrated._"),
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


def render_markdown(findings: Sequence[Finding], *, engagement_id: str) -> str:
    return render(findings, engagement_id=engagement_id, platform="generic")
