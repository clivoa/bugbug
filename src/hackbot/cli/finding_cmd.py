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
            if key not in _REQUIRED_FINDING_KEYS and key not in _OPTIONAL_FINDING_KEYS:
                raise CliInputError(f"unknown field {key!r}")
        for key in _REQUIRED_FINDING_KEYS:
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
            vulnerability_type=value.get("vulnerability_type", ""),  # type: ignore[arg-type]
            reproduction_steps=value.get("reproduction_steps", ""),  # type: ignore[arg-type]
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
