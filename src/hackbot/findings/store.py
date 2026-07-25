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
        "vulnerability_type": finding.vulnerability_type,
        "reproduction_steps": finding.reproduction_steps,
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
            vulnerability_type=value.get("vulnerability_type", ""),
            reproduction_steps=value.get("reproduction_steps", ""),
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
