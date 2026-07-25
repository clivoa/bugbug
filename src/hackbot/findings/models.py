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
