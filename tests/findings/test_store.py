"""Evidence-linked, secret-scanned finding store."""

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
    return Finding(finding_id=make_finding_id(base["title"], base["created_at"]), **base)


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
