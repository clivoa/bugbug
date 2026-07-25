"""Frozen finding model: demonstrated vs plausible impact (rule 10)."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from hackbot.findings.models import Finding, FindingStatus, Severity, make_finding_id

_NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)
_RUN = "20260725T120000Z-0123456789ab"


def _finding(**over):
    base = dict(
        finding_id=make_finding_id("Reflected XSS on /search", _NOW),
        title="Reflected XSS on /search",
        severity=Severity.HIGH,
        status=FindingStatus.DEMONSTRATED,
        target="http://127.0.0.1/search",
        action_id="net.http-get",
        evidence_run_id=_RUN,
        summary="A reflected parameter is echoed unescaped.",
        demonstrated_impact="Arbitrary script executes in the victim's session.",
        plausible_impact="Session theft if combined with a missing HttpOnly flag.",
        created_at=_NOW,
    )
    base.update(over)
    return Finding(**base)


def test_finding_is_frozen():
    finding = _finding()
    with pytest.raises(FrozenInstanceError):
        finding.title = "changed"


def test_make_finding_id_is_filesystem_safe():
    fid = make_finding_id("Reflected XSS on /search", _NOW)
    assert "/" not in fid and ":" not in fid
    assert fid.startswith("20260725T120000Z-")


def test_demonstrated_requires_evidence_and_impact():
    with pytest.raises(ValueError):
        _finding(evidence_run_id=None)
    with pytest.raises(ValueError):
        _finding(demonstrated_impact="")


def test_plausible_and_untested_may_omit_evidence():
    _finding(status=FindingStatus.PLAUSIBLE, evidence_run_id=None, demonstrated_impact="")
    _finding(status=FindingStatus.UNTESTED, evidence_run_id=None, demonstrated_impact="")


def test_bad_run_id_is_rejected():
    with pytest.raises(ValueError):
        _finding(evidence_run_id="../escape")


def test_severity_and_status_must_be_enums():
    with pytest.raises(ValueError):
        _finding(severity="high")
    with pytest.raises(ValueError):
        _finding(status="demonstrated")


def test_optional_fields_default_empty():
    f = _finding()
    assert f.vulnerability_type == "" and f.reproduction_steps == ""


def test_optional_fields_round_trip_values():
    f = _finding(vulnerability_type="reflected-xss", reproduction_steps="GET /x?q=<t>")
    assert f.vulnerability_type == "reflected-xss"
    assert f.reproduction_steps == "GET /x?q=<t>"
