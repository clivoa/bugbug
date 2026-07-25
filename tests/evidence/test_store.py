"""Redacted, run-linked evidence store."""

import json
import stat
from datetime import UTC, datetime

import pytest

from hackbot.evidence.store import EvidenceError, EvidenceStore
from hackbot.risk.identity import canonical_engagement_identity
from hackbot.risk.models import ActionRequest
from hackbot.tools.runner import CommandResult

_NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=UTC)


def _request(engagement, rationale="Fetch one in-scope lab URL once."):
    path, engagement_id = canonical_engagement_identity(str(engagement))
    return ActionRequest(
        engagement_id=engagement_id,
        engagement_path=path,
        action_id="net.http-get",
        target="http://127.0.0.1/",
        argv=("/usr/bin/curl", "-sS", "--max-time", "10", "http://127.0.0.1/"),
        hypothesis_id="hyp-1",
        rationale=rationale,
        rate=1,
        concurrency=1,
        data_touched="Public lab response.",
        expected_impact="One GET.",
        stop_condition="Stop on error.",
        cleanup_plan="None.",
        program_rule="Authorized lab fetch.",
        required_headers=(),
        requested_risk=None,
    )


def test_record_writes_redacted_stdout_and_meta(tmp_path):
    store = EvidenceStore(tmp_path)
    result = CommandResult(0, b"Set-Cookie: s=topsecretvalue\r\n\r\nlab-ok", b"", 9, False, False)
    run_id = store.record(
        action_id="net.http-get",
        request=_request(tmp_path),
        result=result,
        decision_kind="allow",
        reason_code="ALLOW",
        now=_NOW,
    )
    run_dir = tmp_path / "evidence" / run_id
    stdout = (run_dir / "stdout").read_bytes()
    assert b"topsecretvalue" not in stdout and b"lab-ok" in stdout
    meta = json.loads((run_dir / "meta.json").read_text())
    assert meta["action_id"] == "net.http-get"
    assert meta["hypothesis_id"] == "hyp-1"
    assert meta["exit_code"] == 0
    assert stat.S_IMODE((run_dir / "stdout").stat().st_mode) == 0o600
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700


def test_record_rejects_secret_bearing_rationale_and_writes_nothing(tmp_path):
    store = EvidenceStore(tmp_path)
    result = CommandResult(0, b"lab-ok", b"", 1, False, False)
    with pytest.raises(EvidenceError):
        store.record(
            action_id="net.http-get",
            request=_request(
                tmp_path, rationale="token aws_secret_access_key=AKIAIOSFODNN7EXAMPLEabcd"
            ),
            result=result,
            decision_kind="allow",
            reason_code="ALLOW",
            now=_NOW,
        )
    assert not (tmp_path / "evidence").exists() or not any((tmp_path / "evidence").iterdir())


def test_run_id_is_filesystem_safe(tmp_path):
    store = EvidenceStore(tmp_path)
    run_id = store.record(
        action_id="net.http-get",
        request=_request(tmp_path),
        result=CommandResult(0, b"lab-ok", b"", 1, False, False),
        decision_kind="allow",
        reason_code="ALLOW",
        now=_NOW,
    )
    assert "/" not in run_id and ":" not in run_id
    assert run_id.startswith("20260725T120000Z-")
