"""Append-only, secret-free tool-run audit sink."""

import json
import stat
from datetime import UTC, datetime

import pytest

from hackbot.audit.tool_runs import AuditError, AuditSink
from hackbot.risk.models import RiskLevel
from hackbot.tools.runner import CommandResult

_NOW = datetime(2026, 7, 25, tzinfo=UTC)


def _result() -> CommandResult:
    return CommandResult(0, b"body", b"", 12, False, False)


def _record(sink: AuditSink, *, argv=("/usr/bin/curl", "http://127.0.0.1/"), result=...):
    if result is ...:
        result = _result()
    sink.record_run(
        action_id="net.http-get",
        effective_risk=RiskLevel.L0,
        target="http://127.0.0.1/",
        argv=argv,
        decision_kind="allow" if result else "deny",
        reason_code="ALLOW" if result else "DENY_SCOPE",
        result=result,
        now=_NOW,
    )


def test_record_writes_one_secret_free_line(tmp_path):
    sink = AuditSink(tmp_path)
    _record(sink)
    log = tmp_path / "audit" / "tool-runs.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["action_id"] == "net.http-get"
    assert record["exit_code"] == 0
    assert record["stdout_sha256"]
    assert "stdout" not in record and "body" not in lines[0]
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "audit").stat().st_mode) == 0o700


def test_record_appends(tmp_path):
    sink = AuditSink(tmp_path)
    _record(sink)
    _record(sink)
    log = tmp_path / "audit" / "tool-runs.jsonl"
    assert len(log.read_text(encoding="utf-8").splitlines()) == 2


def test_record_rejects_secret_bearing_argv(tmp_path):
    sink = AuditSink(tmp_path)
    with pytest.raises(AuditError):
        _record(sink, argv=("/usr/bin/curl", "aws_secret_access_key=AKIAIOSFODNN7EXAMPLEabcd"))
    assert not (tmp_path / "audit" / "tool-runs.jsonl").exists()


def test_record_without_execution_uses_nulls(tmp_path):
    sink = AuditSink(tmp_path)
    _record(sink, result=None)
    record = json.loads((tmp_path / "audit" / "tool-runs.jsonl").read_text().splitlines()[0])
    assert record["decision"] == "deny"
    assert record["exit_code"] is None
    assert record["stdout_sha256"] is None
