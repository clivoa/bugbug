"""Non-executing-by-default `hackbot tool run` CLI."""

import json
from pathlib import Path

import pytest

from hackbot.cli.main import app
from hackbot.tools.actions import curl_path


def _write_request(path: Path, target: str, action_id: str) -> Path:
    request = path / "request.json"
    request.write_text(
        json.dumps(
            {
                "action_id": action_id,
                "target": target,
                "argv": [curl_path() or "/usr/bin/curl", "-sS", "--max-time", "10", target],
                "hypothesis_id": "hyp-1",
                "rationale": "Fetch one in-scope lab URL once.",
                "rate": 1,
                "concurrency": 1,
                "data_touched": "Public lab response.",
                "expected_impact": "One low-rate GET.",
                "stop_condition": "Stop on any error.",
                "cleanup_plan": "No state created.",
                "program_rule": "Authorized lab fetch.",
                "required_headers": [],
                "requested_risk": None,
            }
        )
    )
    return request


def test_tool_run_unknown_action_is_invalid(lab_engagement, tmp_path):
    request = _write_request(tmp_path, "http://127.0.0.1/", "net.nonexistent")
    code = app(
        [
            "tool",
            "run",
            "net.nonexistent",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--json",
        ]
    )
    assert code == 2


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_out_of_scope_denies(lab_engagement, tmp_path, capsys):
    request = _write_request(tmp_path, "http://10.0.0.5/", "net.http-get")
    code = app(
        ["tool", "run", "net.http-get", str(request), "--engagement", str(lab_engagement), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["reason_code"] == "DENY_SCOPE"
    assert payload["executed"] is False


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_executes_in_scope(lab_engagement, tmp_path, capsys, local_server):
    request = _write_request(tmp_path, local_server, "net.http-get")
    code = app(
        ["tool", "run", "net.http-get", str(request), "--engagement", str(lab_engagement), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["executed"] is True
    assert payload["exit_code"] == 0
    assert "stdout" not in payload


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_reports_and_writes_evidence(lab_engagement, tmp_path, capsys, local_server):
    request = _write_request(tmp_path, local_server, "net.http-get")
    code = app(
        ["tool", "run", "net.http-get", str(request), "--engagement", str(lab_engagement), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    run_id = payload["evidence_run_id"]
    assert run_id
    stdout = (lab_engagement / "evidence" / run_id / "stdout").read_bytes()
    assert b"lab-ok" in stdout
    assert "stdout" not in payload
