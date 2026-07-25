"""Behavioral tests for the non-executing risk and approval CLI."""

import json
from pathlib import Path

from hackbot.cli.main import app

FIX = Path(__file__).parent / "fixtures"


def _evaluate(engagement: Path, request_name: str, capsys) -> tuple[int, dict]:
    code = app(
        [
            "risk",
            "evaluate",
            str(FIX / request_name),
            "--engagement",
            str(engagement),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    return code, payload


def test_evaluate_l0_allows(sample_engagement, capsys):
    code, payload = _evaluate(sample_engagement, "l0-request.json", capsys)
    assert code == 0
    assert payload["decision"] == "allow"
    assert payload["effective_risk"] == "L0"


def test_evaluate_l3_always_denied(sample_engagement, capsys):
    code, payload = _evaluate(sample_engagement, "l3-request.json", capsys)
    assert code == 1
    assert payload["decision"] == "deny"
    assert payload["reason_code"] == "DENY_PROHIBITED"


def test_evaluate_l2_persists_pending(sample_engagement, capsys):
    code, payload = _evaluate(sample_engagement, "l2-request.json", capsys)
    assert code == 4
    assert payload["decision"] == "requires-approval"
    assert payload["approval_status"] == "pending"
    challenge_id = payload["challenge_id"]
    assert len(challenge_id) == 64 and all(c in "0123456789abcdef" for c in challenge_id)
    # Never leak the artifact path, binding, or secrets.
    assert "challenge_file" not in payload
    assert "binding" not in payload
    # The pending record now exists under the engagement's approvals directory.
    pending = sample_engagement / "approvals" / "pending" / f"{challenge_id}.json"
    assert pending.exists()


def test_status_reports_stored_state_for_pending(sample_engagement, capsys):
    _, payload = _evaluate(sample_engagement, "l2-request.json", capsys)
    challenge_id = payload["challenge_id"]
    code = app(
        [
            "approval",
            "status",
            challenge_id,
            "--engagement",
            str(sample_engagement),
            "--json",
        ]
    )
    status = json.loads(capsys.readouterr().out)
    assert code == 0
    assert status["challenge_id"] == challenge_id
    assert status["stored_state"] == "pending"


def test_status_reports_missing_for_unknown_digest(sample_engagement, capsys):
    digest = "0" * 64
    code = app(["approval", "status", digest, "--engagement", str(sample_engagement), "--json"])
    status = json.loads(capsys.readouterr().out)
    assert code == 0
    assert status["stored_state"] == "missing"


def test_status_rejects_non_digest_id(sample_engagement, capsys):
    code = app(
        ["approval", "status", "../escape", "--engagement", str(sample_engagement), "--json"]
    )
    assert code == 2
    assert "digest" in capsys.readouterr().err.lower()


# ---- interactive grant ------------------------------------------------------


def test_grant_succeeds_when_tty_confirms(sample_engagement, capsys, monkeypatch):
    _, payload = _evaluate(sample_engagement, "l2-request.json", capsys)
    challenge_id = payload["challenge_id"]
    monkeypatch.setattr("hackbot.cli.main._read_approval_from_tty", lambda _challenge: None)
    code = app(
        ["approval", "grant", challenge_id, "--engagement", str(sample_engagement), "--json"]
    )
    granted = json.loads(capsys.readouterr().out)
    assert code == 0
    assert granted["approval_status"] == "granted"
    assert granted["approved_by"] == "test-operator"

    status_code = app(
        ["approval", "status", challenge_id, "--engagement", str(sample_engagement), "--json"]
    )
    status = json.loads(capsys.readouterr().out)
    assert status_code == 0
    assert status["stored_state"] == "granted"


def test_grant_refuses_without_tty(sample_engagement, capsys, monkeypatch):
    _, payload = _evaluate(sample_engagement, "l2-request.json", capsys)
    challenge_id = payload["challenge_id"]

    def _no_tty(_challenge):
        raise OSError("interactive TTY required")

    monkeypatch.setattr("hackbot.cli.main._read_approval_from_tty", _no_tty)
    code = app(["approval", "grant", challenge_id, "--engagement", str(sample_engagement)])
    assert code == 3
    assert "interactive TTY required" in capsys.readouterr().err
    # A refused confirmation leaves the challenge pending.
    app(["approval", "status", challenge_id, "--engagement", str(sample_engagement), "--json"])
    assert json.loads(capsys.readouterr().out)["stored_state"] == "pending"


def test_grant_rejects_non_digest_id(sample_engagement, capsys):
    code = app(["approval", "grant", "../escape", "--engagement", str(sample_engagement)])
    assert code == 2


# ---- strict request parsing -------------------------------------------------


def _write_request(tmp_path: Path, text: str) -> Path:
    request = tmp_path / "request.json"
    request.write_text(text, encoding="utf-8")
    return request


def _evaluate_raw(engagement: Path, request: Path, capsys) -> tuple[int, str, str]:
    code = app(["risk", "evaluate", str(request), "--engagement", str(engagement), "--json"])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_request_rejects_duplicate_keys(sample_engagement, tmp_path, capsys):
    request = _write_request(
        tmp_path,
        '{"action_id": "fixture.passive", "action_id": "fixture.prohibited",'
        ' "target": "https://acme-corp.example/app", "argv": [],'
        ' "hypothesis_id": "", "rationale": "", "rate": null, "concurrency": null,'
        ' "data_touched": "", "expected_impact": "", "stop_condition": "",'
        ' "cleanup_plan": "", "program_rule": "x", "required_headers": [],'
        ' "requested_risk": null}',
    )
    code, _out, err = _evaluate_raw(sample_engagement, request, capsys)
    assert code == 2
    assert "Traceback" not in err


def test_request_rejects_non_finite_numbers(sample_engagement, tmp_path, capsys):
    request = _write_request(
        tmp_path,
        '{"action_id": "fixture.passive", "target": "https://acme-corp.example/app",'
        ' "argv": [], "hypothesis_id": "", "rationale": "", "rate": NaN,'
        ' "concurrency": null, "data_touched": "", "expected_impact": "",'
        ' "stop_condition": "", "cleanup_plan": "", "program_rule": "x",'
        ' "required_headers": [], "requested_risk": null}',
    )
    code, _out, err = _evaluate_raw(sample_engagement, request, capsys)
    assert code == 2
    assert "Traceback" not in err


def test_request_rejects_non_object_root(sample_engagement, tmp_path, capsys):
    request = _write_request(tmp_path, "[1, 2, 3]")
    code, _out, err = _evaluate_raw(sample_engagement, request, capsys)
    assert code == 2


def test_request_rejects_unknown_key(sample_engagement, tmp_path, capsys):
    request = _write_request(
        tmp_path,
        '{"action_id": "fixture.passive", "target": "https://acme-corp.example/app",'
        ' "argv": [], "hypothesis_id": "", "rationale": "", "rate": null,'
        ' "concurrency": null, "data_touched": "", "expected_impact": "",'
        ' "stop_condition": "", "cleanup_plan": "", "program_rule": "x",'
        ' "required_headers": [], "requested_risk": null, "engagement_id": "spoof"}',
    )
    code, _out, err = _evaluate_raw(sample_engagement, request, capsys)
    assert code == 2
    assert "engagement_id" in err


def test_request_rejects_missing_key(sample_engagement, tmp_path, capsys):
    request = _write_request(
        tmp_path,
        '{"action_id": "fixture.passive", "target": "https://acme-corp.example/app"}',
    )
    code, _out, err = _evaluate_raw(sample_engagement, request, capsys)
    assert code == 2


def test_request_rejects_boolean_as_rate(sample_engagement, tmp_path, capsys):
    request = _write_request(
        tmp_path,
        '{"action_id": "fixture.intrusive", "target": "https://acme-corp.example/app",'
        ' "argv": [], "hypothesis_id": "h", "rationale": "r", "rate": true,'
        ' "concurrency": 1, "data_touched": "d", "expected_impact": "e",'
        ' "stop_condition": "s", "cleanup_plan": "c", "program_rule": "x",'
        ' "required_headers": [], "requested_risk": null}',
    )
    code, _out, err = _evaluate_raw(sample_engagement, request, capsys)
    assert code == 2


def test_request_rejects_oversize_file(sample_engagement, tmp_path, capsys):
    request = _write_request(tmp_path, '{"pad": "' + "a" * (64 * 1024 + 16) + '"}')
    code, _out, err = _evaluate_raw(sample_engagement, request, capsys)
    assert code == 2


def test_secret_bearing_l2_request_denies_without_pending(sample_engagement, tmp_path, capsys):
    request = _write_request(
        tmp_path,
        '{"action_id": "fixture.intrusive", "target": "https://acme-corp.example/app",'
        ' "argv": [], "hypothesis_id": "hyp-1",'
        ' "rationale": "aws_secret_access_key=AKIAIOSFODNN7EXAMPLEabcdefpatch",'
        ' "rate": 1, "concurrency": 1, "data_touched": "d",'
        ' "expected_impact": "e", "stop_condition": "s", "cleanup_plan": "c",'
        ' "program_rule": "x", "required_headers": [], "requested_risk": null}',
    )
    code, _out, _err = _evaluate_raw(sample_engagement, request, capsys)
    assert code in (1, 2)
    approvals = sample_engagement / "approvals" / "pending"
    assert not approvals.exists() or not any(approvals.iterdir())
