"""hackbot finding add/report/list CLI."""

import json
from pathlib import Path

from hackbot.cli.main import app

FIX = Path(__file__).parent / "fixtures"


def test_finding_add_untested_and_report(tmp_path, capsys):
    code = app(
        ["finding", "add", str(FIX / "untested.json"), "--engagement", str(tmp_path), "--json"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["finding_id"]

    code = app(["finding", "report", "--engagement", str(tmp_path)])
    report = capsys.readouterr().out
    assert code == 0
    assert "Missing security headers" in report
    assert "Plausible additional impact (untested)" in report


def test_finding_add_demonstrated_requires_existing_evidence(tmp_path, capsys):
    code = app(
        ["finding", "add", str(FIX / "demonstrated.json"), "--engagement", str(tmp_path), "--json"]
    )
    assert code == 2  # evidence run does not exist
    capsys.readouterr()
    (tmp_path / "evidence" / "20260725T120000Z-0123456789ab").mkdir(parents=True)
    code = app(
        ["finding", "add", str(FIX / "demonstrated.json"), "--engagement", str(tmp_path), "--json"]
    )
    assert json.loads(capsys.readouterr().out)["finding_id"]
    assert code == 0


def test_finding_list(tmp_path, capsys):
    app(["finding", "add", str(FIX / "untested.json"), "--engagement", str(tmp_path), "--json"])
    capsys.readouterr()
    code = app(["finding", "list", "--engagement", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["findings"][0]["title"] == "Missing security headers"


def test_finding_add_rejects_bad_status(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"title":"x","severity":"low","status":"nope","target":"t",'
        '"action_id":"a","evidence_run_id":null,"summary":"s",'
        '"demonstrated_impact":"","plausible_impact":""}'
    )
    code = app(["finding", "add", str(bad), "--engagement", str(tmp_path), "--json"])
    assert code == 2


def test_finding_add_accepts_optional_fields(tmp_path, capsys):
    desc = tmp_path / "f.json"
    desc.write_text(
        '{"title":"IDOR on /orders","severity":"high","status":"untested",'
        '"target":"http://127.0.0.1/orders","action_id":"net.http-get",'
        '"evidence_run_id":null,"summary":"Sequential ids.",'
        '"demonstrated_impact":"","plausible_impact":"Read others orders.",'
        '"vulnerability_type":"idor","reproduction_steps":"GET /orders/1002"}'
    )
    code = app(["finding", "add", str(desc), "--engagement", str(tmp_path), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["finding_id"]


def test_finding_report_platform_selects_renderer(tmp_path, capsys):
    app(["finding", "add", str(FIX / "untested.json"), "--engagement", str(tmp_path), "--json"])
    capsys.readouterr()
    code = app(["finding", "report", "--engagement", str(tmp_path), "--platform", "hackerone"])
    out = capsys.readouterr().out
    assert code == 0
    assert "HackerOne" in out and "Steps To Reproduce" in out


def test_finding_report_unknown_platform_is_invalid(tmp_path, capsys):
    code = app(["finding", "report", "--engagement", str(tmp_path), "--platform", "nope"])
    assert code == 2
