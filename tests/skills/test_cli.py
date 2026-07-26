"""hackbot skills list CLI."""

import json

from hackbot.cli.main import app


def test_skills_list_shows_attribution_and_availability(capsys):
    code = app(["skills", "list", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    by_id = {row["action_id"]: row for row in payload["skills"]}
    dns = by_id["dns.txt"]
    assert dns["available"] is True
    assert dns["skill"] == "recon/dns-recon"
    assert "@reeshasx" in dns["attribution"]
    assert dns["bundle_risk_level"] == "1"


def test_skills_list_marks_non_bundle_actions(capsys):
    app(["skills", "list", "--json"])
    payload = json.loads(capsys.readouterr().out)
    by_id = {row["action_id"]: row for row in payload["skills"]}
    if "net.http-post" in by_id:
        assert by_id["net.http-post"]["skill"] is None


def test_skills_list_remote_without_engagement_is_invalid(capsys):
    code = app(["skills", "list", "--runner", "remote", "--json"])
    assert code == 2


def test_skills_list_remote_marks_remote_availability(tmp_path, capsys, monkeypatch):
    (tmp_path / "k").write_text("KEY")
    (tmp_path / "runner.json").write_text(
        json.dumps({"host": "h", "user": "u", "port": 22, "key_path": str(tmp_path / "k")})
    )

    class _FakeRemote:
        def __init__(self, *a, **k):
            pass

        def probe(self, tools):
            return {"gobuster"}  # only gobuster present on the remote

    monkeypatch.setattr("hackbot.tools.remote.RemoteRunner", _FakeRemote)
    code = app(["skills", "list", "--engagement", str(tmp_path), "--runner", "remote", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    by_id = {r["action_id"]: r for r in payload["skills"]}
    assert by_id["web.dir-enum-gobuster"]["remote_available"] is True
    assert by_id["dns.txt"]["remote_available"] is False  # dig not in the fake probe set
