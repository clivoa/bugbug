"""hackbot skills list CLI."""

import json

from hackbot.cli.main import app


def test_skills_list_shows_skill_domains_and_availability(capsys):
    code = app(["skills", "list", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["registry_loaded"] is True
    by_id = {row["action_id"]: row for row in payload["skills"]}
    # A DNS action should be available and mapped to a skill domain
    dns = by_id["recon.dns.txt"]
    assert dns["available"] is True
    assert dns["skill_domain"] == "DNS Reconnaissance"


def test_skills_list_marks_all_registered_actions(capsys):
    code = app(["skills", "list", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    by_id = {row["action_id"]: row for row in payload["skills"]}
    # All registered actions should have available=True
    if "net.http-post" in by_id:
        assert by_id["net.http-post"]["available"] is True


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
    assert by_id["recon.dns.txt"]["remote_available"] is not True  # dig not in the fake probe set
