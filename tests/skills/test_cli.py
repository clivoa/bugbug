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
