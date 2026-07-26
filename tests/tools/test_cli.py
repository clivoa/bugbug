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


def _write_post_request(path: Path, target: str) -> Path:
    request = path / "request.json"
    request.write_text(
        json.dumps(
            {
                "action_id": "net.http-post",
                "target": target,
                "argv": [
                    curl_path() or "/usr/bin/curl",
                    "-sS",
                    "-X",
                    "POST",
                    "--max-time",
                    "10",
                    target,
                ],
                "hypothesis_id": "hyp-1",
                "rationale": "Send one authorized POST to a lab endpoint.",
                "rate": 1,
                "concurrency": 1,
                "data_touched": "Lab request/response.",
                "expected_impact": "One low-rate state-changing POST.",
                "stop_condition": "Stop on any error.",
                "cleanup_plan": "Lab state reset out of band.",
                "program_rule": "Authorized intrusive lab testing.",
                "required_headers": [],
                "requested_risk": None,
            }
        )
    )
    return request


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_l2_without_approve_writes_pending(lab_engagement, tmp_path, capsys):
    request = _write_post_request(tmp_path, "http://127.0.0.1/")
    code = app(
        [
            "tool",
            "run",
            "net.http-post",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 4
    assert payload["approval_status"] == "pending"
    assert payload["executed"] is False
    challenge_id = payload["challenge_id"]
    assert (lab_engagement / "approvals" / "pending" / f"{challenge_id}.json").exists()


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_l2_approve_executes_and_consumes(
    lab_engagement, tmp_path, capsys, monkeypatch, local_server
):
    monkeypatch.setattr("hackbot.cli.main._read_approval_from_tty", lambda _c: None)
    request = _write_post_request(tmp_path, local_server)
    code = app(
        [
            "tool",
            "run",
            "net.http-post",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--approve",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["executed"] is True
    assert payload["exit_code"] == 0
    assert payload["evidence_run_id"]
    challenge_id = payload["challenge_id"]
    from hackbot.risk.approvals import ApprovalStore

    with ApprovalStore(lab_engagement) as store:
        assert store.status(challenge_id) == "consumed"


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_tool_run_l2_approve_without_tty_does_not_execute(
    lab_engagement, tmp_path, capsys, monkeypatch
):
    def _no_tty(_challenge):
        raise OSError("interactive TTY required")

    monkeypatch.setattr("hackbot.cli.main._read_approval_from_tty", _no_tty)
    request = _write_post_request(tmp_path, "http://127.0.0.1/")
    code = app(
        [
            "tool",
            "run",
            "net.http-post",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--approve",
        ]
    )
    assert code == 3
    assert "interactive TTY required" in capsys.readouterr().err
    assert not (lab_engagement / "evidence").exists()


from hackbot.tools.actions import ffuf_path, web_content_wordlist  # noqa: E402


def _write_dir_enum_request(path: Path, target: str) -> Path:
    request = path / "request.json"
    request.write_text(
        json.dumps(
            {
                "action_id": "web.dir-enum",
                "target": target,
                "argv": [
                    ffuf_path() or "/opt/homebrew/bin/ffuf",
                    "-s",
                    "-u",
                    target,
                    "-w",
                    web_content_wordlist(),
                ],
                "hypothesis_id": "hyp-1",
                "rationale": "Enumerate one in-scope lab path set once.",
                "rate": 1,
                "concurrency": 1,
                "data_touched": "Public lab responses.",
                "expected_impact": "One low-rate directory sweep.",
                "stop_condition": "Stop on any error.",
                "cleanup_plan": "No state created.",
                "program_rule": "Authorized lab enumeration.",
                "required_headers": [],
                "requested_risk": None,
            }
        )
    )
    return request


@pytest.mark.skipif(ffuf_path() is None, reason="ffuf not installed")
def test_tool_run_web_dir_enum_approve_executes(
    lab_engagement, tmp_path, capsys, monkeypatch, local_server
):
    monkeypatch.setattr("hackbot.cli.main._read_approval_from_tty", lambda _c: None)
    target = local_server.rstrip("/") + "/FUZZ"
    request = _write_dir_enum_request(tmp_path, target)
    code = app(
        [
            "tool",
            "run",
            "web.dir-enum",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--approve",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["executed"] is True
    assert payload["exit_code"] == 0
    assert payload["evidence_run_id"]
    run_dir = lab_engagement / "evidence" / payload["evidence_run_id"]
    assert b"admin" in (run_dir / "stdout").read_bytes()


def test_tool_run_remote_missing_config_is_invalid(lab_engagement, tmp_path, capsys):
    request = _write_request(tmp_path, "http://127.0.0.1/", "net.http-get")
    code = app(
        [
            "tool",
            "run",
            "net.http-get",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--runner",
            "remote",
            "--json",
        ]
    )
    assert code == 2
    assert "runner" in capsys.readouterr().err.lower()


def test_tool_run_remote_uses_remote_runner(lab_engagement, tmp_path, capsys, monkeypatch):
    import json as _json

    from hackbot.tools.runner import CommandResult

    (tmp_path / "k").write_text("KEY")
    (lab_engagement / "runner.json").write_text(
        _json.dumps({"host": "h", "user": "u", "port": 22, "key_path": str(tmp_path / "k")})
    )

    calls = {}

    class _FakeRemote:
        def __init__(self, *a, **k):
            calls["built"] = True

        def run(self, argv):
            calls["argv"] = tuple(argv)
            return CommandResult(0, b"remote", b"", 3, False, False)

    monkeypatch.setattr("hackbot.tools.remote.RemoteRunner", _FakeRemote)
    request = _write_request(tmp_path, "http://127.0.0.1/", "net.http-get")
    code = app(
        [
            "tool",
            "run",
            "net.http-get",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--runner",
            "remote",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0 and payload["executed"] is True
    assert calls.get("built") is True


def _write_gobuster_request(path: Path, *, wordlist: str | None) -> Path:
    argv = ["gobuster", "dir", "-u", "http://127.0.0.1/", "-w", wordlist or "", "-q"]
    body = {
        "action_id": "web.dir-enum-gobuster",
        "target": "http://127.0.0.1/",
        "argv": argv,
        "hypothesis_id": "hyp-1",
        "rationale": "Directory enumeration of one in-scope lab host.",
        "rate": 1,
        "concurrency": 1,
        "data_touched": "Public lab responses.",
        "expected_impact": "One low-rate directory sweep.",
        "stop_condition": "Stop on any error.",
        "cleanup_plan": "No state created.",
        "program_rule": "Authorized lab enumeration.",
        "required_headers": [],
        "requested_risk": None,
    }
    if wordlist is not None:
        body["wordlist"] = wordlist
    request = path / "request.json"
    request.write_text(json.dumps(body))
    return request


def test_tool_run_gobuster_with_wordlist_requires_approval(lab_engagement, tmp_path, capsys):
    request = _write_gobuster_request(tmp_path, wordlist="/usr/share/wordlists/dirb/common.txt")
    code = app(
        [
            "tool",
            "run",
            "web.dir-enum-gobuster",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 4  # L2 -> requires approval (not executed)
    assert payload["approval_status"] == "pending"


def test_tool_run_gobuster_without_wordlist_is_denied(lab_engagement, tmp_path, capsys):
    request = _write_gobuster_request(tmp_path, wordlist=None)
    code = app(
        [
            "tool",
            "run",
            "web.dir-enum-gobuster",
            str(request),
            "--engagement",
            str(lab_engagement),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 1  # empty wordlist -> render_argv None -> DENY_ARGV_TEMPLATE_MISMATCH
    assert payload["reason_code"] == "DENY_ARGV_TEMPLATE_MISMATCH"


def test_wordlists_list_remote_prints_entries(tmp_path, capsys, monkeypatch):
    import json as _json

    from hackbot.cli import wordlists_cmd
    from hackbot.tools.remote import WordlistEntry

    eng = tmp_path / "eng"
    (eng).mkdir()
    (eng / "runner.json").write_text("{}")

    class _R:
        def __init__(self, *a, **k):
            pass

        def discover_wordlists(self):
            return (
                WordlistEntry("/usr/share/wordlists/dirb/common.txt", 4614),
                WordlistEntry("/usr/share/seclists/Discovery/DNS/n.txt", 10),
            )

    monkeypatch.setattr(wordlists_cmd, "load_remote_config", lambda p: object())
    monkeypatch.setattr(wordlists_cmd, "RemoteRunner", _R)

    rc = wordlists_cmd.cmd_list(engagement=str(eng), runner="remote", as_json=True)
    assert rc == 0
    payload = _json.loads(capsys.readouterr().out)
    assert payload["wordlists"] == [
        {"path": "/usr/share/seclists/Discovery/DNS/n.txt", "size_bytes": 10},
        {"path": "/usr/share/wordlists/dirb/common.txt", "size_bytes": 4614},
    ]


def test_wordlists_list_requires_engagement(capsys):
    from hackbot.cli import wordlists_cmd

    rc = wordlists_cmd.cmd_list(engagement=None, runner="remote", as_json=False)
    assert rc == 2
    assert "engagement" in capsys.readouterr().err.lower()


def test_wordlists_list_rejects_non_remote_runner(capsys):
    from hackbot.cli import wordlists_cmd

    rc = wordlists_cmd.cmd_list(engagement="x", runner="local", as_json=False)
    assert rc == 2
    assert "runner" in capsys.readouterr().err.lower()


def test_wordlists_list_reports_remote_error(tmp_path, capsys, monkeypatch):
    from hackbot.cli import wordlists_cmd
    from hackbot.tools.remote import RemoteError

    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "runner.json").write_text("{}")

    def _boom(_p):
        raise RemoteError("bad config")

    monkeypatch.setattr(wordlists_cmd, "load_remote_config", _boom)
    rc = wordlists_cmd.cmd_list(engagement=str(eng), runner="remote", as_json=False)
    assert rc == 2
    assert "bad config" in capsys.readouterr().err
