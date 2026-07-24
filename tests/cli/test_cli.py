"""CLI wiring tests: doctor, scope, secrets (in-memory), version."""
import json

import pytest

from hackbot.cli.main import app


def run(argv, capsys, env=None, monkeypatch=None):
    if env and monkeypatch:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
    code = app(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_version(capsys):
    code, out, _ = run(["version"], capsys)
    assert code == 0 and "hackbot" in out


def test_doctor_json_has_python_check(capsys):
    code, out, _ = run(["doctor", "--json", "--no-net"], capsys)
    assert code == 0
    data = json.loads(out)
    assert data["min_python"] == "3.11"
    keys = {c["key"]: c["status"] for c in data["checks"]}
    assert "running" in keys
    # the running interpreter (>=3.11 in CI/venv) must be ok
    assert keys["running"] == "ok"


def test_scope_check_deny(capsys):
    code, out, _ = run(["scope", "check", "https://evil.com", "--in", "example.com"], capsys)
    assert code == 1 and "DENY" in out


def test_scope_check_allow(capsys):
    code, out, _ = run(["scope", "check", "https://api.example.com/", "--in", "example.com"], capsys)
    assert code == 0 and "ALLOW" in out


def test_scope_explain_path_rule(capsys):
    code, out, _ = run(
        ["scope", "explain", "https://example.com/api/x", "--in", "example.com/api"], capsys)
    assert code == 0 and "IN SCOPE" in out and "example.com/api" in out


def test_secrets_set_and_list_memory(capsys, monkeypatch):
    monkeypatch.setenv("HACKBOT_SECRET_BACKEND", "memory")
    # NOTE: memory backend does not persist across app() calls (new instance each
    # time), so we exercise set + list within a single manager via the module API.
    from hackbot.security.secrets import SecretManager, InMemoryBackend
    mgr = SecretManager(backend=InMemoryBackend())
    mgr.set("shodan", "abc")
    st = mgr.status()
    assert st["SHODAN_API_KEY"] is True
    assert "abc" not in json.dumps(st)


def test_secrets_set_reads_stdin_not_argv(capsys, monkeypatch):
    monkeypatch.setenv("HACKBOT_SECRET_BACKEND", "memory")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("sys.stdin.readline", lambda: "piped-secret\n")
    code, out, _ = run(["secrets", "set", "kimi3"], capsys)
    assert code == 0 and "MOONSHOT_API_KEY" in out
    assert "piped-secret" not in out  # value never echoed


def test_secrets_requires_name(capsys):
    with pytest.raises(SystemExit):
        app(["secrets", "test"])
