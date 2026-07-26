"""SSH RemoteConfig and RemoteRunner (gate stays local; execution is remote)."""

import json

import pytest

from hackbot.tools.remote import RemoteConfig, RemoteError, RemoteRunner, load_remote_config
from hackbot.tools.runner import CommandResult


def _cfg(tmp_path):
    key = tmp_path / "id"
    key.write_text("KEY")
    key.chmod(0o600)
    return RemoteConfig(host="192.168.64.4", user="kali", port=22, key_path=str(key))


def test_load_remote_config_parses(tmp_path):
    key = tmp_path / "id"
    key.write_text("KEY")
    key.chmod(0o600)
    path = tmp_path / "runner.json"
    path.write_text(json.dumps({"host": "h", "user": "u", "port": 2222, "key_path": str(key)}))
    cfg = load_remote_config(path)
    assert cfg.host == "h" and cfg.user == "u" and cfg.port == 2222
    assert cfg.key_path == str(key)


def test_load_remote_config_rejects_bad_port(tmp_path):
    key = tmp_path / "id"
    key.write_text("KEY")
    path = tmp_path / "runner.json"
    path.write_text(json.dumps({"host": "h", "user": "u", "port": 0, "key_path": str(key)}))
    with pytest.raises(RemoteError):
        load_remote_config(path)


def test_load_remote_config_requires_existing_key(tmp_path):
    path = tmp_path / "runner.json"
    path.write_text(json.dumps({"host": "h", "user": "u", "port": 22, "key_path": "/nope/key"}))
    with pytest.raises(RemoteError):
        load_remote_config(path)


class _Fake:
    def __init__(self):
        self.argv = None

    def run(self, argv):
        self.argv = tuple(argv)
        return CommandResult(0, b"remote-ok", b"", 5, False, False)


def test_remote_runner_builds_safe_ssh_argv(tmp_path):
    fake = _Fake()
    cfg = _cfg(tmp_path)
    runner = RemoteRunner(cfg, runner=fake, ssh_path="/usr/bin/ssh")
    result = runner.run(("/opt/homebrew/bin/curl", "-sS", "http://in-scope/; rm -rf /"))
    assert result.stdout == b"remote-ok"
    argv = fake.argv
    assert argv[0] == "/usr/bin/ssh"
    assert "-i" in argv and cfg.key_path in argv
    assert "BatchMode=yes" in argv
    assert "kali@192.168.64.4" in argv
    remote_cmd = argv[-1]
    assert remote_cmd.startswith("curl ")  # basename, not the local abs path
    assert "'http://in-scope/; rm -rf /'" in remote_cmd  # metachars stay one quoted token


def test_remote_runner_rejects_empty_argv(tmp_path):
    with pytest.raises(RemoteError):
        RemoteRunner(_cfg(tmp_path), runner=_Fake(), ssh_path="/usr/bin/ssh").run(())
