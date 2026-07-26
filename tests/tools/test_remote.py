"""SSH RemoteConfig and RemoteRunner (gate stays local; execution is remote)."""

import json

import pytest

from hackbot.tools.remote import (
    RemoteConfig,
    RemoteError,
    RemoteRunner,
    WordlistEntry,
    load_remote_config,
)
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


def test_probe_builds_command_v_script_and_parses(tmp_path):
    class _P:
        def run(self, argv):
            self.argv = tuple(argv)
            return CommandResult(0, b"curl\ngobuster\n", b"", 4, False, False)

    fake = _P()
    runner = RemoteRunner(_cfg(tmp_path), runner=fake, ssh_path="/usr/bin/ssh")
    found = runner.probe(["curl", "gobuster", "nmap"])
    assert found == {"curl", "gobuster"}
    remote_cmd = fake.argv[-1]
    assert "command -v curl" in remote_cmd and "command -v gobuster" in remote_cmd


def test_probe_rejects_unsafe_tool_name(tmp_path):
    runner = RemoteRunner(_cfg(tmp_path), runner=_Fake(), ssh_path="/usr/bin/ssh")
    with pytest.raises(RemoteError):
        runner.probe(["curl; rm -rf /"])


def test_discover_wordlists_parses_and_sorts(tmp_path):
    class _W:
        def run(self, argv):
            self.argv = tuple(argv)
            return CommandResult(
                0,
                b"4749\t/usr/share/seclists/Discovery/Web-Content/common.txt\n"
                b"100\t/usr/share/wordlists/dirb/small.txt\n"
                b"4749\t/usr/share/seclists/Discovery/Web-Content/common.txt\n",  # dup
                b"",
                7,
                False,
                False,
            )

    fake = _W()
    runner = RemoteRunner(_cfg(tmp_path), runner=fake, ssh_path="/usr/bin/ssh")
    entries = runner.discover_wordlists()
    assert entries == (
        WordlistEntry("/usr/share/seclists/Discovery/Web-Content/common.txt", 4749),
        WordlistEntry("/usr/share/wordlists/dirb/small.txt", 100),
    )
    remote_cmd = fake.argv[-1]
    assert "find" in remote_cmd and "-maxdepth 4" in remote_cmd
    # roots are shlex.quote'd; they contain only safe chars so no quotes are added
    assert "/usr/share/seclists/Discovery/Web-Content" in remote_cmd
    assert "head -n 2000" in remote_cmd


def test_discover_wordlists_drops_malformed_and_out_of_allowlist(tmp_path):
    class _W:
        def run(self, argv):
            return CommandResult(
                0,
                b"12\t/etc/passwd\n"  # not under an allowlist root
                b"12\t/usr/share/wordlists/dirb/ok.txt\n"
                b"12\t/usr/share/wordlists/dirb/we ird.txt\n"  # space in path
                b"x\t/usr/share/wordlists/dirb/bad.txt\n"  # non-numeric size
                b"12\t/usr/share/wordlists/dirb/ctrl\x01.txt\n"  # control char
                b"garbage-line-no-tab\n",
                b"",
                7,
                False,
                False,
            )

    runner = RemoteRunner(_cfg(tmp_path), runner=_W(), ssh_path="/usr/bin/ssh")
    entries = runner.discover_wordlists()
    assert entries == (WordlistEntry("/usr/share/wordlists/dirb/ok.txt", 12),)


def test_discover_wordlists_drops_non_ascii_digit_size(tmp_path):
    class _W:
        def run(self, argv):
            return CommandResult(
                0,
                b"\xc2\xb2\t/usr/share/wordlists/dirb/x.txt\n"  # size is U+00B2 (superscript 2)
                b"12\t/usr/share/wordlists/dirb/ok.txt\n",
                b"",
                7,
                False,
                False,
            )

    runner = RemoteRunner(_cfg(tmp_path), runner=_W(), ssh_path="/usr/bin/ssh")
    entries = runner.discover_wordlists()
    assert entries == (WordlistEntry("/usr/share/wordlists/dirb/ok.txt", 12),)


def test_discover_wordlists_empty_stdout(tmp_path):
    class _W:
        def run(self, argv):
            return CommandResult(0, b"", b"", 1, False, False)

    runner = RemoteRunner(_cfg(tmp_path), runner=_W(), ssh_path="/usr/bin/ssh")
    assert runner.discover_wordlists() == ()


def test_discover_wordlists_wraps_runner_error(tmp_path):
    from hackbot.tools.runner import RunnerError

    class _W:
        def run(self, argv):
            raise RunnerError("ssh boom")

    runner = RemoteRunner(_cfg(tmp_path), runner=_W(), ssh_path="/usr/bin/ssh")
    with pytest.raises(RemoteError):
        runner.discover_wordlists()
