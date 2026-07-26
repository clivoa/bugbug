"""Policy-free CommandRunner: argv arrays only, never a shell."""

import os

import pytest

from hackbot.tools.runner import CommandResult, CommandRunner, RunnerError


def test_captures_stdout_and_zero_exit():
    result = CommandRunner().run(("/bin/echo", "hello"))
    assert isinstance(result, CommandResult)
    assert result.exit_code == 0
    assert result.stdout.strip() == b"hello"
    assert result.timed_out is False
    assert result.truncated is False


def test_argv_is_never_shell_interpreted():
    result = CommandRunner().run(("/bin/echo", "a; rm -rf /"))
    assert b"a; rm -rf /" in result.stdout


def test_environment_is_sanitized(monkeypatch):
    monkeypatch.setenv("HACKBOT_TEST_SECRET", "topsecret")
    result = CommandRunner().run(("/usr/bin/env",))
    assert b"HACKBOT_TEST_SECRET" not in result.stdout
    assert b"topsecret" not in result.stdout


def test_timeout_kills_process_group():
    result = CommandRunner(timeout_seconds=0.5).run(("/bin/sleep", "5"))
    assert result.timed_out is True
    assert result.exit_code is None
    assert result.duration_ms < 4000


def test_output_is_capped_and_marked_truncated():
    result = CommandRunner(output_cap_bytes=10).run(("/bin/echo", "x" * 1000))
    assert result.truncated is True
    assert len(result.stdout) <= 10


def test_missing_executable_fails_closed():
    with pytest.raises(RunnerError):
        CommandRunner().run(("/nonexistent/tool-xyz",))


def test_empty_argv_fails_closed():
    with pytest.raises(RunnerError):
        CommandRunner().run(())


def test_provides_an_ephemeral_home():
    result = CommandRunner().run(("/usr/bin/env",))
    out = result.stdout.decode()
    assert "HOME=" in out  # tools that need a config/cache dir get one
    real = os.environ.get("HOME", "")
    if real:
        assert f"HOME={real}\n" not in out  # never the operator's real HOME
