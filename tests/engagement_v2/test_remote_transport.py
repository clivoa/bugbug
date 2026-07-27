"""P4 fixed exec-only SSH argv construction."""

from __future__ import annotations

import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.remote_transport import build_ssh_argv


def _runner() -> dict:
    return {
        "ssh": {
            "host": "10.10.0.5",
            "user": "operator",
            "port": 22,
            "private_key_path": "/home/operator/.ssh/id_ed25519",
            "known_hosts_path": "/home/operator/.ssh/known_hosts",
        },
        "helper": {"path": "/opt/hackbot/hackbot-remote-runner"},
    }


def test_argv_pins_options_and_fixed_helper() -> None:
    argv = build_ssh_argv(_runner())
    assert argv[0] == "ssh"
    joined = " ".join(argv)
    assert "StrictHostKeyChecking=yes" in argv
    assert "IdentitiesOnly=yes" in argv
    assert "BatchMode=yes" in argv
    assert "ForwardAgent=no" in argv and "ForwardX11=no" in argv
    assert "ClearAllForwardings=yes" in argv and "RequestTTY=no" in argv
    assert "UserKnownHostsFile=/home/operator/.ssh/known_hosts" in argv
    assert "operator@10.10.0.5" in argv
    assert argv[-1] == "/opt/hackbot/hackbot-remote-runner"
    # No action/target/secret content is interpolated.
    assert "curl" not in joined and "http" not in joined


def test_missing_ssh_section_fails_closed() -> None:
    with pytest.raises(ContractError) as excinfo:
        build_ssh_argv({"helper": {"path": "/opt/hackbot/helper"}})
    assert excinfo.value.reason_code is ReasonCode.INVALID_RUNNER


def test_relative_helper_path_rejected() -> None:
    runner = _runner()
    runner["helper"]["path"] = "hackbot-remote-runner"
    with pytest.raises(ContractError) as excinfo:
        build_ssh_argv(runner)
    assert excinfo.value.reason_code is ReasonCode.INVALID_RUNNER


def test_bad_port_rejected() -> None:
    runner = _runner()
    runner["ssh"]["port"] = 70000
    with pytest.raises(ContractError):
        build_ssh_argv(runner)
