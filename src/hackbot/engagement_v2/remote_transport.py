"""Fixed exec-only pinned-SSH transport argv construction.

The SSH argv invokes only the fixed absolute helper path with pinned host-key,
identity, and forwarding/TTY options. No action executable, target, parameter,
artifact, or secret is ever interpolated into it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from hackbot.engagement_v2.errors import ContractError, ReasonCode

_ABSOLUTE_PATH = re.compile(r"/[\x21-\x7e]{1,4095}", re.ASCII)
_HOSTNAME = re.compile(r"[A-Za-z0-9.\-:_]{1,253}", re.ASCII)
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,63}", re.ASCII)


def _invalid() -> ContractError:
    return ContractError(ReasonCode.INVALID_RUNNER)


def _require(condition: bool) -> None:
    if not condition:
        raise _invalid()


def _absolute_path(value: object) -> str:
    if not (isinstance(value, str) and _ABSOLUTE_PATH.fullmatch(value) is not None):
        raise _invalid()
    return value


def build_ssh_argv(runner: Mapping[str, object]) -> list[str]:
    """Build the fixed exec-only SSH argv for a confirmed runner, or fail closed."""

    ssh = runner.get("ssh")
    helper = runner.get("helper")
    if not isinstance(ssh, Mapping) or not isinstance(helper, Mapping):
        raise _invalid()

    host = ssh.get("host")
    user = ssh.get("user")
    port = ssh.get("port")
    identity = ssh.get("identity_path", ssh.get("private_key_path"))
    known_hosts = ssh.get("known_hosts_path")
    helper_path = helper.get("path")

    _require(isinstance(host, str) and _HOSTNAME.fullmatch(host) is not None)
    _require(isinstance(user, str) and _USER.fullmatch(user) is not None)
    _require(type(port) is int and 1 <= port <= 65535)
    identity_path = _absolute_path(identity)
    known_hosts_path = _absolute_path(known_hosts)
    fixed_helper = _absolute_path(helper_path)
    assert isinstance(host, str) and isinstance(user, str)

    # Fixed, pinned, exec-only invocation. The only variable data is the pinned
    # runner configuration; no action content ever appears here.
    return [
        "ssh",
        "-T",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "RequestTTY=no",
        "-o",
        f"UserKnownHostsFile={known_hosts_path}",
        "-i",
        identity_path,
        "-p",
        str(port),
        f"{user}@{host}",
        fixed_helper,
    ]
