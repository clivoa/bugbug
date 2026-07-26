"""Run a code-owned action argv on a remote host over SSH (gate stays local).

The risk gate (scope + risk + approval) runs locally, exactly as for a local run;
only *execution* happens on the configured remote host. The SSH command is built
from the already-validated, code-owned action argv with every token
``shlex.quote``d and ``argv[0]`` reduced to its basename (resolved on the remote
PATH), so no shell metacharacter in a scope-validated target can inject.
"""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from hackbot.tools.runner import CommandResult, CommandRunner, RunnerError

_SSH_CANDIDATES: tuple[str, ...] = ("/usr/bin/ssh", "/opt/homebrew/bin/ssh", "/usr/local/bin/ssh")
_CONFIG_KEYS = frozenset({"host", "user", "port", "key_path", "connect_timeout"})


class RemoteError(Exception):
    """Raised for an invalid remote config or a malformed remote invocation."""


@dataclass(frozen=True, slots=True)
class RemoteConfig:
    host: str
    user: str
    port: int
    key_path: str
    connect_timeout: int = 10


def _clean(value: object, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(c.isspace() or ord(c) < 0x20 for c in value)
    ):
        raise RemoteError(f"{name}: expected a non-empty token with no whitespace/control chars")
    return value


def load_remote_config(path: str | Path) -> RemoteConfig:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RemoteError(f"cannot read runner config: {exc}") from exc
    if not isinstance(value, dict) or set(value) - _CONFIG_KEYS:
        raise RemoteError("runner config must be a JSON object with known keys")
    host = _clean(value.get("host"), name="host")
    user = _clean(value.get("user"), name="user")
    port = value.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise RemoteError("port: expected an integer 1..65535")
    key_path = value.get("key_path")
    if not isinstance(key_path, str) or not os.path.isabs(key_path) or not os.path.isfile(key_path):
        raise RemoteError("key_path: expected an absolute path to an existing key file")
    connect_timeout = value.get("connect_timeout", 10)
    if (
        isinstance(connect_timeout, bool)
        or not isinstance(connect_timeout, int)
        or not 1 <= connect_timeout <= 120
    ):
        raise RemoteError("connect_timeout: expected an integer 1..120")
    return RemoteConfig(
        host=host, user=user, port=port, key_path=key_path, connect_timeout=connect_timeout
    )


def _resolve_ssh(explicit: str | None) -> str:
    if explicit is not None:
        return explicit
    for candidate in _SSH_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    raise RemoteError("ssh executable not found")


class RemoteRunner:
    def __init__(
        self,
        config: RemoteConfig,
        *,
        runner: object | None = None,
        ssh_path: str | None = None,
    ) -> None:
        self._config = config
        self._ssh = _resolve_ssh(ssh_path)
        self._runner = runner if runner is not None else CommandRunner()

    def run(self, argv: Sequence[str]) -> CommandResult:
        items = tuple(argv)
        if not items:
            raise RemoteError("argv must be non-empty")
        tool = os.path.basename(items[0])
        remote_cmd = " ".join(shlex.quote(t) for t in (tool, *items[1:]))
        cfg = self._config
        ssh_argv = (
            self._ssh,
            "-F",
            "/dev/null",
            "-i",
            cfg.key_path,
            "-p",
            str(cfg.port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={cfg.connect_timeout}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={cfg.key_path}.known_hosts",
            f"{cfg.user}@{cfg.host}",
            remote_cmd,
        )
        try:
            return self._runner.run(ssh_argv)  # type: ignore[attr-defined]
        except RunnerError as exc:
            raise RemoteError(str(exc)) from exc
