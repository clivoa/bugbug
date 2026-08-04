"""Closed deployment identity for the fixed root-owned P5b Linux broker."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from hackbot.engagement_v2.constants import AUTHORITY_DIGEST_PATTERN
from hackbot.engagement_v2.errors import ContractError, ReasonCode

_BROKER_PATH = "/usr/local/libexec/hackbot-l3-runner"
_SSH_USER = "hackbot-l3"
_FIELDS = frozenset(
    {
        "schema_version",
        "broker_path",
        "broker_sha256",
        "broker_owner_uid",
        "broker_mode",
        "broker_regular_file",
        "broker_symlink",
        "ssh_user",
        "forced_command",
        "interactive_shell",
        "tty",
        "port_forwarding",
        "agent_forwarding",
        "x11_forwarding",
        "authorized_keys_restrict",
        "permitted_signer_sha256",
    }
)
_DISABLED_BOOLEAN_FIELDS = (
    "interactive_shell",
    "tty",
    "port_forwarding",
    "agent_forwarding",
    "x11_forwarding",
)


@dataclass(frozen=True, slots=True)
class L3DeploymentContract:
    """The only accepted broker binary and forced-command SSH identity."""

    broker_path: str
    broker_sha256: str
    broker_owner_uid: int
    broker_mode: int
    broker_regular_file: bool
    broker_symlink: bool
    ssh_user: str
    forced_command: str
    permitted_signer_sha256: str
    authorized_keys_restrict: bool


def _invalid() -> ContractError:
    return ContractError(ReasonCode.INVALID_RUNNER)


def _valid_digest(value: object) -> bool:
    return type(value) is str and AUTHORITY_DIGEST_PATTERN.fullmatch(value) is not None


def validate_l3_deployment(document: Mapping[str, object]) -> L3DeploymentContract:
    """Validate exact fixed deployment fields without trusting runtime reports."""

    if not isinstance(document, Mapping) or set(document) != _FIELDS:
        raise _invalid()
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise _invalid()
    if document["broker_path"] != _BROKER_PATH or document["forced_command"] != _BROKER_PATH:
        raise _invalid()
    if document["ssh_user"] != _SSH_USER:
        raise _invalid()
    if (
        type(document["broker_owner_uid"]) is not int
        or document["broker_owner_uid"] != 0
        or type(document["broker_mode"]) is not int
        or document["broker_mode"] != 0o755
        or document["broker_regular_file"] is not True
        or document["broker_symlink"] is not False
        or document["authorized_keys_restrict"] is not True
    ):
        raise _invalid()
    if any(document[field] is not False for field in _DISABLED_BOOLEAN_FIELDS):
        raise _invalid()
    if not _valid_digest(document["broker_sha256"]) or not _valid_digest(
        document["permitted_signer_sha256"]
    ):
        raise _invalid()
    return L3DeploymentContract(
        broker_path=_BROKER_PATH,
        broker_sha256=str(document["broker_sha256"]),
        broker_owner_uid=0,
        broker_mode=0o755,
        broker_regular_file=True,
        broker_symlink=False,
        ssh_user=_SSH_USER,
        forced_command=_BROKER_PATH,
        permitted_signer_sha256=str(document["permitted_signer_sha256"]),
        authorized_keys_restrict=True,
    )


__all__ = ["L3DeploymentContract", "validate_l3_deployment"]
