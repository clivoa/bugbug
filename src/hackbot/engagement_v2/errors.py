"""Typed, secret-free public failures for engagement v2 contracts."""

from __future__ import annotations

from enum import Enum


class ReasonCode(str, Enum):
    """Closed public reason codes for contract failures."""

    INVALID_SCHEMA_VERSION = "INVALID_SCHEMA_VERSION"
    INVALID_DOCUMENT_SIZE = "INVALID_DOCUMENT_SIZE"
    INVALID_DOCUMENT_ENCODING = "INVALID_DOCUMENT_ENCODING"
    INVALID_DOCUMENT_STRUCTURE = "INVALID_DOCUMENT_STRUCTURE"
    INVALID_UNKNOWN_FIELD = "INVALID_UNKNOWN_FIELD"
    INVALID_DUPLICATE_KEY = "INVALID_DUPLICATE_KEY"
    INVALID_IDENTIFIER = "INVALID_IDENTIFIER"
    INVALID_LIMIT = "INVALID_LIMIT"
    INVALID_CANONICAL_VALUE = "INVALID_CANONICAL_VALUE"
    INVALID_ACTION_MANIFEST = "INVALID_ACTION_MANIFEST"
    INVALID_PLACEHOLDER = "INVALID_PLACEHOLDER"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_RUNNER = "INVALID_RUNNER"
    DENY_AUTHORIZATION_UNCONFIRMED = "DENY_AUTHORIZATION_UNCONFIRMED"
    DENY_AUTHORIZATION_STALE = "DENY_AUTHORIZATION_STALE"
    DENY_CAPABILITY_NOT_ALLOWED = "DENY_CAPABILITY_NOT_ALLOWED"
    DENY_POLICY_LIMIT = "DENY_POLICY_LIMIT"
    DENY_RATE_UNENFORCEABLE = "DENY_RATE_UNENFORCEABLE"
    EXEC_PROTOCOL_INVALID = "EXEC_PROTOCOL_INVALID"
    EXEC_PROTOCOL_EXPIRED = "EXEC_PROTOCOL_EXPIRED"
    EXEC_PROTOCOL_REPLAY = "EXEC_PROTOCOL_REPLAY"
    EXEC_TRUST_MISMATCH = "EXEC_TRUST_MISMATCH"
    EXEC_PRIVILEGE_MISMATCH = "EXEC_PRIVILEGE_MISMATCH"
    EVIDENCE_POLICY_DENIED = "EVIDENCE_POLICY_DENIED"
    CLEANUP_RESOURCE_INCOMPLETE = "CLEANUP_RESOURCE_INCOMPLETE"
    CLEANUP_TARGET_INCOMPLETE = "CLEANUP_TARGET_INCOMPLETE"


class ContractError(ValueError):
    """A public failure containing only a registered, code-owned message."""

    __slots__ = ()

    def __init__(self, reason_code: ReasonCode) -> None:
        if type(reason_code) is not ReasonCode:
            raise TypeError("reason_code must be an exact ReasonCode")
        super().__init__(reason_code)

    @property
    def reason_code(self) -> ReasonCode:
        """Return the exact registered reason held by this immutable error."""

        reason_code = self.args[0]
        if type(reason_code) is not ReasonCode:
            raise TypeError("stored reason_code must be an exact ReasonCode")
        return reason_code

    @property
    def message(self) -> str:
        """Derive the deterministic code-owned message."""

        return self.reason_code.value.lower().replace("_", " ")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ContractError is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("ContractError is immutable")

    def __str__(self) -> str:
        return f"{self.reason_code.value}: {self.message}"

    def as_dict(self) -> dict[str, str]:
        """Return the stable, secret-free public failure representation."""

        reason_code = self.reason_code
        message = reason_code.value.lower().replace("_", " ")
        return {"reason_code": reason_code.value, "message": message}
