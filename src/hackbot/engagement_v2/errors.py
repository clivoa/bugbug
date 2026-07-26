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

    def __init__(self, reason_code: ReasonCode) -> None:
        if type(reason_code) is not ReasonCode:
            raise TypeError("reason_code must be an exact ReasonCode")
        self.reason_code = reason_code
        self.message = reason_code.value.lower().replace("_", " ")
        super().__init__(f"{reason_code.value}: {self.message}")

    def as_dict(self) -> dict[str, str]:
        """Return the stable, secret-free public failure representation."""

        return {"reason_code": self.reason_code.value, "message": self.message}
