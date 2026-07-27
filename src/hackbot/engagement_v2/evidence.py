"""Declared-output evidence retention and secret-aware redaction.

Operator actions default to metadata-only. `redacted-output` requires exact
policy permission and is invalid for credential/sensitive-data capabilities.
Retained output is redacted before storage: every resolved secret byte value is
replaced, then the structural/pattern redactor applies. Raw output is never
stored.
"""

from __future__ import annotations

from collections.abc import Iterable

from hackbot.engagement_v2.constants import EvidenceMode
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.evidence.redact import redact_bytes

# Capabilities for which raw/redacted output must never be persisted.
_SENSITIVE_CAPABILITIES = frozenset(
    {"credential-access", "credential-capture", "sensitive-data-access"}
)
_REDACTION_PLACEHOLDER = b"[REDACTED-SECRET]"


def check_evidence_mode(
    mode: str, capabilities: frozenset[str], *, output_persistence_allowed: bool
) -> None:
    """Reject an evidence mode that policy does not permit (fail closed)."""

    if mode == EvidenceMode.METADATA_ONLY.value:
        return
    if mode == EvidenceMode.REDACTED_OUTPUT.value:
        if not output_persistence_allowed or (capabilities & _SENSITIVE_CAPABILITIES):
            raise ContractError(ReasonCode.EVIDENCE_POLICY_DENIED)
        return
    if mode == EvidenceMode.STRUCTURED.value:
        if capabilities & _SENSITIVE_CAPABILITIES:
            raise ContractError(ReasonCode.EVIDENCE_POLICY_DENIED)
        return
    raise ContractError(ReasonCode.EVIDENCE_POLICY_DENIED)


def redact(data: bytes, secret_values: Iterable[bytes]) -> bytes:
    """Replace resolved secret bytes, then apply the structural/pattern redactor."""

    redacted = data
    # Longest-first so a secret that contains another is handled first.
    for secret in sorted((value for value in secret_values if value), key=len, reverse=True):
        redacted = redacted.replace(secret, _REDACTION_PLACEHOLDER)
    return redact_bytes(redacted)
