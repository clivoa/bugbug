"""Best-effort secret redaction over untrusted tool output.

Defense in depth, not a guarantee: this replaces known secret shapes (private
key blocks, Authorization/Cookie-style headers, JWTs, AKIA…/sk_… tokens, and
secret-name assignments) with a placeholder. It does not remove every possible
secret or PII. Evidence is also never printed and lives only in the git-ignored
engagement directory.

Redaction uses its own patterns rather than the approval store's detection
patterns: detection matches minimally (enough to flag), while redaction must
consume the *whole* secret — a header value to end of line, a key block to its
END marker — so no token fragment survives.
"""

from __future__ import annotations

import re

from hackbot.risk.approvals import _is_secret_name

_PLACEHOLDER = "[REDACTED]"

_SECRET_HEADER_RE = re.compile(
    r"(?im)^([ \t]*(?:proxy-)?"
    r"(?:authorization|cookie|set-cookie|x-auth-token|x-api-key|authentication-info)"
    r"[ \t]*:[ \t]*)[^\r\n]+"
)
_SECRET_TOKEN_RE = re.compile(
    r"(?is)("
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----"
    r"|-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----"
    r"|eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"|(?:sk|ghp|glpat|xox[baprs])[_-][A-Za-z0-9_-]{12,}"
    r")"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<name>[A-Za-z][A-Za-z0-9_. -]{0,95})(?P<sep>\s*[:=]\s*)(?P<value>\S+)"
)


def _redact_header(match: re.Match[str]) -> str:
    return match.group(1) + _PLACEHOLDER


def _redact_assignment(match: re.Match[str]) -> str:
    if not _is_secret_name(match.group("name")):
        return match.group(0)
    return match.group("name") + match.group("sep") + _PLACEHOLDER


def redact_bytes(data: bytes) -> bytes:
    text = data.decode("latin-1")
    text = _SECRET_TOKEN_RE.sub(_PLACEHOLDER, text)
    text = _SECRET_HEADER_RE.sub(_redact_header, text)
    text = _SECRET_ASSIGNMENT_RE.sub(_redact_assignment, text)
    return text.encode("latin-1")
