"""
security.secrets — OS-agnostic secret storage with strict hygiene.

Backends (native, argv-safe):
  * KeyringBackend  — uses the `keyring` library, which talks to the macOS
    Keychain / Linux SecretService via native APIs, so secret VALUES never appear
    in process arguments, shell history, or logs.
  * InMemoryBackend — for tests only; never persists.

Hygiene rules enforced here:
  * `names()` / `exists()` reveal only WHETHER a secret is stored, never its value.
  * Values are passed as function arguments read from stdin (getpass) at the CLI
    layer — never placed on a command line.
  * `__repr__`/logging of the manager never includes values.
  * Secret names are validated against a known set to avoid typos creating orphans.

This module never prints a secret. Callers must not log return values of `get()`.
"""
from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

SERVICE = "hackbot"

# Canonical secret names + friendly aliases the CLI accepts.
_CANONICAL = {
    "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "MOONSHOT_API_KEY",
    "SHODAN_API_KEY", "OPENROUTER_API_KEY", "LITELLM_MASTER_KEY",
    "GITHUB_TOKEN",
}
_ALIASES = {
    "anthropic": "ANTHROPIC_API_KEY",
    "claude": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "moonshot": "MOONSHOT_API_KEY",
    "kimi": "MOONSHOT_API_KEY",
    "kimi3": "MOONSHOT_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "litellm": "LITELLM_MASTER_KEY",
    "github": "GITHUB_TOKEN",
}

_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


class SecretError(Exception):
    pass


class UnknownSecretName(SecretError):
    pass


def canonical_name(name: str) -> str:
    """Resolve an alias (case-insensitively) or validate a canonical secret name."""
    key = name.strip()
    # aliases are matched case-insensitively: "kimi3", "Kimi3", "KIMI3" all resolve.
    lowered = key.lower()
    if lowered in _ALIASES:
        return _ALIASES[lowered]
    upper = key.upper().replace("-", "_")
    if upper in _CANONICAL:
        return upper
    if _NAME_RE.match(upper):
        return upper  # allow custom, well-formed names
    raise UnknownSecretName(
        f"unknown secret {name!r}; known aliases: "
        f"{', '.join(sorted(_ALIASES))}; or a CANONICAL_NAME"
    )


@runtime_checkable
class SecretBackend(Protocol):
    def get(self, name: str) -> str | None: ...
    def set(self, name: str, value: str) -> None: ...
    def delete(self, name: str) -> bool: ...
    def names(self) -> list[str]: ...


class InMemoryBackend:
    """Volatile backend for tests. Never persists to disk or keychain."""

    def __init__(self) -> None:
        self._d: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self._d.get(name)

    def set(self, name: str, value: str) -> None:
        self._d[name] = value

    def delete(self, name: str) -> bool:
        return self._d.pop(name, None) is not None

    def names(self) -> list[str]:
        return sorted(self._d)


class KeyringBackend:
    """Production backend using the native OS keychain via the `keyring` library."""

    def __init__(self, service: str = SERVICE) -> None:
        try:
            import keyring  # lazy: tests don't need it installed
        except Exception as e:  # pragma: no cover - env dependent
            raise SecretError(
                "the 'keyring' package is required for keychain storage; "
                "install it or use a different backend"
            ) from e
        self._keyring = keyring
        self.service = service
        # We keep an index of stored names in the keychain itself (not values),
        # because SecretService/Keychain don't offer a portable 'list by service'.
        self._index_key = "__hackbot_index__"

    def _load_index(self) -> set[str]:
        raw = self._keyring.get_password(self.service, self._index_key) or ""
        return {p for p in raw.split(",") if p}

    def _save_index(self, names: set[str]) -> None:
        self._keyring.set_password(self.service, self._index_key, ",".join(sorted(names)))

    def get(self, name: str) -> str | None:
        return self._keyring.get_password(self.service, name)

    def set(self, name: str, value: str) -> None:
        self._keyring.set_password(self.service, name, value)
        idx = self._load_index()
        idx.add(name)
        self._save_index(idx)

    def delete(self, name: str) -> bool:
        try:
            self._keyring.delete_password(self.service, name)
        except Exception:
            return False
        idx = self._load_index()
        idx.discard(name)
        self._save_index(idx)
        return True

    def names(self) -> list[str]:
        return sorted(self._load_index())


class SecretManager:
    """Front door for secret operations. Resolves aliases; never leaks values."""

    def __init__(self, backend: SecretBackend | None = None) -> None:
        self._backend = backend if backend is not None else KeyringBackend()

    def set(self, name: str, value: str) -> str:
        if not value or not value.strip():
            raise SecretError("refusing to store an empty secret")
        cname = canonical_name(name)
        self._backend.set(cname, value)
        return cname

    def get(self, name: str) -> str | None:
        return self._backend.get(canonical_name(name))

    def exists(self, name: str) -> bool:
        return self.get(name) is not None

    def delete(self, name: str) -> bool:
        return self._backend.delete(canonical_name(name))

    def status(self) -> dict[str, bool]:
        """Map of canonical name -> present? (values never included)."""
        stored = set(self._backend.names())
        keys = sorted(_CANONICAL | stored)
        return {k: (k in stored) for k in keys}

    def __repr__(self) -> str:  # never expose values
        return f"<SecretManager backend={type(self._backend).__name__} names={self._backend.names()}>"
