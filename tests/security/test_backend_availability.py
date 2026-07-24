"""
Backend availability tests:
  * the CLI degrades gracefully (no traceback) when `keyring` is absent;
  * the real KeyringBackend roundtrips against a throwaway service when `keyring`
    IS installed (skipped otherwise — e.g. offline core install).
"""
import importlib.util

import pytest

from hackbot.cli.main import app

HAS_KEYRING = importlib.util.find_spec("keyring") is not None


def test_secrets_list_degrades_without_keyring(capsys, monkeypatch):
    """With no keychain backend available, `secrets list` must guide, not crash."""
    monkeypatch.delenv("HACKBOT_SECRET_BACKEND", raising=False)
    import hackbot.security.secrets as s

    def _boom(*a, **k):
        raise s.SecretError("the 'keyring' package is required for keychain storage")

    monkeypatch.setattr(s, "KeyringBackend", _boom)
    code = app(["secrets", "list"])
    err = capsys.readouterr().err
    assert code == 3
    assert "Traceback" not in err
    assert "hackbot[secrets]" in err


@pytest.mark.skipif(not HAS_KEYRING, reason="keyring not installed (offline core env)")
def test_keyring_backend_roundtrip_isolated():
    """
    Validate KeyringBackend against an ISOLATED, in-process keyring backend — this
    does NOT touch the native macOS Keychain. The native Keychain round-trip lives
    in scripts/keychain_sentinel.py (run out-of-band; never in the default suite).
    """
    import keyring
    from keyring.backend import KeyringBackend as _KBackend
    from hackbot.security.secrets import KeyringBackend

    class _DictKeyring(_KBackend):
        priority = 1  # type: ignore[assignment]

        def __init__(self):
            super().__init__()
            self._store: dict[tuple[str, str], str] = {}

        def get_password(self, service, username):
            return self._store.get((service, username))

        def set_password(self, service, username, password):
            self._store[(service, username)] = password

        def delete_password(self, service, username):
            self._store.pop((service, username), None)

        def get_credential(self, service, username):  # pragma: no cover
            return None

    previous = keyring.get_keyring()
    keyring.set_keyring(_DictKeyring())
    try:
        b = KeyringBackend(service="hackbot-isolated-test")
        b.set("ISOLATED_TEST_KEY", "throwaway")
        assert b.get("ISOLATED_TEST_KEY") == "throwaway"
        assert "ISOLATED_TEST_KEY" in b.names()
        b.delete("ISOLATED_TEST_KEY")
        assert b.get("ISOLATED_TEST_KEY") is None
    finally:
        keyring.set_keyring(previous)
