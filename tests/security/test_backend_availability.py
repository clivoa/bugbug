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
def test_real_keyring_backend_roundtrip():
    """Exercise the production backend against a throwaway service, then clean up."""
    import keyring
    from keyring.backends import fail  # noqa: F401  (ensures keyring imports cleanly)
    from hackbot.security.secrets import KeyringBackend

    # use an in-memory keyring so we never touch the user's real login keychain
    try:
        from keyrings.alt.file import PlaintextKeyring  # type: ignore
        keyring.set_keyring(PlaintextKeyring())
    except Exception:
        pytest.skip("no isolated keyring backend available to test safely")

    b = KeyringBackend(service="hackbot-smoketest")
    try:
        b.set("SMOKE_TEST_KEY", "throwaway")
        assert b.get("SMOKE_TEST_KEY") == "throwaway"
        assert "SMOKE_TEST_KEY" in b.names()
    finally:
        b.delete("SMOKE_TEST_KEY")
    assert b.get("SMOKE_TEST_KEY") is None
