"""
Secret-hygiene tests. Verify alias resolution, existence-only disclosure, empty
rejection, and that values never appear in repr/status.
"""

import pytest

from hackbot.security.secrets import (
    InMemoryBackend,
    SecretError,
    SecretManager,
    UnknownSecretName,
    canonical_name,
)


@pytest.fixture
def mgr():
    return SecretManager(backend=InMemoryBackend())


def test_alias_resolution():
    assert canonical_name("kimi3") == "MOONSHOT_API_KEY"
    assert canonical_name("shodan") == "SHODAN_API_KEY"
    assert canonical_name("claude") == "ANTHROPIC_API_KEY"
    assert canonical_name("ANTHROPIC_API_KEY") == "ANTHROPIC_API_KEY"


def test_unknown_name_rejected():
    with pytest.raises(UnknownSecretName):
        canonical_name("not a valid name!!")


def test_alias_resolution_is_case_insensitive():
    for variant in ("kimi3", "Kimi3", "KIMI3", "KiMi3"):
        assert canonical_name(variant) == "MOONSHOT_API_KEY", variant
    for variant in ("shodan", "Shodan", "SHODAN"):
        assert canonical_name(variant) == "SHODAN_API_KEY", variant
    for variant in ("claude", "Claude", "CLAUDE", "anthropic", "Anthropic"):
        assert canonical_name(variant) == "ANTHROPIC_API_KEY", variant


def test_set_get_roundtrip(mgr):
    cname = mgr.set("shodan", "s3cr3t-value")
    assert cname == "SHODAN_API_KEY"
    assert mgr.get("shodan") == "s3cr3t-value"
    assert mgr.exists("shodan")


def test_empty_secret_rejected(mgr):
    with pytest.raises(SecretError):
        mgr.set("shodan", "   ")


def test_status_reveals_only_existence(mgr):
    mgr.set("deepseek", "dsk-abc")
    st = mgr.status()
    assert st["DEEPSEEK_API_KEY"] is True
    assert st["SHODAN_API_KEY"] is False
    # values must never appear anywhere in status
    assert "dsk-abc" not in repr(st)
    assert all(isinstance(v, bool) for v in st.values())


def test_repr_never_leaks_value(mgr):
    mgr.set("anthropic", "sk-ant-SUPERSECRET")
    assert "SUPERSECRET" not in repr(mgr)
    assert "ANTHROPIC_API_KEY" in repr(mgr)  # name ok, value not


def test_delete(mgr):
    mgr.set("kimi3", "moon")
    assert mgr.delete("kimi3") is True
    assert not mgr.exists("kimi3")
    assert mgr.delete("kimi3") is False


def test_alias_and_canonical_share_slot(mgr):
    mgr.set("kimi3", "one")
    # moonshot is the same canonical secret
    assert mgr.get("moonshot") == "one"
