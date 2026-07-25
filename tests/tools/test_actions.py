"""Code-owned real action registry (net.http-get)."""

import os

import pytest

from hackbot.tools.actions import (
    REAL_ACTIONS,
    curl_path,
    dig_path,
    openssl_path,
    resolve_executable,
)


def test_resolve_executable_returns_first_existing_absolute_path(tmp_path):
    real = tmp_path / "tool"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    assert resolve_executable(("/nonexistent/x", str(real))) == str(real)
    assert resolve_executable(("/nonexistent/x",)) is None
    assert resolve_executable(("relative/tool",)) is None


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_http_get_is_registered_and_curl_backed():
    definition = REAL_ACTIONS.require("net.http-get")
    assert definition.minimum_risk.name == "L0"
    assert definition.network_access is True
    assert definition.uses_external_tool is True
    assert definition.shell_execution is False
    assert os.path.isabs(definition.executable)
    assert definition.argv_template[-1] == "{target}"


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_http_post_is_registered_l2_and_state_changing():
    from hackbot.risk.models import RiskLevel

    definition = REAL_ACTIONS.require("net.http-post")
    assert definition.state_changing is True
    assert definition.effective_floor is RiskLevel.L2
    assert definition.network_access is True
    assert definition.uses_external_tool is True
    assert definition.shell_execution is False
    assert definition.argv_template[-1] == "{target}"


@pytest.mark.skipif(curl_path() is None, reason="curl not installed")
def test_http_head_and_options_are_registered_l0():
    from hackbot.risk.models import RiskLevel

    for action_id, extra in (("net.http-head", ()), ("net.http-options", ("-X", "OPTIONS"))):
        definition = REAL_ACTIONS.require(action_id)
        assert definition.minimum_risk is RiskLevel.L0
        assert definition.effective_floor is RiskLevel.L0
        assert definition.network_access is True
        assert definition.uses_external_tool is True
        assert definition.state_changing is False
        assert definition.argv_template[-1] == "{target}"
        for token in extra:
            assert token in definition.argv_template


@pytest.mark.skipif(dig_path() is None, reason="dig not installed")
def test_dns_lookup_is_registered_l0():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("dns.lookup")
    assert d.effective_floor is RiskLevel.L0
    assert d.network_access is True and d.uses_external_tool is True
    assert d.state_changing is False
    assert d.argv_template[-1] == "{target}" and "+short" in d.argv_template


@pytest.mark.skipif(openssl_path() is None, reason="openssl not installed")
def test_tls_cert_is_registered_l0():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("tls.cert")
    assert d.effective_floor is RiskLevel.L0
    assert d.network_access is True and d.uses_external_tool is True
    assert d.state_changing is False
    assert d.argv_template[-1] == "{target}" and "s_client" in d.argv_template
