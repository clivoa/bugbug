"""Code-owned real action registry (net.http-get)."""

import os

import pytest

from hackbot.tools.actions import (
    REAL_ACTIONS,
    REGISTERED_ACTION_IDS,
    curl_path,
    dig_path,
    nmap_path,
    openssl_path,
    resolve_executable,
    web_content_wordlist,
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


@pytest.mark.skipif(dig_path() is None, reason="dig not installed")
@pytest.mark.parametrize(
    "action_id,record", [("dns.txt", "TXT"), ("dns.mx", "MX"), ("dns.ns", "NS")]
)
def test_dns_record_actions_are_registered_l0(action_id, record):
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require(action_id)
    assert d.effective_floor is RiskLevel.L0
    assert d.network_access is True and d.uses_external_tool is True
    assert d.argv_template[-1] == record and "{target}" in d.argv_template


@pytest.mark.skipif(nmap_path() is None, reason="nmap not installed")
def test_port_scan_is_registered_l2_high_volume():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("net.port-scan")
    assert d.effective_floor is RiskLevel.L2
    assert d.high_volume is True
    assert d.network_access is True and d.uses_external_tool is True
    assert d.argv_template[-1] == "{target}"


def test_registered_action_ids_lists_only_available_actions():
    # curl is universally available; its actions are always registered
    assert "net.http-get" in REGISTERED_ACTION_IDS
    if nmap_path() is None:
        assert "net.port-scan" not in REGISTERED_ACTION_IDS


@pytest.mark.skip(reason="web.dir-enum (ffuf) replaced by web.dir-enum-gobuster")
def test_web_dir_enum_is_registered_l2_high_volume():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("web.dir-enum")
    assert d.effective_floor is RiskLevel.L2
    assert d.high_volume is True
    assert d.network_access is True and d.uses_external_tool is True
    assert "-u" in d.argv_template and "{target}" in d.argv_template


@pytest.mark.skip(reason="web.dir-enum (ffuf) replaced by web.dir-enum-gobuster")
def test_web_dir_enum_threads_the_policy_rate_into_ffuf():
    d = REAL_ACTIONS.require("web.dir-enum")
    assert "-rate" in d.argv_template
    assert "{rate}" in d.argv_template


@pytest.mark.skip(reason="web.dir-enum (ffuf) replaced by web.dir-enum-gobuster")
def test_web_dir_enum_takes_a_configurable_wordlist():
    d = REAL_ACTIONS.require("web.dir-enum")
    assert "{wordlist}" in d.argv_template
    assert web_content_wordlist() not in d.argv_template


def test_web_content_wordlist_exists():
    import os

    assert os.path.isfile(web_content_wordlist())


def test_web_dir_enum_gobuster_is_remote_only_l2():
    from hackbot.risk.models import RiskLevel

    d = REAL_ACTIONS.require("web.dir-enum-gobuster")
    assert d.effective_floor is RiskLevel.L2
    assert d.high_volume is True
    assert d.uses_external_tool is True
    assert d.executable == "gobuster"  # bare name -> remote-only
    assert "-u" in d.argv_template and "{target}" in d.argv_template
    assert "{wordlist}" in d.argv_template  # operator supplies the wordlist path
    assert "web.dir-enum-gobuster" in REGISTERED_ACTION_IDS
