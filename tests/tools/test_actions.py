"""Code-owned real action registry (net.http-get)."""

import os

import pytest

from hackbot.tools.actions import REAL_ACTIONS, curl_path, resolve_executable


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
