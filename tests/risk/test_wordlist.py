"""The {wordlist} argv placeholder: operator-supplied, lexically-validated path."""

import pytest

from hackbot.risk.identity import canonical_engagement_identity
from hackbot.risk.models import ActionDefinition, ActionRequest, RiskLevel


def _defn():
    return ActionDefinition(
        "t.fuzz",
        RiskLevel.L0,
        uses_external_tool=True,
        executable="/bin/echo",
        argv_template=("/bin/echo", "-w", "{wordlist}", "{target}"),
    )


def _req(tmp_path, *, argv, wordlist="", target="http://127.0.0.1/"):
    path, engagement_id = canonical_engagement_identity(str(tmp_path))
    return ActionRequest(
        engagement_id=engagement_id,
        engagement_path=path,
        action_id="t.fuzz",
        target=target,
        argv=argv,
        hypothesis_id="h",
        rationale="r",
        rate=1,
        concurrency=1,
        data_touched="d",
        expected_impact="e",
        stop_condition="s",
        cleanup_plan="c",
        program_rule="p",
        required_headers=(),
        requested_risk=None,
        wordlist=wordlist,
    )


def test_wordlist_renders_into_argv(tmp_path):
    argv = ("/bin/echo", "-w", "/usr/share/wl.txt", "http://127.0.0.1/")
    rendered = _defn().render_argv(_req(tmp_path, argv=argv, wordlist="/usr/share/wl.txt"))
    assert rendered == argv


def test_empty_wordlist_with_placeholder_renders_none(tmp_path):
    argv = ("/bin/echo", "-w", "/usr/share/wl.txt", "http://127.0.0.1/")
    assert _defn().render_argv(_req(tmp_path, argv=argv, wordlist="")) is None


def test_wordlist_must_be_absolute(tmp_path):
    with pytest.raises(ValueError):
        _req(tmp_path, argv=("/bin/echo",), wordlist="relative/wl.txt")


def test_default_wordlist_is_empty_for_non_wordlist_actions(tmp_path):
    path, engagement_id = canonical_engagement_identity(str(tmp_path))
    request = ActionRequest(
        engagement_id=engagement_id,
        engagement_path=path,
        action_id="t.plain",
        target="http://127.0.0.1/",
        argv=("/bin/echo", "http://127.0.0.1/"),
        hypothesis_id="h",
        rationale="r",
        rate=1,
        concurrency=1,
        data_touched="d",
        expected_impact="e",
        stop_condition="s",
        cleanup_plan="c",
        program_rule="p",
        required_headers=(),
        requested_risk=None,
    )
    assert request.wordlist == ""
