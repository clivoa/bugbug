"""End-to-end: net.http-get fetches an in-scope lab URL, denies out of scope."""

from datetime import UTC, datetime

import pytest

from hackbot.audit.tool_runs import AuditSink
from hackbot.evidence.store import EvidenceStore
from hackbot.risk.context import load_policy_context
from hackbot.risk.models import ActionRequest, DecisionKind
from hackbot.tools.actions import REAL_ACTIONS, curl_path
from hackbot.tools.adapter import run_action
from hackbot.tools.runner import CommandRunner

pytestmark = pytest.mark.skipif(curl_path() is None, reason="curl not installed")


def _request(context, target):
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id="net.http-get",
        target=target,
        argv=(curl_path(), "-sS", "--max-time", "10", target),
        hypothesis_id="hyp-1",
        rationale="Fetch one in-scope lab URL once.",
        rate=1,
        concurrency=1,
        data_touched="Public lab response.",
        expected_impact="One low-rate GET against a local lab.",
        stop_condition="Stop on any error.",
        cleanup_plan="No state created.",
        program_rule="Authorized lab fetch.",
        required_headers=(),
        requested_risk=None,
    )


def test_http_get_fetches_in_scope_lab_url(lab_engagement, local_server):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("net.http-get")
    outcome = run_action(
        definition,
        _request(context, local_server),
        context,
        now=datetime.now(UTC),
        runner=CommandRunner(),
        audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert outcome.command_result.exit_code == 0
    assert b"lab-ok" in outcome.command_result.stdout


def test_http_get_out_of_scope_is_denied_without_execution(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("net.http-get")
    outcome = run_action(
        definition,
        _request(context, "http://10.0.0.5/"),
        context,
        now=datetime.now(UTC),
        runner=CommandRunner(),
        audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.reason_code == "DENY_SCOPE"
    assert outcome.executed is False


@pytest.mark.parametrize(
    "action_id,argv_tail",
    [
        ("net.http-head", ("-sS", "-I", "--max-time", "10")),
        ("net.http-options", ("-sS", "-i", "-X", "OPTIONS", "--max-time", "10")),
    ],
)
def test_passive_probe_executes_in_scope(lab_engagement, local_server, action_id, argv_tail):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require(action_id)
    argv = (curl_path(), *argv_tail, local_server)
    request = ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id=action_id,
        target=local_server,
        argv=argv,
        hypothesis_id="hyp-1",
        rationale="Probe one in-scope lab URL once.",
        rate=1,
        concurrency=1,
        data_touched="Public lab response.",
        expected_impact="One low-rate passive probe.",
        stop_condition="Stop on any error.",
        cleanup_plan="No state created.",
        program_rule="Authorized lab probe.",
        required_headers=(),
        requested_risk=None,
    )
    outcome = run_action(
        definition,
        request,
        context,
        now=datetime.now(UTC),
        runner=CommandRunner(),
        audit=AuditSink(lab_engagement),
        evidence=EvidenceStore(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert outcome.command_result.exit_code == 0
    assert outcome.evidence_run_id
