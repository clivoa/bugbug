"""End-to-end: dns.lookup and tls.cert run through the substrate."""

from datetime import UTC, datetime

import pytest

from hackbot.audit.tool_runs import AuditSink
from hackbot.evidence.store import EvidenceStore
from hackbot.risk.context import load_policy_context
from hackbot.risk.models import ActionRequest, DecisionKind
from hackbot.tools.actions import REAL_ACTIONS, dig_path, openssl_path
from hackbot.tools.adapter import run_action
from hackbot.tools.runner import CommandRunner


def _request(context, action_id, target, argv):
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id=action_id,
        target=target,
        argv=argv,
        hypothesis_id="hyp-1",
        rationale="Probe one in-scope lab asset once.",
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


def _run(lab_engagement, request, definition, timeout=15.0):
    context = load_policy_context(lab_engagement)
    return run_action(
        definition,
        request,
        context,
        now=datetime.now(UTC),
        runner=CommandRunner(timeout_seconds=timeout),
        audit=AuditSink(lab_engagement),
        evidence=EvidenceStore(lab_engagement),
    )


@pytest.mark.skipif(dig_path() is None, reason="dig not installed")
def test_dns_lookup_executes_in_scope(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("dns.lookup")
    argv = (dig_path(), "+short", "127.0.0.1")
    outcome = _run(lab_engagement, _request(context, "dns.lookup", "127.0.0.1", argv), definition)
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert outcome.command_result.exit_code == 0
    assert outcome.evidence_run_id


@pytest.mark.skipif(openssl_path() is None, reason="openssl not installed")
def test_tls_cert_captures_certificate_in_scope(lab_engagement, tls_server):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("tls.cert")
    argv = (openssl_path(), "s_client", "-connect", tls_server)
    outcome = _run(lab_engagement, _request(context, "tls.cert", tls_server, argv), definition)
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    stdout = outcome.command_result.stdout
    assert b"CERTIFICATE" in stdout or b"subject=" in stdout
    assert outcome.evidence_run_id


@pytest.mark.skipif(openssl_path() is None, reason="openssl not installed")
def test_tls_cert_out_of_scope_is_denied(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("tls.cert")
    argv = (openssl_path(), "s_client", "-connect", "10.0.0.5:443")
    outcome = _run(lab_engagement, _request(context, "tls.cert", "10.0.0.5:443", argv), definition)
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.reason_code == "DENY_SCOPE"
    assert outcome.executed is False


@pytest.mark.skipif(dig_path() is None, reason="dig not installed")
@pytest.mark.parametrize(
    "action_id,record", [("dns.txt", "TXT"), ("dns.mx", "MX"), ("dns.ns", "NS")]
)
def test_dns_record_lookup_executes_in_scope(lab_engagement, action_id, record):
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require(action_id)
    argv = (dig_path(), "+short", "127.0.0.1", record)
    outcome = _run(lab_engagement, _request(context, action_id, "127.0.0.1", argv), definition)
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert outcome.command_result.exit_code == 0
    assert outcome.evidence_run_id
