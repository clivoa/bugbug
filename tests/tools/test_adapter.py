"""Gate-bound run_action: execute only after a RiskEngine ALLOW."""

from datetime import UTC, datetime

from hackbot.audit.tool_runs import AuditSink
from hackbot.evidence.store import EvidenceStore
from hackbot.risk.context import load_policy_context
from hackbot.risk.models import ActionDefinition, ActionRequest, DecisionKind, RiskLevel
from hackbot.tools.adapter import run_action
from hackbot.tools.runner import CommandResult

_ECHO = "/bin/echo"


class FakeRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv):
        self.calls.append(tuple(argv))
        return CommandResult(0, b"ran", b"", 3, False, False)


def _request(context, action_id):
    # External-tool actions always carry a rate/concurrency (an active request);
    # render_argv requires them even when the template has no placeholders.
    return ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id=action_id,
        target="http://127.0.0.1/",
        argv=(_ECHO, "ok") if action_id == "test.echo" else (_ECHO, "x"),
        hypothesis_id="hyp-1",
        rationale="lab probe",
        rate=1,
        concurrency=1,
        data_touched="none",
        expected_impact="none",
        stop_condition="stop on block",
        cleanup_plan="none",
        program_rule="lab rule",
        required_headers=(),
        requested_risk=None,
    )


def test_allow_executes_and_audits(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.echo",
        RiskLevel.L0,
        uses_external_tool=True,
        executable=_ECHO,
        argv_template=(_ECHO, "ok"),
    )
    runner = FakeRunner()
    outcome = run_action(
        definition,
        _request(context, "test.echo"),
        context,
        now=datetime.now(UTC),
        runner=runner,
        audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.executed is True
    assert runner.calls == [(_ECHO, "ok")]
    log = (lab_engagement / "audit" / "tool-runs.jsonl").read_text().splitlines()
    assert len(log) == 1


def test_deny_never_executes(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.prohibited",
        RiskLevel.L3,
        uses_external_tool=True,
        executable=_ECHO,
        argv_template=(_ECHO, "x"),
    )
    runner = FakeRunner()
    outcome = run_action(
        definition,
        _request(context, "test.prohibited"),
        context,
        now=datetime.now(UTC),
        runner=runner,
        audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.executed is False
    assert runner.calls == []


def test_requires_approval_without_grant_never_executes(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.intrusive",
        RiskLevel.L1,
        uses_external_tool=True,
        executable=_ECHO,
        argv_template=(_ECHO, "x"),
        high_volume=True,
    )
    runner = FakeRunner()
    outcome = run_action(
        definition,
        _request(context, "test.intrusive"),
        context,
        now=datetime.now(UTC),
        runner=runner,
        audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert outcome.executed is False
    assert runner.calls == []


def test_allow_captures_evidence(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.echo",
        RiskLevel.L0,
        uses_external_tool=True,
        executable=_ECHO,
        argv_template=(_ECHO, "ok"),
    )
    outcome = run_action(
        definition,
        _request(context, "test.echo"),
        context,
        now=datetime.now(UTC),
        runner=FakeRunner(),
        audit=AuditSink(lab_engagement),
        evidence=EvidenceStore(lab_engagement),
    )
    assert outcome.evidence_run_id is not None
    run_dir = lab_engagement / "evidence" / outcome.evidence_run_id
    assert (run_dir / "stdout").exists()
    assert (run_dir / "meta.json").exists()


def test_deny_captures_no_evidence(lab_engagement):
    context = load_policy_context(lab_engagement)
    definition = ActionDefinition(
        "test.prohibited",
        RiskLevel.L3,
        uses_external_tool=True,
        executable=_ECHO,
        argv_template=(_ECHO, "x"),
    )
    outcome = run_action(
        definition,
        _request(context, "test.prohibited"),
        context,
        now=datetime.now(UTC),
        runner=FakeRunner(),
        audit=AuditSink(lab_engagement),
        evidence=EvidenceStore(lab_engagement),
    )
    assert outcome.evidence_run_id is None
    assert not (lab_engagement / "evidence").exists()


def test_web_dir_enum_requires_approval(lab_engagement):
    from hackbot.tools.actions import REAL_ACTIONS, ffuf_path, web_content_wordlist

    if ffuf_path() is None:
        import pytest

        pytest.skip("ffuf not installed")
    context = load_policy_context(lab_engagement)
    definition = REAL_ACTIONS.require("web.dir-enum")
    target = "http://127.0.0.1/FUZZ"
    argv = (ffuf_path(), "-s", "-rate", "1", "-u", target, "-w", web_content_wordlist())
    request = ActionRequest(
        engagement_id=context.engagement_id,
        engagement_path=context.engagement_path,
        action_id="web.dir-enum",
        target=target,
        argv=argv,
        hypothesis_id="hyp-1",
        rationale="Enumerate one in-scope lab path set once.",
        rate=1,
        concurrency=1,
        data_touched="Public lab responses.",
        expected_impact="One low-rate directory sweep.",
        stop_condition="Stop on any error.",
        cleanup_plan="No state created.",
        program_rule="Authorized lab enumeration.",
        required_headers=(),
        requested_risk=None,
        wordlist=web_content_wordlist(),
    )
    outcome = run_action(
        definition,
        request,
        context,
        now=datetime.now(UTC),
        runner=FakeRunner(),
        audit=AuditSink(lab_engagement),
    )
    assert outcome.decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert outcome.executed is False
