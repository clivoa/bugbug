"""Gate-bound execution: run an action only after a RiskEngine ALLOW.

``run_action`` is the only sanctioned way to execute a code-owned action. It
evaluates the request against the risk gate and runs the rendered, code-owned
argv template through the ``CommandRunner`` *only* when the decision is ``ALLOW``.
Every outcome is recorded in the secret-free audit sink. Captured output is
untrusted data and is never interpreted as instructions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from hackbot.audit.tool_runs import AuditSink
from hackbot.evidence.store import EvidenceStore
from hackbot.risk.models import (
    ActionDefinition,
    ActionRequest,
    ApprovalGrant,
    DecisionKind,
    PolicyContext,
    PolicyDecision,
)
from hackbot.risk.registry import ActionRegistry
from hackbot.tools.runner import CommandResult, CommandRunner


@dataclass(frozen=True, slots=True)
class ActionOutcome:
    decision: PolicyDecision
    command_result: CommandResult | None
    evidence_run_id: str | None = None

    @property
    def executed(self) -> bool:
        return self.command_result is not None


def run_action(
    definition: ActionDefinition,
    request: ActionRequest,
    context: PolicyContext,
    *,
    grant: ApprovalGrant | None = None,
    now: datetime | None = None,
    runner: CommandRunner,
    audit: AuditSink,
    evidence: EvidenceStore | None = None,
    approval_store: object | None = None,
) -> ActionOutcome:
    from hackbot.risk.policy import RiskEngine

    decision_at = now if now is not None else datetime.now(UTC)
    engine = RiskEngine(ActionRegistry([definition]), approval_store=approval_store)  # type: ignore[arg-type]
    decision = engine.evaluate(request, context, grant=grant, now=decision_at)
    rendered = definition.render_argv(request) or ()
    result: CommandResult | None = None
    if decision.kind is DecisionKind.ALLOW and definition.uses_external_tool and rendered:
        result = runner.run(rendered)
    # Audit before evidence, so the trail exists even if evidence capture fails.
    audit.record_run(
        action_id=request.action_id,
        effective_risk=decision.effective_risk,
        target=request.target,
        argv=rendered,
        decision_kind=decision.kind.value,
        reason_code=decision.reason_code,
        result=result,
        now=decision_at,
    )
    evidence_run_id: str | None = None
    if result is not None and evidence is not None:
        evidence_run_id = evidence.record(
            action_id=request.action_id,
            request=request,
            result=result,
            decision_kind=decision.kind.value,
            reason_code=decision.reason_code,
            now=decision_at,
        )
    return ActionOutcome(decision, result, evidence_run_id)
