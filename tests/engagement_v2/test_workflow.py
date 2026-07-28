"""P6 workflow schema, fresh-decision state machine, barriers, and gating."""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from hackbot.engagement_v2.constants import ResourceCleanupState, TargetCleanupState
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.executor import ExecutionResult
from hackbot.engagement_v2.loader import load_engagement
from hackbot.engagement_v2.workflow import (
    WorkflowStatus,
    guard_autonomous_progression,
    run_workflow,
    validate_workflow,
    workflow_authority_digest,
)

from ._engagement_builders import program_doc, scope_doc, write_engagement
from ._workflow_builders import step_doc, workflow_doc, workflow_registry


# ------------------------------------------------------------------ helpers ---
def _program(**testing_rules: Any) -> dict[str, Any]:
    program = program_doc()
    program["testing_rules"]["autonomous_progression_allowed"] = True
    program["testing_rules"].update(testing_rules)
    return program


def _snapshot(
    *, program: dict[str, Any] | None = None, authority_digest: str = "engv2:auth-a"
) -> SimpleNamespace:
    return SimpleNamespace(
        authorization={"confirmed": True},
        program=program if program is not None else _program(),
        scope=scope_doc(),
        profile="private-pentest",
        authority_digest=authority_digest,
        identity="engv2:id",
    )


def _result(
    *,
    executed: bool = True,
    exit_code: int | None = 0,
    resource: str = ResourceCleanupState.COMPLETE.value,
    target: str = TargetCleanupState.NOT_REQUIRED.value,
) -> ExecutionResult:
    return ExecutionResult(
        lifecycle="finalized",
        executed=executed,
        reason="ALLOW" if executed else "failed",
        exit_code=exit_code,
        resource_cleanup_status=resource,
        target_cleanup_status=target,
    )


class _Executor:
    """A recording step executor with an optional per-action result script."""

    def __init__(self, script: dict[str, list[ExecutionResult]] | None = None) -> None:
        self.script = script or {}
        self.calls: list[str] = []
        self.after: dict[str, Any] | None = None  # snapshot mutation after first call

    def __call__(self, bound: Any, action: Any, snapshot: Any, decision: Any) -> ExecutionResult:
        self.calls.append(action.id)
        if self.after is not None:
            for key, value in self.after.items():
                setattr(snapshot, key, value)
            self.after = None
        queue = self.script.get(action.id)
        if queue:
            return queue.pop(0)
        return _result()


def _confirmed(workflow: Any, snapshot: Any) -> str:
    return workflow_authority_digest(snapshot.authority_digest, workflow.projection)


def _run(workflow: Any, snapshot: Any, executor: _Executor, **over: Any) -> Any:
    kwargs: dict[str, Any] = {
        "platform": "linux",
        "confirmed_workflow_digest": _confirmed(workflow, snapshot),
        "step_executor": executor,
    }
    kwargs.update(over)
    return run_workflow(workflow, snapshot, workflow_registry(), **kwargs)


# =============================================================== task 1: schema
def test_valid_workflow_builds_immutable_typed_dag() -> None:
    workflow = validate_workflow(workflow_doc(), workflow_registry())
    assert workflow.workflow_id == "operator.recon-flow"
    assert tuple(step.id for step in workflow.steps) == ("s0",)
    with pytest.raises((AttributeError, TypeError)):
        workflow.steps[0].parameters["rate"] = 9  # type: ignore[index]


def test_unknown_action_rejected() -> None:
    document = workflow_doc(steps=[step_doc(action_id="operator.does-not-exist")])
    with pytest.raises(ContractError) as excinfo:
        validate_workflow(document, workflow_registry())
    assert excinfo.value.reason_code is ReasonCode.INVALID_WORKFLOW_MANIFEST


def test_cycle_or_forward_reference_rejected() -> None:
    # s0 depends on a later step id: a forward reference / cycle fails closed.
    document = workflow_doc(steps=[step_doc(step_id="s0", depends_on=["s1"])])
    with pytest.raises(ContractError) as excinfo:
        validate_workflow(document, workflow_registry())
    assert excinfo.value.reason_code is ReasonCode.INVALID_WORKFLOW_MANIFEST


def test_untyped_output_rejected() -> None:
    document = workflow_doc(steps=[step_doc(outputs={"code": {"source": "exit_code"}})])
    with pytest.raises(ContractError) as excinfo:
        validate_workflow(document, workflow_registry())
    assert excinfo.value.reason_code is ReasonCode.INVALID_WORKFLOW_MANIFEST


def test_raw_output_source_rejected() -> None:
    document = workflow_doc(
        steps=[step_doc(outputs={"leak": {"type": "scalar", "source": "stdout"}})]
    )
    with pytest.raises(ContractError) as excinfo:
        validate_workflow(document, workflow_registry())
    assert excinfo.value.reason_code is ReasonCode.INVALID_WORKFLOW_MANIFEST


def test_raw_output_as_step_input_rejected() -> None:
    # s1 tries to read s0's raw stdout, which is not a declared typed output.
    s0 = step_doc(step_id="s0")
    s1 = step_doc(
        step_id="s1",
        action_id="operator.followup",
        inputs={"prior": {"from_step": "s0", "output": "stdout"}},
    )
    with pytest.raises(ContractError) as excinfo:
        validate_workflow(workflow_doc(steps=[s0, s1]), workflow_registry())
    assert excinfo.value.reason_code is ReasonCode.INVALID_WORKFLOW_MANIFEST


# ================================================ task 2: fresh per-step decision
def test_two_step_workflow_completes_with_fresh_decisions() -> None:
    executor = _Executor()
    workflow = validate_workflow(
        workflow_doc(steps=[step_doc(step_id="s0"), step_doc(step_id="s1")]), workflow_registry()
    )
    result = _run(workflow, _snapshot(), executor)
    assert result.status == WorkflowStatus.COMPLETED.value
    assert result.completed_step_ids == ("s0", "s1")
    # Each step drove its own executor call (fresh decision, no inherited ALLOW).
    assert executor.calls == ["operator.http-probe", "operator.http-probe"]


def test_step_whose_target_left_scope_halts() -> None:
    executor = _Executor()
    s0 = step_doc(step_id="s0")
    s1 = step_doc(step_id="s1", targets={"url": ["https://evil.example/"]})
    workflow = validate_workflow(workflow_doc(steps=[s0, s1]), workflow_registry())
    result = _run(workflow, _snapshot(), executor)
    assert result.status == WorkflowStatus.HALTED.value
    assert result.reason == "out-of-scope-no-match"
    # The out-of-scope step never ran; only s0 executed.
    assert result.completed_step_ids == ("s0",)
    assert executor.calls == ["operator.http-probe"]


def test_step_reads_input_only_from_typed_prior_output() -> None:
    executor = _Executor(script={"operator.http-probe": [_result(exit_code=7)]})
    s0 = step_doc(step_id="s0")
    s1 = step_doc(
        step_id="s1",
        action_id="operator.followup",
        inputs={"prior": {"from_step": "s0", "output": "code"}},
    )
    workflow = validate_workflow(workflow_doc(steps=[s0, s1]), workflow_registry())
    captured: list[list[str]] = []
    real = executor

    def capturing(bound: Any, action: Any, snapshot: Any, decision: Any) -> ExecutionResult:
        if action.id == "operator.followup":
            captured.append([str(token) for token in bound.argv])
        return real(bound, action, snapshot, decision)

    result = run_workflow(
        workflow,
        _snapshot(),
        workflow_registry(),
        platform="linux",
        confirmed_workflow_digest=_confirmed(workflow, _snapshot()),
        step_executor=capturing,
    )
    assert result.status == WorkflowStatus.COMPLETED.value
    # s0's typed exit_code (7) flowed into s1's bound argv as the prior value.
    assert "7" in captured[0]


# =============================================== task 3: digest binding + barriers
def test_security_relevant_workflow_change_denies_stale() -> None:
    snapshot = _snapshot()
    original = validate_workflow(workflow_doc(), workflow_registry())
    confirmed = _confirmed(original, snapshot)
    changed = validate_workflow(workflow_doc(steps=[step_doc(retry_limit=3)]), workflow_registry())
    result = run_workflow(
        changed,
        snapshot,
        workflow_registry(),
        platform="linux",
        confirmed_workflow_digest=confirmed,
        step_executor=_Executor(),
    )
    assert result.status == WorkflowStatus.HALTED.value
    assert result.reason == ReasonCode.DENY_AUTHORIZATION_STALE.value


def test_midrun_authority_drift_halts_fail_closed() -> None:
    executor = _Executor()
    executor.after = {"authority_digest": "engv2:auth-b"}  # drift after step s0
    workflow = validate_workflow(
        workflow_doc(steps=[step_doc(step_id="s0"), step_doc(step_id="s1")]), workflow_registry()
    )
    result = _run(workflow, _snapshot(), executor)
    assert result.status == WorkflowStatus.HALTED.value
    assert result.reason == ReasonCode.DENY_AUTHORIZATION_STALE.value
    assert result.completed_step_ids == ("s0",)


def test_bounded_retry_never_replays_completed_step() -> None:
    executor = _Executor(
        script={
            "operator.http-probe": [_result()],  # s0 completes once
            "operator.followup": [_result(executed=False), _result()],  # s1 fails then succeeds
        }
    )
    s0 = step_doc(step_id="s0")
    s1 = step_doc(
        step_id="s1",
        action_id="operator.followup",
        inputs={"prior": {"from_value": 3}},
        retry_limit=1,
    )
    workflow = validate_workflow(workflow_doc(steps=[s0, s1]), workflow_registry())
    result = _run(workflow, _snapshot(), executor)
    assert result.status == WorkflowStatus.COMPLETED.value
    # s0 ran exactly once; only the failing s1 was retried.
    assert executor.calls.count("operator.http-probe") == 1
    assert executor.calls.count("operator.followup") == 2


def test_retry_exhaustion_halts() -> None:
    executor = _Executor(
        script={"operator.http-probe": [_result(executed=False), _result(executed=False)]}
    )
    workflow = validate_workflow(workflow_doc(steps=[step_doc(retry_limit=1)]), workflow_registry())
    result = _run(workflow, _snapshot(), executor)
    assert result.status == WorkflowStatus.HALTED.value
    assert result.reason == ReasonCode.WORKFLOW_STEP_FAILED.value


def test_cancellation_halts_before_next_step() -> None:
    executor = _Executor()
    workflow = validate_workflow(
        workflow_doc(steps=[step_doc(step_id="s0"), step_doc(step_id="s1")]), workflow_registry()
    )
    state = {"count": 0}

    def cancel() -> bool:
        # Allow s0, cancel before s1.
        state["count"] += 1
        return state["count"] > 1

    result = _run(workflow, _snapshot(), executor, cancel=cancel)
    assert result.status == WorkflowStatus.CANCELLED.value
    assert result.completed_step_ids == ("s0",)


def test_incomplete_resource_cleanup_halts() -> None:
    executor = _Executor(
        script={"operator.http-probe": [_result(resource=ResourceCleanupState.FAILED.value)]}
    )
    workflow = validate_workflow(workflow_doc(steps=[step_doc(retry_limit=0)]), workflow_registry())
    result = _run(workflow, _snapshot(), executor)
    assert result.status == WorkflowStatus.HALTED.value
    assert result.reason == ReasonCode.CLEANUP_RESOURCE_INCOMPLETE.value


def test_incomplete_target_cleanup_halts() -> None:
    executor = _Executor(
        script={
            "operator.http-probe": [_result(target=TargetCleanupState.UNVERIFIED_SELF_REPORT.value)]
        }
    )
    workflow = validate_workflow(workflow_doc(steps=[step_doc(retry_limit=0)]), workflow_registry())
    result = _run(workflow, _snapshot(), executor)
    assert result.status == WorkflowStatus.HALTED.value
    assert result.reason == ReasonCode.CLEANUP_TARGET_INCOMPLETE.value


# ================================================= task 4: gating and pre-P6 guard
def test_progression_denied_without_capability_true() -> None:
    program = program_doc()  # no autonomous_progression_allowed field
    snapshot = _snapshot(program=program)
    workflow = validate_workflow(workflow_doc(), workflow_registry())
    result = _run(workflow, snapshot, _Executor())
    assert result.status == WorkflowStatus.HALTED.value
    assert result.reason == ReasonCode.DENY_CAPABILITY_NOT_ALLOWED.value


def test_progression_denied_when_capability_false() -> None:
    snapshot = _snapshot(program=_program(autonomous_progression_allowed=False))
    workflow = validate_workflow(workflow_doc(), workflow_registry())
    result = _run(workflow, snapshot, _Executor())
    assert result.reason == ReasonCode.DENY_CAPABILITY_NOT_ALLOWED.value


def test_workflow_manifest_rejected_until_capability_loaded() -> None:
    with pytest.raises(ContractError) as excinfo:
        validate_workflow(workflow_doc(), workflow_registry(), capability_available=False)
    assert excinfo.value.reason_code is ReasonCode.INVALID_WORKFLOW_MANIFEST


def test_autonomous_field_rejected_until_capability_loaded() -> None:
    program = _program()
    with pytest.raises(ContractError) as excinfo:
        guard_autonomous_progression(program, capability_available=False)
    assert excinfo.value.reason_code is ReasonCode.INVALID_AUTONOMOUS_PROGRESSION
    # Once the capability is available the field is accepted at load time.
    guard_autonomous_progression(program, capability_available=True)


def test_engagement_with_autonomous_progression_loads(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    program = copy.deepcopy(program_doc())
    program["testing_rules"]["autonomous_progression_allowed"] = True
    directory = write_engagement(tmp_path / "eng", program=program)
    snapshot = load_engagement(directory)
    assert snapshot.program["testing_rules"]["autonomous_progression_allowed"] is True
