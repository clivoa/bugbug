"""P6 workflow schema and fail-closed autonomous state machine.

A workflow is a **code-owned typed graph** of steps over existing gated actions.
It adds a safety layer above the unchanged P2 gate and P3/P4 executor: it never
introduces an action, executor, or capability, and it never lets raw tool output
steer execution.

Two contracts live here:

* ``validate_workflow`` decodes an operator workflow manifest into an immutable
  ``WorkflowDefinition``. A step's inputs come only from a typed prior-step output
  or a manifest literal (confirmed authority); a step's typed outputs are drawn
  only from a code-owned structured-result whitelist. Raw stdout/stderr can never
  be an input, an output, an argv token, a target, or a capability. Cycles,
  forward references, unknown actions, and untyped in/outputs fail closed.

* ``run_workflow`` walks the DAG and, for **every** step, creates a *fresh* P2
  decision against the current confirmed snapshot (re-binding argv, re-validating
  every target against scope, re-checking capabilities/rate), executes via P3/P4
  only on ``ALLOW``, and records typed outputs. No step inherits a prior ALLOW.
  The run binds to the confirmed workflow projection, so a security-relevant
  workflow (or authority) change halts with ``DENY_AUTHORIZATION_STALE``. Bounded
  per-step retries never replay a completed step; cancellation, policy/scope
  drift, and any incomplete resource/target cleanup halt fail-closed.

Autonomous progression is gated exactly like any other sensitive capability and
is rejected until this module (the capability) is present.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Protocol

from hackbot.engagement_v2.binder import BoundCommand
from hackbot.engagement_v2.canonical import digest_value
from hackbot.engagement_v2.constants import (
    ACTION_REQUEST_SCHEMA_VERSION,
    BINDING_NAME_PATTERN,
    IDENTIFIER_PATTERN,
    MAX_IDENTIFIER_BYTES,
    MAX_STEP_INPUTS,
    MAX_STEP_OUTPUTS,
    MAX_STEP_RETRIES,
    MAX_STEP_TARGET_VALUES,
    MAX_WORKFLOW_STEPS,
    MIN_STEP_RETRIES,
    OPERATOR_ACTION_ID_PREFIX,
    WORKFLOW_PROJECTION_FORMAT,
    WORKFLOW_SCHEMA_VERSION,
    ResourceCleanupState,
    TargetCleanupState,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.executor import ExecutionResult
from hackbot.engagement_v2.manifest import ActionDefinition
from hackbot.engagement_v2.policy import DecisionKind, PolicyDecision, decide

# ---------------------------------------------------------------- capability ---

# The autonomous-progression capability field consumed by the P2 gate.
AUTONOMOUS_PROGRESSION_FIELD = "autonomous_progression_allowed"


def workflow_capability_available() -> bool:
    """Return whether the P6 workflow capability is delivered.

    The presence of this module *is* the capability: autonomous progression and
    workflow manifests are accepted only once it is importable. A build that has
    not shipped P6 has no such module, so the loader's guard rejects both.
    """

    return True


# ------------------------------------------------------------ typed schema -----


class WorkflowValueType(str, Enum):
    """Closed set of typed workflow input/output value kinds."""

    SCALAR = "scalar"
    BOOLEAN = "boolean"


# Code-owned structured-result whitelist: the only sources a typed output may be
# drawn from. Each maps to a pure projection of an ``ExecutionResult`` structured
# field. Raw stdout/stderr and any other target-controlled bytes are absent by
# construction, so they can never become a typed output (and thus never a later
# step's input).
_OUTPUT_SOURCES: Mapping[str, tuple[WorkflowValueType, Callable[[ExecutionResult], object]]] = (
    MappingProxyType(
        {
            "exit_code": (WorkflowValueType.SCALAR, lambda result: result.exit_code),
            "executed": (WorkflowValueType.BOOLEAN, lambda result: result.executed),
            "timed_out": (WorkflowValueType.BOOLEAN, lambda result: result.timed_out),
            "resource_cleanup_status": (
                WorkflowValueType.SCALAR,
                lambda result: result.resource_cleanup_status,
            ),
            "target_cleanup_status": (
                WorkflowValueType.SCALAR,
                lambda result: result.target_cleanup_status,
            ),
        }
    )
)

# Resource/target cleanup states that satisfy the fail-closed barrier.
_RESOURCE_CLEANUP_OK = frozenset(
    {ResourceCleanupState.NOT_REQUIRED.value, ResourceCleanupState.COMPLETE.value}
)
_TARGET_CLEANUP_OK = frozenset(
    {TargetCleanupState.NOT_REQUIRED.value, TargetCleanupState.COMPLETE.value}
)


@dataclass(frozen=True)
class OutputDef:
    name: str
    type: str
    source: str


@dataclass(frozen=True)
class InputBinding:
    """A typed input sourced from a prior step's output or a manifest literal."""

    parameter: str
    from_step: str | None
    from_output: str | None
    literal: object | None
    type: str


@dataclass(frozen=True)
class WorkflowStep:
    id: str
    action_id: str
    parameters: Mapping[str, object]
    targets: Mapping[str, tuple[str, ...]]
    inputs: tuple[InputBinding, ...]
    outputs: Mapping[str, OutputDef]
    depends_on: frozenset[str]
    retry_limit: int


@dataclass(frozen=True)
class WorkflowDefinition:
    workflow_id: str
    steps: tuple[WorkflowStep, ...]
    projection: Mapping[str, object]


def _fail() -> ContractError:
    return ContractError(ReasonCode.INVALID_WORKFLOW_MANIFEST)


def _require(condition: bool) -> None:
    if not condition:
        raise _fail()


def _str(value: object) -> str:
    _require(isinstance(value, str))
    assert isinstance(value, str)
    return value


def _mapping(value: object) -> Mapping[str, object]:
    _require(isinstance(value, Mapping))
    assert isinstance(value, Mapping)
    return value


def _list(value: object) -> Sequence[object]:
    _require(isinstance(value, Sequence) and not isinstance(value, str | bytes))
    assert isinstance(value, Sequence)
    return value


_STEP_FIELDS = frozenset(
    {"id", "action_id", "parameters", "targets", "inputs", "outputs", "depends_on", "retry_limit"}
)
_WORKFLOW_FIELDS = frozenset({"schema_version", "workflow_id", "steps"})
_INPUT_FIELDS = frozenset({"from_step", "output", "from_value"})
_OUTPUT_FIELDS = frozenset({"type", "source"})
_LITERAL_TYPE = MappingProxyType(
    {int: WorkflowValueType.SCALAR.value, bool: WorkflowValueType.BOOLEAN.value, str: "string"}
)


def _validate_outputs(raw: object) -> dict[str, OutputDef]:
    outputs = _mapping(raw)
    _require(len(outputs) <= MAX_STEP_OUTPUTS)
    resolved: dict[str, OutputDef] = {}
    for name, definition in outputs.items():
        _require(bool(BINDING_NAME_PATTERN.fullmatch(name)))
        body = _mapping(definition)
        for key in body:
            _require(key in _OUTPUT_FIELDS)
        source = _str(body.get("source"))
        # The only legal sources are code-owned structured-result fields; raw
        # stdout/stderr (or any other name) is rejected here.
        _require(source in _OUTPUT_SOURCES)
        declared_type = _str(body.get("type"))
        source_type, _ = _OUTPUT_SOURCES[source]
        _require(declared_type == source_type.value)
        resolved[name] = OutputDef(name=name, type=declared_type, source=source)
    return resolved


def _validate_inputs(
    raw: object,
    *,
    prior_outputs: Mapping[str, Mapping[str, OutputDef]],
) -> tuple[tuple[InputBinding, ...], frozenset[str]]:
    inputs = _mapping(raw)
    _require(len(inputs) <= MAX_STEP_INPUTS)
    resolved: list[InputBinding] = []
    step_dependencies: set[str] = set()
    for parameter, binding in inputs.items():
        _require(bool(BINDING_NAME_PATTERN.fullmatch(parameter)))
        body = _mapping(binding)
        for key in body:
            _require(key in _INPUT_FIELDS)
        if "from_value" in body:
            # A manifest literal is confirmed authority (it is part of the
            # workflow projection and thus the authority digest).
            _require("from_step" not in body and "output" not in body)
            literal = body["from_value"]
            literal_type = _LITERAL_TYPE.get(type(literal))
            _require(literal_type is not None)
            resolved.append(
                InputBinding(
                    parameter=parameter,
                    from_step=None,
                    from_output=None,
                    literal=literal,
                    type=str(literal_type),
                )
            )
            continue
        # Otherwise the input must come from a prior step's declared typed output.
        source_step = _str(body.get("from_step"))
        output_name = _str(body.get("output"))
        _require(source_step in prior_outputs)
        declared = prior_outputs[source_step]
        _require(output_name in declared)
        step_dependencies.add(source_step)
        resolved.append(
            InputBinding(
                parameter=parameter,
                from_step=source_step,
                from_output=output_name,
                literal=None,
                type=declared[output_name].type,
            )
        )
    return tuple(resolved), frozenset(step_dependencies)


def _validate_targets(raw: object, action: ActionDefinition) -> dict[str, tuple[str, ...]]:
    targets = _mapping(raw)
    # Every action target binding must be supplied, and only those bindings.
    _require(set(targets) == set(action.target_bindings))
    resolved: dict[str, tuple[str, ...]] = {}
    for binding, values in targets.items():
        items = _list(values)
        _require(1 <= len(items) <= MAX_STEP_TARGET_VALUES)
        literals = tuple(_str(item) for item in items)
        resolved[binding] = literals
    return resolved


def _validate_parameters(raw: object, action: ActionDefinition) -> dict[str, object]:
    parameters = _mapping(raw)
    resolved: dict[str, object] = {}
    for name, value in parameters.items():
        _require(bool(BINDING_NAME_PATTERN.fullmatch(name)))
        # A literal bound parameter must name a declared non-target parameter.
        _require(name in action.parameters)
        _require(type(value) in _LITERAL_TYPE)
        resolved[name] = value
    return resolved


def _validate_step(
    raw: object,
    registry: Mapping[str, ActionDefinition],
    seen_ids: dict[str, WorkflowStep],
    prior_outputs: dict[str, Mapping[str, OutputDef]],
) -> WorkflowStep:
    step = _mapping(raw)
    for key in step:
        _require(key in _STEP_FIELDS)

    step_id = _str(step.get("id"))
    _require(bool(BINDING_NAME_PATTERN.fullmatch(step_id)))
    _require(step_id not in seen_ids)

    action_id = _str(step.get("action_id"))
    _require(action_id in registry)
    action = registry[action_id]

    parameters = _validate_parameters(step.get("parameters", {}), action)
    targets = _validate_targets(step.get("targets", {}), action)
    outputs = _validate_outputs(step.get("outputs", {}))
    inputs, input_dependencies = _validate_inputs(
        step.get("inputs", {}), prior_outputs=prior_outputs
    )

    # A literal parameter and a sourced input can never bind the same name.
    bound_names = {binding.parameter for binding in inputs}
    _require(not (set(parameters) & bound_names))
    # Every required action parameter must be bound by a literal or a typed input,
    # so a step can never reach the binder with a missing required parameter.
    required = {name for name, param in action.parameters.items() if param.required}
    _require(required <= (set(parameters) | bound_names))

    depends_on_raw = _list(step.get("depends_on", []))
    explicit_dependencies = frozenset(_str(item) for item in depends_on_raw)
    # Every explicit dependency and every implicit input dependency must be an
    # already-seen (earlier) step: forward references and cycles fail closed.
    for dependency in explicit_dependencies | input_dependencies:
        _require(dependency in seen_ids)
    depends_on = explicit_dependencies | input_dependencies

    retry_limit = step.get("retry_limit", MIN_STEP_RETRIES)
    _require(type(retry_limit) is int)
    assert isinstance(retry_limit, int)
    _require(MIN_STEP_RETRIES <= retry_limit <= MAX_STEP_RETRIES)

    return WorkflowStep(
        id=step_id,
        action_id=action_id,
        parameters=MappingProxyType(parameters),
        targets=MappingProxyType(targets),
        inputs=inputs,
        outputs=MappingProxyType(outputs),
        depends_on=depends_on,
        retry_limit=retry_limit,
    )


def _step_projection(step: WorkflowStep) -> dict[str, object]:
    return {
        "id": step.id,
        "action_id": step.action_id,
        "parameters": dict(step.parameters),
        "targets": {name: sorted(values) for name, values in step.targets.items()},
        "inputs": {
            binding.parameter: (
                {"from_value": binding.literal}
                if binding.from_step is None
                else {"from_step": binding.from_step, "output": binding.from_output}
            )
            for binding in step.inputs
        },
        "outputs": {
            name: {"type": output.type, "source": output.source}
            for name, output in step.outputs.items()
        },
        "depends_on": sorted(step.depends_on),
        "retry_limit": step.retry_limit,
    }


def validate_workflow(
    document: Mapping[str, object],
    registry: Mapping[str, ActionDefinition],
    *,
    capability_available: bool = True,
) -> WorkflowDefinition:
    """Validate a decoded workflow manifest into an immutable typed DAG.

    Until the workflow capability is available a workflow manifest is rejected
    fail-closed (the pre-P6 invariant).
    """

    guard_workflow_manifest(capability_available=capability_available)

    version = document.get("schema_version")
    if type(version) is not int or version != WORKFLOW_SCHEMA_VERSION:
        raise ContractError(ReasonCode.INVALID_SCHEMA_VERSION)
    for key in document:
        _require(key in _WORKFLOW_FIELDS)

    workflow_id = _str(document.get("workflow_id"))
    _require(workflow_id.startswith(OPERATOR_ACTION_ID_PREFIX))
    _require(bool(IDENTIFIER_PATTERN.fullmatch(workflow_id)))
    _require(len(workflow_id.encode("utf-8")) <= MAX_IDENTIFIER_BYTES)

    raw_steps = _list(document.get("steps"))
    _require(1 <= len(raw_steps) <= MAX_WORKFLOW_STEPS)

    seen: dict[str, WorkflowStep] = {}
    prior_outputs: dict[str, Mapping[str, OutputDef]] = {}
    for raw in raw_steps:
        step = _validate_step(raw, registry, seen, prior_outputs)
        seen[step.id] = step
        prior_outputs[step.id] = step.outputs

    steps = tuple(seen.values())
    # A plain (canonical) dict: the digest layer validates exact dict/list types.
    projection: dict[str, object] = {
        "workflow_id": workflow_id,
        "steps": [_step_projection(step) for step in steps],
    }
    return WorkflowDefinition(workflow_id=workflow_id, steps=steps, projection=projection)


# --------------------------------------------------------- authority binding ---


def workflow_authority_digest(authority_digest: str, projection: Mapping[str, object]) -> str:
    """Bind a workflow projection into the confirmed authority digest.

    The result changes whenever the confirmed authority changes *or* the workflow
    changes in any security-relevant way, so drift denies ``DENY_AUTHORIZATION_STALE``
    under the same mechanism P1 uses for scope/policy/runner.
    """

    return digest_value(
        {
            "contract": WORKFLOW_PROJECTION_FORMAT,
            "authority_digest": authority_digest,
            "workflow": projection,
        }
    )


# --------------------------------------------------------------- guard/gate ----


def guard_workflow_manifest(*, capability_available: bool) -> None:
    """Reject a workflow manifest unless the workflow capability is present."""

    if not capability_available:
        raise ContractError(ReasonCode.INVALID_WORKFLOW_MANIFEST)


def guard_autonomous_progression(
    program: Mapping[str, object], *, capability_available: bool
) -> None:
    """Reject ``autonomous_progression_allowed: true`` until the capability ships.

    Once the capability is present the field is accepted at load time; the P2 gate
    (via ``run_workflow``) still requires it to be exactly ``true`` before any
    autonomous progression.
    """

    if capability_available:
        return
    testing_rules = program.get("testing_rules")
    if (
        isinstance(testing_rules, Mapping)
        and testing_rules.get(AUTONOMOUS_PROGRESSION_FIELD) is True
    ):
        raise ContractError(ReasonCode.INVALID_AUTONOMOUS_PROGRESSION)


def _autonomous_allowed(snapshot: object) -> bool:
    program = getattr(snapshot, "program", None)
    if not isinstance(program, Mapping):
        return False
    testing_rules = program.get("testing_rules")
    if not isinstance(testing_rules, Mapping):
        return False
    return testing_rules.get(AUTONOMOUS_PROGRESSION_FIELD) is True


# ------------------------------------------------------------ state machine ----


class StepExecutor(Protocol):
    """P3/P4 executor seam: run a bound command for one gated step."""

    def __call__(
        self,
        bound: BoundCommand,
        action: ActionDefinition,
        snapshot: object,
        decision: PolicyDecision,
    ) -> ExecutionResult: ...


class WorkflowStatus(str, Enum):
    COMPLETED = "completed"
    HALTED = "halted"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class StepRecord:
    step_id: str
    status: str  # "completed" | "denied" | "failed"
    reason: str
    attempts: int


@dataclass(frozen=True)
class WorkflowResult:
    status: str
    reason: str
    completed_step_ids: tuple[str, ...]
    records: tuple[StepRecord, ...]


def _cleanup_barrier(result: ExecutionResult) -> str | None:
    if result.resource_cleanup_status not in _RESOURCE_CLEANUP_OK:
        return ReasonCode.CLEANUP_RESOURCE_INCOMPLETE.value
    if result.target_cleanup_status not in _TARGET_CLEANUP_OK:
        return ReasonCode.CLEANUP_TARGET_INCOMPLETE.value
    return None


def _build_request(
    step: WorkflowStep, store: Mapping[str, Mapping[str, object]]
) -> dict[str, object]:
    parameters: dict[str, object] = dict(step.parameters)
    for binding_name, values in step.targets.items():
        parameters[binding_name] = list(values)
    for binding in step.inputs:
        if binding.from_step is None or binding.from_output is None:
            parameters[binding.parameter] = binding.literal
        else:
            # Only typed prior-step outputs are read; the store never holds raw
            # stdout/stderr, so this can never surface target-controlled bytes.
            parameters[binding.parameter] = store[binding.from_step][binding.from_output]
    return {
        "schema_version": ACTION_REQUEST_SCHEMA_VERSION,
        "action_id": step.action_id,
        "parameters": parameters,
    }


def _extract_outputs(step: WorkflowStep, result: ExecutionResult) -> dict[str, object]:
    outputs: dict[str, object] = {}
    for name, definition in step.outputs.items():
        _, getter = _OUTPUT_SOURCES[definition.source]
        outputs[name] = getter(result)
    return outputs


def run_workflow(
    workflow: WorkflowDefinition,
    snapshot: object,
    registry: Mapping[str, ActionDefinition],
    *,
    platform: str,
    confirmed_workflow_digest: str,
    step_executor: StepExecutor,
    cancel: Callable[[], bool] | None = None,
) -> WorkflowResult:
    """Run a workflow with a fresh per-step decision and fail-closed barriers."""

    store: dict[str, Mapping[str, object]] = {}
    completed: list[str] = []
    records: list[StepRecord] = []

    def halt(
        step_id: str, status: str, reason: str, attempts: int, run_status: str
    ) -> WorkflowResult:
        records.append(StepRecord(step_id, status, reason, attempts))
        return WorkflowResult(run_status, reason, tuple(completed), tuple(records))

    for step in workflow.steps:
        # Cancellation barrier: halt before starting a new step.
        if cancel is not None and cancel():
            return halt(step.id, "denied", "workflow-cancelled", 0, WorkflowStatus.CANCELLED.value)

        # Drift barrier: the workflow is part of the confirmed authority digest,
        # so any security-relevant workflow or authority change halts fail-closed.
        current_digest = workflow_authority_digest(
            str(getattr(snapshot, "authority_digest", "")), workflow.projection
        )
        if current_digest != confirmed_workflow_digest:
            return halt(
                step.id,
                "denied",
                ReasonCode.DENY_AUTHORIZATION_STALE.value,
                0,
                WorkflowStatus.HALTED.value,
            )

        # Autonomous-progression gate, re-checked fresh for every step.
        if not _autonomous_allowed(snapshot):
            return halt(
                step.id,
                "denied",
                ReasonCode.DENY_CAPABILITY_NOT_ALLOWED.value,
                0,
                WorkflowStatus.HALTED.value,
            )

        action = registry[step.action_id]
        request = _build_request(step, store)

        attempts = 0
        while True:
            # Fresh P2 decision against the current snapshot: re-binds argv,
            # re-validates every target against scope, re-checks capabilities/rate.
            decision = decide(request, snapshot, registry, platform=platform)
            if decision.kind is DecisionKind.DENY:
                return halt(
                    step.id, "denied", decision.reason, attempts, WorkflowStatus.HALTED.value
                )
            assert decision.bound is not None
            result = step_executor(decision.bound, action, snapshot, decision)
            cleanup_reason = _cleanup_barrier(result)
            if result.executed and cleanup_reason is None:
                break  # step completed; never replayed on any later retry
            attempts += 1
            if attempts > step.retry_limit:
                reason = cleanup_reason or ReasonCode.WORKFLOW_STEP_FAILED.value
                return halt(step.id, "failed", reason, attempts, WorkflowStatus.HALTED.value)

        store[step.id] = _extract_outputs(step, result)
        completed.append(step.id)
        records.append(StepRecord(step.id, "completed", "ALLOW", attempts))

    return WorkflowResult(
        WorkflowStatus.COMPLETED.value, "completed", tuple(completed), tuple(records)
    )
