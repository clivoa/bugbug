"""Engagement workflow state machine.

The workflow orchestrator manages the lifecycle of a bug bounty engagement:
  import → authorize → scope-lock → recon → surface → hypothesis
  → hunt → validate → evidence → report → close

Each phase gates the next. The system does not automatically progress from
reconnaissance to intrusive validation. Every transition is recorded.
"""

from hackbot.workflows.state import (
    EngagementState,
    WorkflowPhase,
    WorkflowStateMachine,
    load_state,
)

__all__ = [
    "EngagementState",
    "WorkflowPhase",
    "WorkflowStateMachine",
    "load_state",
]
