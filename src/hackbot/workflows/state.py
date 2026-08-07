"""Workflow state machine — engagement lifecycle management.

Every engagement follows a gated workflow. The system tracks which phase is
active and enforces that transitions happen in order. It does not automatically
progress from reconnaissance to intrusive validation — the operator must
explicitly advance through each gate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path


class WorkflowPhase(str, Enum):
    """Ordered phases of a bug bounty engagement."""

    IMPORTED = "imported"  # Program loaded, not yet authorized
    AUTHORIZED = "authorized"  # Authorization confirmed
    SCOPE_LOCKED = "scope_locked"  # Scope frozen, no expansion
    RECON_PASSIVE = "recon_passive"  # Passive recon complete
    RECON_ACTIVE = "recon_active"  # Low-impact active recon complete
    SURFACE_MAPPED = "surface_mapped"  # Attack surface classified
    HYPOTHESES_GENERATED = "hypotheses_generated"  # Hypotheses created
    HUNTING = "hunting"  # Active vulnerability testing
    VALIDATING = "validating"  # Finding validation in progress
    EVIDENCE_COLLECTED = "evidence_collected"  # Evidence gathered
    REPORTING = "reporting"  # Report generation
    CLOSED = "closed"  # Engagement complete, artifacts cleaned

    def next_phase(self) -> WorkflowPhase | None:
        """Return the next phase in the workflow, or None if at the end."""
        phases = list(WorkflowPhase)
        idx = phases.index(self)
        return phases[idx + 1] if idx + 1 < len(phases) else None

    def is_before(self, other: WorkflowPhase) -> bool:
        """Check if this phase comes before another."""
        phases = list(WorkflowPhase)
        return phases.index(self) < phases.index(other)

    def requires_approval_to_advance(self) -> bool:
        """Phases that require explicit operator approval to advance beyond."""
        return self in {
            WorkflowPhase.RECON_ACTIVE,  # Passive → active requires check
            WorkflowPhase.HUNTING,  # Hypotheses → testing requires approval
            WorkflowPhase.VALIDATING,  # Requires evidence review
        }


@dataclass
class EngagementState:
    """Immutable snapshot of an engagement's current workflow state."""

    engagement_id: str
    engagement_path: str
    current_phase: WorkflowPhase = WorkflowPhase.IMPORTED
    phase_history: list[dict[str, str]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    program_name: str = ""
    platform: str = ""
    profile: str = "web2"

    def transition(self, to_phase: WorkflowPhase, *, reason: str = "") -> EngagementState:
        """Create a new state with the phase advanced.

        The transition is recorded in phase_history with timestamp and reason.
        The caller is responsible for enforcing transition validity.
        """
        now = datetime.now(UTC).isoformat()
        history = list(self.phase_history)
        history.append(
            {
                "from": self.current_phase.value,
                "to": to_phase.value,
                "at": now,
                "reason": reason or f"Advanced from {self.current_phase.value} to {to_phase.value}",
            }
        )
        return EngagementState(
            engagement_id=self.engagement_id,
            engagement_path=self.engagement_path,
            current_phase=to_phase,
            phase_history=history,
            created_at=self.created_at,
            updated_at=now,
            program_name=self.program_name,
            platform=self.platform,
            profile=self.profile,
        )

    def is_phase_complete(self, phase: WorkflowPhase) -> bool:
        """Check if a phase has been completed (current or past)."""
        if self.current_phase == phase:
            return True
        phases = list(WorkflowPhase)
        return phases.index(self.current_phase) > phases.index(phase)


class WorkflowStateMachine:
    """Manages the lifecycle of a single engagement.

    The state machine enforces phase ordering but does not execute any
    security actions itself. It tracks where we are and records transitions.
    """

    def __init__(self, state: EngagementState) -> None:
        self._state = state

    @property
    def current_phase(self) -> WorkflowPhase:
        return self._state.current_phase

    @property
    def state(self) -> EngagementState:
        return self._state

    def can_advance_to(self, phase: WorkflowPhase) -> bool:
        """Check if a transition to the given phase is valid."""
        next_phase = self._state.current_phase.next_phase()
        if next_phase is None:
            return False
        # Can only advance one phase at a time
        return phase == next_phase

    def advance(self, reason: str = "") -> EngagementState:
        """Advance to the next phase. Raises ValueError if at the end."""
        next_phase = self._state.current_phase.next_phase()
        if next_phase is None:
            raise ValueError(
                f"Engagement is already at final phase: {self._state.current_phase.value}"
            )
        self._state = self._state.transition(next_phase, reason=reason)
        return self._state

    def jump_to(self, phase: WorkflowPhase, *, reason: str = "") -> EngagementState:
        """Jump directly to a past phase (backfill). Valid only for completed phases."""
        phases = list(WorkflowPhase)
        target_idx = phases.index(phase)
        current_idx = phases.index(self._state.current_phase)
        if target_idx > current_idx:
            raise ValueError(
                f"Cannot jump forward from {self._state.current_phase.value} "
                f"to {phase.value}. Use advance() for forward transitions."
            )
        self._state = self._state.transition(phase, reason=reason)
        return self._state

    def save(self) -> None:
        """Persist the current state to the engagement directory."""
        path = Path(self._state.engagement_path) / "engagement.yaml"
        data = {
            "engagement_id": self._state.engagement_id,
            "current_phase": self._state.current_phase.value,
            "phase_history": self._state.phase_history,
            "created_at": self._state.created_at,
            "updated_at": self._state.updated_at,
            "program_name": self._state.program_name,
            "platform": self._state.platform,
            "profile": self._state.profile,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_state(engagement_path: str) -> EngagementState | None:
    """Load the workflow state from an engagement directory.

    Returns None if no state file exists (new engagement).
    """
    path = Path(engagement_path) / "engagement.yaml"
    if not path.is_file():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        phase = WorkflowPhase(data.get("current_phase", "imported"))
        history = data.get("phase_history", [])
        return EngagementState(
            engagement_id=data.get("engagement_id", ""),
            engagement_path=str(Path(engagement_path).resolve()),
            current_phase=phase,
            phase_history=([dict(h) for h in history] if isinstance(history, list) else []),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            program_name=data.get("program_name", ""),
            platform=data.get("platform", ""),
            profile=data.get("profile", "web2"),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        return None
