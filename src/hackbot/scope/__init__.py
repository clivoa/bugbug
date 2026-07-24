"""Code-enforced scope checking (default-deny, deny-wins, immutable at runtime)."""

from hackbot.scope.engine import (
    Scope,
    ScopeDecision,
    ScopeKind,
    classify_target,
)

__all__ = ["Scope", "ScopeDecision", "ScopeKind", "classify_target"]
