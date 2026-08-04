"""Immutable registry of code-owned action definitions."""

from __future__ import annotations

from collections.abc import Iterable
from types import MappingProxyType

from hackbot.risk.models import ActionDefinition


class RegistryError(Exception):
    """Raised when a registry cannot safely resolve an action definition."""


class ActionRegistry:
    def __init__(self, definitions: Iterable[ActionDefinition]) -> None:
        items: dict[str, ActionDefinition] = {}
        for definition in definitions:
            if not isinstance(definition, ActionDefinition):
                raise RegistryError("invalid action definition")
            try:
                definition.validate()
            except ValueError as exc:
                raise RegistryError("invalid action definition") from exc
            if definition.action_id in items:
                raise RegistryError(f"duplicate action id: {definition.action_id}")
            items[definition.action_id] = definition
        self._items = MappingProxyType(items)

    def require(self, action_id: str) -> ActionDefinition:
        try:
            return self._items[action_id]
        except KeyError as exc:
            raise RegistryError(f"unknown action id: {action_id}") from exc

    def definitions(self) -> tuple[ActionDefinition, ...]:
        """Return the registered definitions (for composing a wider registry)."""
        return tuple(self._items.values())
