"""Immutable, code-owned real action definitions.

CLI input can never register or mutate an action. The first member,
``net.http-get``, is a low-impact passive fetch backed by ``curl`` (resolved
from a small absolute-path allowlist); ``network_access=True`` forces a scope
check, so it only runs against in-scope targets.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from hackbot.risk.models import ActionDefinition, RiskLevel
from hackbot.risk.registry import ActionRegistry

_CURL_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/curl",
    "/opt/homebrew/bin/curl",
    "/usr/local/bin/curl",
)


def resolve_executable(candidates: Sequence[str]) -> str | None:
    for candidate in candidates:
        if os.path.isabs(candidate) and os.path.isfile(candidate):
            return candidate
    return None


def curl_path() -> str | None:
    return resolve_executable(_CURL_CANDIDATES)


def _build_actions() -> ActionRegistry:
    definitions: list[ActionDefinition] = []
    curl = curl_path()
    if curl is not None:
        definitions.append(
            ActionDefinition(
                "net.http-get",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=curl,
                argv_template=(curl, "-sS", "--max-time", "10", "{target}"),
            )
        )
        definitions.append(
            ActionDefinition(
                "net.http-post",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                state_changing=True,
                executable=curl,
                argv_template=(curl, "-sS", "-X", "POST", "--max-time", "10", "{target}"),
            )
        )
        definitions.append(
            ActionDefinition(
                "net.http-head",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=curl,
                argv_template=(curl, "-sS", "-I", "--max-time", "10", "{target}"),
            )
        )
        definitions.append(
            ActionDefinition(
                "net.http-options",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=curl,
                argv_template=(curl, "-sS", "-i", "-X", "OPTIONS", "--max-time", "10", "{target}"),
            )
        )
    return ActionRegistry(definitions)


REAL_ACTIONS = _build_actions()

__all__ = ["REAL_ACTIONS", "curl_path", "resolve_executable"]
