"""Deterministic synthetic workflow manifests and actions for P6 tests."""

from __future__ import annotations

import copy
from typing import Any

from hackbot.engagement_v2.constants import WORKFLOW_SCHEMA_VERSION
from hackbot.engagement_v2.manifest import validate_manifest


def _probe_action() -> dict[str, Any]:
    return {
        "id": "operator.http-probe",
        "title": "HTTP probe",
        "risk": "L1",
        "platforms": ["linux"],
        "architectures": ["x86_64"],
        "executables": {"linux": "/usr/bin/curl"},
        "required_privileges": [],
        "parameters": {
            "rate": {"type": "integer", "required": True, "minimum": 1, "maximum": 100},
            "concurrency": {"type": "integer", "required": True, "minimum": 1, "maximum": 16},
        },
        "secrets": {},
        "targets": ["url"],
        "characteristics": {},
        "rate_control": {
            "kind": "argv-placeholder",
            "rate_parameter": "rate",
            "concurrency_parameter": "concurrency",
        },
        "capabilities": ["automated-scanning"],
        "vulnerability_types": [],
        "impacts": [],
        "evidence_policy": {"mode": "metadata-only"},
        "argv": ["--rate", "{value:rate}", "--target", "{target:url}"],
    }


def _followup_action() -> dict[str, Any]:
    action = _probe_action()
    action["id"] = "operator.followup"
    action["title"] = "Follow-up probe"
    action["parameters"]["prior"] = {
        "type": "integer",
        "required": True,
        "minimum": 0,
        "maximum": 1000,
    }
    action["argv"] = [
        "--rate",
        "{value:rate}",
        "--prior",
        "{value:prior}",
        "--target",
        "{target:url}",
    ]
    return action


def workflow_registry() -> Any:
    return validate_manifest(
        {"schema_version": 1, "actions": [_probe_action(), _followup_action()]}
    )


def step_doc(
    step_id: str = "s0", action_id: str = "operator.http-probe", **overrides: Any
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": step_id,
        "action_id": action_id,
        "parameters": {"rate": 5, "concurrency": 2},
        "targets": {"url": ["https://app.corp.example/admin"]},
        "inputs": {},
        "outputs": {"code": {"type": "scalar", "source": "exit_code"}},
        "depends_on": [],
        "retry_limit": 1,
    }
    base.update(overrides)
    return base


def workflow_doc(
    steps: list[dict[str, Any]] | None = None,
    workflow_id: str = "operator.recon-flow",
    **overrides: Any,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": WORKFLOW_SCHEMA_VERSION,
        "workflow_id": workflow_id,
        "steps": copy.deepcopy(steps) if steps is not None else [step_doc()],
    }
    document.update(overrides)
    return document
