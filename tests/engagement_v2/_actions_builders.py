"""Deterministic synthetic actions.yaml and request documents for P2 tests."""

from __future__ import annotations

import copy
from typing import Any


def action_doc() -> dict[str, Any]:
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


def manifest_doc(action: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "actions": [copy.deepcopy(action if action is not None else action_doc())],
    }


def request_doc(**overrides: Any) -> dict[str, Any]:
    request = {
        "schema_version": 2,
        "action_id": "operator.http-probe",
        "parameters": {
            "rate": 5,
            "concurrency": 2,
            "url": "https://app.corp.example/admin",
        },
        "hypothesis_id": "h1",
        "rationale": "probe the admin endpoint",
        "expected_impact": "none demonstrated",
        "stop_condition": "on any 5xx",
        "cleanup_plan": "none required",
    }
    request.update(overrides)
    return request
