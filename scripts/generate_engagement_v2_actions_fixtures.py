#!/usr/bin/env python3
"""Generate the deterministic engagement-v2 actions/request fixture corpus.

Synthetic only: example executables, parameters, and an example in-scope target;
no real target or credential material.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Final

_PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
_DEFAULT_ROOT: Final = _PROJECT_ROOT / "tests" / "fixtures" / "engagement_v2_actions"

_MANIFEST: Final = {
    "schema_version": 1,
    "actions": [
        {
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
    ],
}
_REQUEST: Final = {
    "schema_version": 2,
    "action_id": "operator.http-probe",
    "parameters": {"rate": 10, "concurrency": 2, "url": "https://app.corp.example/admin"},
    "hypothesis_id": "h1",
    "rationale": "probe the admin endpoint",
    "expected_impact": "none demonstrated",
    "stop_condition": "on any 5xx",
    "cleanup_plan": "none required",
}


def _pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _generated_bytes() -> dict[str, bytes]:
    return {"actions.json": _pretty(_MANIFEST), "request.json": _pretty(_REQUEST)}


def generate(root: Path, *, check: bool) -> tuple[str, ...]:
    generated = _generated_bytes()
    differing: list[str] = []
    for relative_path, value in generated.items():
        destination = root / relative_path
        current = destination.read_bytes() if destination.is_file() else None
        if current == value:
            continue
        differing.append(relative_path)
        if not check:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(value)
    return tuple(sorted(differing))


def main(arguments: list[str]) -> int:
    if arguments not in ([], ["--check"]):
        raise SystemExit("usage: generate_engagement_v2_actions_fixtures.py [--check]")
    differing = generate(_DEFAULT_ROOT, check=arguments == ["--check"])
    if arguments == ["--check"] and differing:
        print("\n".join(differing))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
