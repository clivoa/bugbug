"""Committed P2 actions fixtures are reproducible and decide as specified."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import scripts.generate_engagement_v2_actions_fixtures as fixtures

from hackbot.engagement_v2.manifest import load_manifest
from hackbot.engagement_v2.policy import DecisionKind, decide

from ._engagement_builders import program_doc, scope_doc

_ROOT = Path("tests/fixtures/engagement_v2_actions")


def test_committed_actions_fixtures_are_reproducible() -> None:
    assert fixtures.main(["--check"]) == 0


def test_fixture_manifest_and_request_allow() -> None:
    registry = load_manifest(str(_ROOT / "actions.json"))
    request = json.loads((_ROOT / "request.json").read_text())
    snapshot = SimpleNamespace(
        authorization={"confirmed": True},
        program=program_doc(),
        scope=scope_doc(),
        profile="bug-bounty",
    )
    decision = decide(request, snapshot, registry, platform="linux")
    assert decision.kind is DecisionKind.ALLOW
    assert decision.bound is not None
    assert decision.bound.argv[0] == "/usr/bin/curl"
