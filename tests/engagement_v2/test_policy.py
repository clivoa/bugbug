"""P2 policy v2 decisions."""

from __future__ import annotations

import copy
from types import SimpleNamespace

from hackbot.engagement_v2.manifest import validate_manifest
from hackbot.engagement_v2.policy import DecisionKind, decide

from ._actions_builders import action_doc, manifest_doc, request_doc
from ._engagement_builders import program_doc, scope_doc


def _registry(action_override=None):
    return validate_manifest(manifest_doc(action_override))


def _snapshot(*, program=None, scope=None, confirmed=True, profile="bug-bounty"):
    return SimpleNamespace(
        authorization={"confirmed": confirmed},
        program=program if program is not None else program_doc(),
        scope=scope if scope is not None else scope_doc(),
        profile=profile,
    )


def test_permitted_request_allowed() -> None:
    decision = decide(request_doc(), _snapshot(), _registry(), platform="linux")
    assert decision.kind is DecisionKind.ALLOW
    assert decision.bound is not None
    assert decision.bound.argv[0] == "/usr/bin/curl"


def test_unconfirmed_authorization_denies() -> None:
    decision = decide(request_doc(), _snapshot(confirmed=False), _registry(), platform="linux")
    assert decision.kind is DecisionKind.DENY
    assert decision.reason == "DENY_AUTHORIZATION_UNCONFIRMED"
    assert decision.bound is None


def test_missing_capability_denies() -> None:
    program = program_doc()
    del program["testing_rules"]["automated_scanning_allowed"]
    decision = decide(request_doc(), _snapshot(program=program), _registry(), platform="linux")
    assert decision.kind is DecisionKind.DENY
    assert decision.reason == "DENY_CAPABILITY_NOT_ALLOWED"


def test_capability_false_denies() -> None:
    program = program_doc()
    program["testing_rules"]["automated_scanning_allowed"] = False
    decision = decide(request_doc(), _snapshot(program=program), _registry(), platform="linux")
    assert decision.reason == "DENY_CAPABILITY_NOT_ALLOWED"


def test_one_out_of_scope_target_denies() -> None:
    request = request_doc()
    request["parameters"]["url"] = "https://evil.example/"
    decision = decide(request, _snapshot(), _registry(), platform="linux")
    assert decision.kind is DecisionKind.DENY
    assert decision.reason == "out-of-scope-no-match"
    assert decision.bound is None


def test_target_count_limit_denies() -> None:
    action = action_doc()
    action["argv"] = ["--list", "{targets_file:url}"]
    program = program_doc()
    program["testing_rules"]["max_targets_per_action"] = 2
    request = request_doc()
    request["parameters"]["url"] = [
        "app.corp.example",
        "a.apps.corp.example",
        "b.apps.corp.example",
    ]
    decision = decide(request, _snapshot(program=program), _registry(action), platform="linux")
    assert decision.reason == "DENY_POLICY_LIMIT"


def test_rate_unenforceable_denies() -> None:
    action = action_doc()
    action["rate_control"] = {"kind": "not-applicable"}
    action["argv"] = ["--target", "{target:url}"]
    decision = decide(request_doc(), _snapshot(), _registry(action), platform="linux")
    assert decision.reason == "DENY_RATE_UNENFORCEABLE"


def test_profile_independent_determinism() -> None:
    program = program_doc()
    scope = scope_doc()
    first = decide(
        request_doc(),
        _snapshot(program=copy.deepcopy(program), scope=copy.deepcopy(scope), profile="bug-bounty"),
        _registry(),
        platform="linux",
    )
    second = decide(
        request_doc(),
        _snapshot(
            program=copy.deepcopy(program), scope=copy.deepcopy(scope), profile="private-pentest"
        ),
        _registry(),
        platform="linux",
    )
    assert first.kind is second.kind
    assert first.reason == second.reason
    assert first.bound is not None and second.bound is not None
    assert first.bound.argv == second.bound.argv


def test_request_cannot_lower_inferred_level() -> None:
    action = action_doc()
    action["risk"] = "L2"
    decision = decide(
        request_doc(requested_risk="L0"), _snapshot(), _registry(action), platform="linux"
    )
    assert decision.effective_risk == "L2"


def test_decision_is_only_allow_or_deny() -> None:
    decision = decide(request_doc(), _snapshot(), _registry(), platform="linux")
    assert decision.kind in {DecisionKind.ALLOW, DecisionKind.DENY}
