"""Strict authorization and policy-context loading tests."""

import json
import sys
from pathlib import Path
from shutil import copytree

import pytest
import yaml

from hackbot.risk.context import ContextError, load_authorization, load_policy_context

FIXTURES = Path(__file__).parent / "fixtures"


def test_context_requires_confirmed_authorization(sample_engagement):
    (sample_engagement / "authorization.json").write_text(
        '{"confirmed": false, "confirmation_timestamp": null, "confirmed_by": null}',
        encoding="utf-8",
    )
    with pytest.raises(ContextError):
        load_policy_context(sample_engagement, profile="bug-bounty")


def test_policy_digest_changes_when_program_policy_changes(sample_engagement):
    first = load_policy_context(sample_engagement, profile="bug-bounty")
    program = sample_engagement / "program.yaml"
    program.write_text(
        program.read_text(encoding="utf-8").replace(
            "max_requests_per_second: 2", "max_requests_per_second: 1"
        ),
        encoding="utf-8",
    )
    second = load_policy_context(sample_engagement, profile="bug-bounty")
    assert first.policy_digest != second.policy_digest


@pytest.mark.parametrize(
    "change",
    [
        lambda scope: scope["in_scope"]["domains"].append("expanded.example"),
        lambda scope: scope["out_of_scope"].setdefault("domains", []).append("blocked.example"),
    ],
)
def test_context_rejects_standalone_scope_mismatch(sample_engagement, change):
    scope = yaml.safe_load((sample_engagement / "scope.yaml").read_text(encoding="utf-8"))
    change(scope)
    (sample_engagement / "scope.yaml").write_text(
        yaml.safe_dump(scope, sort_keys=False), encoding="utf-8"
    )
    with pytest.raises(ContextError, match="scope"):
        load_policy_context(sample_engagement, profile="bug-bounty")


def test_context_uses_semantic_scope_equality_and_canonical_digest(sample_engagement):
    first = load_policy_context(sample_engagement, profile="bug-bounty")
    scope_path = sample_engagement / "scope.yaml"
    scope = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    scope["in_scope"]["cidrs"].reverse()
    scope_path.write_text(yaml.safe_dump(scope, sort_keys=False), encoding="utf-8")
    second = load_policy_context(sample_engagement, profile="bug-bounty")
    assert second.policy_digest == first.policy_digest


def test_context_binds_canonical_path_and_disambiguates_matching_basenames(sample_engagement):
    second_dir = sample_engagement.parent / "other-parent" / sample_engagement.name
    second_dir.parent.mkdir()
    copytree(sample_engagement, second_dir)
    first = load_policy_context(sample_engagement, profile="bug-bounty")
    second = load_policy_context(second_dir, profile="bug-bounty")
    assert first.engagement_path != second.engagement_path
    assert first.engagement_id != second.engagement_id
    assert first.policy_digest != second.policy_digest
    assert first.engagement_path == str(sample_engagement.resolve())


def test_authorization_accepts_legacy_informational_note_without_affecting_digest(
    sample_engagement,
):
    (sample_engagement / "authorization.json").write_text(
        '{"confirmed": true, "confirmation_timestamp": "2000-01-01T00:00:00Z", '
        '"confirmed_by": "test-operator"}',
        encoding="utf-8",
    )
    without_note = load_policy_context(sample_engagement, profile="bug-bounty")
    (sample_engagement / "authorization.json").write_text(
        (FIXTURES / "authorization-confirmed.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    with_note = load_policy_context(sample_engagement, profile="bug-bounty")
    assert with_note.authorization == without_note.authorization
    assert with_note.policy_digest == without_note.policy_digest


def test_authorization_rejects_unknown_keys(tmp_path):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(
        '{"confirmed": true, "confirmation_timestamp": "2000-01-01T00:00:00Z", '
        '"confirmed_by": "operator", "unexpected": true}',
        encoding="utf-8",
    )
    with pytest.raises(ContextError, match="unknown"):
        load_authorization(authorization)


def test_authorization_invalid_utf8_raises_context_error(tmp_path):
    authorization = tmp_path / "authorization.json"
    authorization.write_bytes(b"\xff\xfe")
    with pytest.raises(ContextError, match=str(authorization)):
        load_authorization(authorization)


@pytest.mark.parametrize(
    "payload",
    [
        lambda: (
            '{"confirmed": true, "confirmation_timestamp": "2000-01-01T00:00:00Z", '
            '"confirmed_by": ' + "9" * (sys.get_int_max_str_digits() + 1) + "}"
        ),
    ],
)
def test_authorization_parser_failures_raise_context_error(tmp_path, payload):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(payload(), encoding="utf-8")
    with pytest.raises(ContextError, match=str(authorization)):
        load_authorization(authorization)


def test_authorization_json_recursion_error_raises_context_error(tmp_path, monkeypatch):
    authorization = tmp_path / "authorization.json"
    authorization.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "hackbot.risk.context.strict_json_loads",
        lambda _text: (_ for _ in ()).throw(RecursionError()),
    )
    with pytest.raises(ContextError, match=str(authorization)):
        load_authorization(authorization)


def test_context_rejects_surrogate_confirmed_by_and_profile(sample_engagement):
    (sample_engagement / "authorization.json").write_text(
        json.dumps(
            {
                "confirmed": True,
                "confirmation_timestamp": "2000-01-01T00:00:00Z",
                "confirmed_by": "\ud800",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ContextError, match="confirmed_by"):
        load_policy_context(sample_engagement, profile="bug-bounty")
    (sample_engagement / "authorization.json").write_text(
        (FIXTURES / "authorization-confirmed.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    with pytest.raises(ContextError, match="profile"):
        load_policy_context(sample_engagement, profile="\ud800")


@pytest.mark.parametrize(
    "document",
    [
        '{"confirmed": true, "confirmation_timestamp": "2000-01-01T00:00:00Z", '
        '"confirmed_by": "operator", "note": "first", "note": "second"}',
        '{"confirmed": true, "confirmation_timestamp": "2000-01-01T00:00:00Z", '
        '"confirmed_by": "operator", "note": {"nested": 1, "nested": 2}}',
    ],
)
def test_authorization_rejects_duplicate_json_keys_at_any_depth(tmp_path, document):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(document, encoding="utf-8")
    with pytest.raises(ContextError, match="duplicate"):
        load_authorization(authorization)


@pytest.mark.parametrize("note", [None, 1, "x" * 8_193])
def test_authorization_note_must_be_a_bounded_string_when_present(tmp_path, note):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(
        json.dumps(
            {
                "confirmed": True,
                "confirmation_timestamp": "2000-01-01T00:00:00Z",
                "confirmed_by": "operator",
                "note": note,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ContextError, match="authorization.note"):
        load_authorization(authorization)


@pytest.mark.parametrize(
    "filename",
    ["authorization-denied.json", "authorization-confirmed.json"],
)
def test_authorization_file_is_parsed_as_a_frozen_state(filename):
    state = load_authorization(FIXTURES / filename)
    assert isinstance(state.confirmed, bool)
