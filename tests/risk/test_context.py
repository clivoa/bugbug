"""Strict authorization and policy-context loading tests."""

import json
from pathlib import Path

import pytest

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
