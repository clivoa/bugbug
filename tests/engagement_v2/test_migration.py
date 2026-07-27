"""P1 read-only dry-run migration analysis and CLI."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hackbot.cli.main import app
from hackbot.engagement_v2.constants import POLICY_BOOLEAN_FIELDS
from hackbot.engagement_v2.migration import MigrationError, analyze_migration

yaml = pytest.importorskip("yaml")


def _write_v1(directory: Path, *, valid_scope: bool = True) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "program.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "program": {"name": "acme", "platform": "hackerone"},
                "testing_rules": {
                    "max_requests_per_second": 7,
                    "concurrency": 3,
                    "automated_scanning_allowed": True,
                    "denial_of_service_allowed": False,
                },
            }
        ),
        encoding="utf-8",
    )
    in_scope = {"domains": ["app.corp.example"]} if valid_scope else {}
    (directory / "scope.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "in_scope": in_scope,
                "out_of_scope": {"domains": ["printer01.corp.example"]},
            }
        ),
        encoding="utf-8",
    )
    (directory / "authorization.json").write_text(
        json.dumps(
            {
                "confirmed": True,
                "confirmation_timestamp": "2026-07-01T00:00:00Z",
                "confirmed_by": "operator",
                "note": "v1",
            }
        ),
        encoding="utf-8",
    )
    return directory


def _snapshot(directory: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            snapshot[str(path.relative_to(directory))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return snapshot


# --------------------------------------------------------------- CLI writes ---
def test_dry_run_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    engagement = _write_v1(tmp_path / "eng")
    before = _snapshot(engagement)
    code = app(
        [
            "engagement",
            "migrate",
            "--engagement",
            str(engagement),
            "--to",
            "2",
            "--profile",
            "bug-bounty",
            "--dry-run",
        ]
    )
    after = _snapshot(engagement)
    assert code == 0
    assert before == after


def test_missing_profile_rejected(tmp_path: Path) -> None:
    engagement = _write_v1(tmp_path / "eng")
    before = _snapshot(engagement)
    code = app(["engagement", "migrate", "--engagement", str(engagement), "--to", "2", "--dry-run"])
    assert code == 2
    assert _snapshot(engagement) == before


def test_invalid_v1_blocks_and_writes_nothing(tmp_path: Path) -> None:
    engagement = _write_v1(tmp_path / "eng", valid_scope=False)
    before = _snapshot(engagement)
    code = app(
        [
            "engagement",
            "migrate",
            "--engagement",
            str(engagement),
            "--to",
            "2",
            "--profile",
            "bug-bounty",
            "--dry-run",
        ]
    )
    assert code == 2
    assert _snapshot(engagement) == before


def test_effective_migration_not_supported(tmp_path: Path) -> None:
    engagement = _write_v1(tmp_path / "eng")
    before = _snapshot(engagement)
    code = app(
        [
            "engagement",
            "migrate",
            "--engagement",
            str(engagement),
            "--to",
            "2",
            "--profile",
            "bug-bounty",
        ]
    )
    assert code == 2
    assert _snapshot(engagement) == before


def test_dry_run_json_reports_proposal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    engagement = _write_v1(tmp_path / "eng")
    code = app(
        [
            "engagement",
            "migrate",
            "--engagement",
            str(engagement),
            "--to",
            "2",
            "--profile",
            "bug-bounty",
            "--dry-run",
            "--json",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dry_run"] is True
    assert payload["ready"] is False
    assert "actions.yaml" in payload["proposed"]


# ------------------------------------------------------------- pure analyzer ---
def _v1_docs() -> tuple[dict, dict, dict]:
    program = {
        "schema_version": 1,
        "program": {"name": "acme", "platform": "hackerone"},
        "testing_rules": {
            "max_requests_per_second": 7,
            "concurrency": 3,
            "automated_scanning_allowed": True,
            "denial_of_service_allowed": True,
        },
    }
    scope = {"schema_version": 1, "in_scope": {"domains": ["app.corp.example"]}, "out_of_scope": {}}
    authorization = {"confirmed": True, "confirmed_by": "operator"}
    return program, scope, authorization


def test_new_sensitive_capabilities_default_false() -> None:
    program, scope, authorization = _v1_docs()
    analysis = analyze_migration(
        v1_program=program, v1_scope=scope, v1_authorization=authorization, profile="bug-bounty"
    )
    rules = analysis.proposed["program.yaml"]["testing_rules"]
    for field in POLICY_BOOLEAN_FIELDS:
        assert rules[field] is False


def test_scope_preserved_exactly() -> None:
    program, scope, authorization = _v1_docs()
    analysis = analyze_migration(
        v1_program=program, v1_scope=scope, v1_authorization=authorization, profile="bug-bounty"
    )
    assert analysis.proposed["scope.yaml"]["in_scope"] == {"domains": ["app.corp.example"]}


def test_numeric_limits_carried_forward() -> None:
    program, scope, authorization = _v1_docs()
    analysis = analyze_migration(
        v1_program=program, v1_scope=scope, v1_authorization=authorization, profile="bug-bounty"
    )
    rules = analysis.proposed["program.yaml"]["testing_rules"]
    assert rules["max_requests_per_second"] == 7
    assert rules["concurrency"] == 3


def test_unenforceable_migration_warned_and_not_ready() -> None:
    program, scope, authorization = _v1_docs()
    analysis = analyze_migration(
        v1_program=program, v1_scope=scope, v1_authorization=authorization, profile="bug-bounty"
    )
    assert analysis.ready is False
    assert any("effective migration unavailable" in warning for warning in analysis.warnings)
    assert any("historical" in warning for warning in analysis.warnings)


def test_unknown_profile_rejected() -> None:
    program, scope, authorization = _v1_docs()
    with pytest.raises(MigrationError):
        analyze_migration(
            v1_program=program, v1_scope=scope, v1_authorization=authorization, profile="root"
        )
