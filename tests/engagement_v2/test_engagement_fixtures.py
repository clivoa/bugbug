"""Committed engagement fixtures are reproducible and load as specified."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import scripts.generate_engagement_v2_engagement_fixtures as fixtures

from hackbot.cli.main import app
from hackbot.engagement_v2.loader import load_engagement

pytest.importorskip("yaml")

_ROOT = Path("tests/fixtures/engagement_v2_loader")


def test_committed_fixtures_are_reproducible() -> None:
    assert fixtures.main(["--check"]) == 0


def test_v2_confirmed_fixture_loads_and_confirms() -> None:
    snapshot = load_engagement(_ROOT / "v2-confirmed")
    assert snapshot.profile == "private-pentest"
    assert snapshot.authority_digest.startswith("sha256:")
    # Deterministic: the stored digest matches the recomputed one.
    assert snapshot.authority_digest == snapshot.authorization["confirmed_authority_digest"]


def test_v1_source_fixture_dry_run_writes_nothing(tmp_path: Path) -> None:
    # Copy the read-only fixture into a temp dir so a bug that writes is visible.
    source = _ROOT / "v1-source"
    engagement = tmp_path / "eng"
    engagement.mkdir()
    for path in source.iterdir():
        (engagement / path.name).write_bytes(path.read_bytes())

    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in engagement.iterdir()}
    code = app(
        [
            "engagement",
            "migrate",
            "--engagement",
            str(engagement),
            "--to",
            "2",
            "--profile",
            "private-pentest",
            "--dry-run",
        ]
    )
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in engagement.iterdir()}
    assert code == 0
    assert before == after
