"""Behavioral checks for deterministic engagement-v2 fixture generation."""

from __future__ import annotations

import random
import re
import shutil
import time
from pathlib import Path

import pytest
import scripts.generate_engagement_v2_contract_fixtures as fixture_generator
from scripts.generate_engagement_v2_contract_fixtures import generate

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "engagement_v2"


def copy_fixture_tree(destination: Path) -> None:
    """Copy the approved fixture tree into an isolated test directory."""

    shutil.copytree(FIXTURE_ROOT, destination, dirs_exist_ok=True)


def fixture_bytes(root: Path) -> dict[str, bytes]:
    """Return all fixture bytes keyed by their stable relative paths."""

    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_fixture_check_accepts_the_approved_clean_tree(tmp_path: Path) -> None:
    """Catch generator changes that no longer reproduce committed fixtures."""

    copy_fixture_tree(tmp_path)
    before = fixture_bytes(tmp_path)

    assert generate(tmp_path, check=True) == ()
    assert fixture_bytes(tmp_path) == before


def test_fixture_check_detects_drift_without_writing(tmp_path: Path) -> None:
    """Catch a check-mode implementation that repairs instead of reporting drift."""

    copy_fixture_tree(tmp_path)
    changed = tmp_path / "canonical" / "authority-digest.txt"
    changed.write_text("sha256:" + "0" * 64 + "\n", encoding="ascii")
    before = changed.read_bytes()

    differing = generate(tmp_path, check=True)

    assert differing == ("canonical/authority-digest.txt",)
    assert changed.read_bytes() == before


def test_cli_check_reports_sorted_drift_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catch CLI checks that repair drift or report paths in unstable order."""

    copy_fixture_tree(tmp_path)
    (tmp_path / "canonical" / "authority-digest.txt").write_text(
        "sha256:" + "0" * 64 + "\n", encoding="ascii"
    )
    (tmp_path / "patterns" / "cases.json").write_text("[]\n", encoding="ascii")
    before = fixture_bytes(tmp_path)
    monkeypatch.setattr(fixture_generator, "_DEFAULT_ROOT", tmp_path)

    assert fixture_generator.main(["--check"]) == 1
    assert capsys.readouterr().out.splitlines() == [
        "canonical/authority-digest.txt",
        "patterns/cases.json",
    ]
    assert fixture_bytes(tmp_path) == before


def test_cli_rejects_options_other_than_check() -> None:
    """Catch an expanded command interface that can mutate fixture contracts."""

    with pytest.raises(SystemExit, match="usage:"):
        fixture_generator.main(["--update"])


def test_fixture_update_recreates_exact_approved_bytes(tmp_path: Path) -> None:
    """Catch an update-mode generator that emits a different fixture contract."""

    generate(tmp_path, check=False)

    assert fixture_bytes(tmp_path) == fixture_bytes(FIXTURE_ROOT)


def test_fixture_output_is_independent_of_process_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catch generator output derived from process-local state instead of contracts."""

    first = tmp_path / "first"
    second = tmp_path / "second"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", "/synthetic/example.invalid/home")
    monkeypatch.setenv("USER", "synthetic-user")
    monkeypatch.setattr(time, "time", lambda: 0)
    monkeypatch.setattr(random, "getrandbits", lambda _bits: 0)
    generate(first, check=False)

    monkeypatch.chdir(tmp_path / "first")
    monkeypatch.setenv("HOME", "/changed/example.invalid/home")
    monkeypatch.setenv("USER", "changed-user")
    monkeypatch.setattr(time, "time", lambda: 2_000_000_000)
    monkeypatch.setattr(random, "getrandbits", lambda _bits: (1 << _bits) - 1)
    generate(second, check=False)

    assert fixture_bytes(first) == fixture_bytes(second) == fixture_bytes(FIXTURE_ROOT)


def test_generated_fixtures_contain_only_synthetic_safe_values(tmp_path: Path) -> None:
    """Catch accidental publication of sensitive, local, or non-synthetic examples."""

    generate(tmp_path, check=False)
    contents = b"\n".join(fixture_bytes(tmp_path).values()).decode("ascii", errors="ignore").lower()

    for forbidden in ("secret:", "password", "token"):
        assert forbidden not in contents
    assert (
        re.search(
            r"(?<![0-9])(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)",
            contents,
        )
        is None
    )
    assert re.search(r"/(?:users|home)/", contents) is None

    domains = re.findall(r"(?<![a-z0-9-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![a-z0-9-])", contents)
    assert all(
        domain == "operator.fixture"
        or domain == "example.invalid"
        or domain.endswith(".example.invalid")
        for domain in domains
    )
