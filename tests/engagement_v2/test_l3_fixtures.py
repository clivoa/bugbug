"""P5b deterministic synthetic isolated-lab fixture generation."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_FIXTURE = Path("tests/fixtures/engagement_v2_l3/isolated-lab.json")
_GENERATOR = Path("scripts/generate_engagement_v2_l3_fixtures.py")


def test_l3_fixture_matches_generator() -> None:
    completed = subprocess.run(
        [sys.executable, str(_GENERATOR), "--check"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_l3_fixture_is_synthetic_and_live_tools_are_disabled() -> None:
    data = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    text = json.dumps(data, sort_keys=True).lower()
    assert data["synthetic"] is True
    assert data["isolated_disposable_lab_only"] is True
    assert data["ci_live_tools_allowed"] is False
    assert data["realm"] == "EXAMPLE.TEST"
    assert all(host["address"].startswith("192.0.2.") for host in data["hosts"])
    assert all(host["name"].endswith(".example.test") for host in data["hosts"])
    for marker in (
        "password",
        "private key",
        "begin rsa",
        "access token",
        "api key",
        "real target",
    ):
        assert marker not in text


def test_fixture_check_detects_drift_without_overwriting(tmp_path: Path) -> None:
    output = tmp_path / "isolated-lab.json"
    generated = subprocess.run(
        [sys.executable, str(_GENERATOR), "--output", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert generated.returncode == 0, generated.stderr
    output.write_text("{}\n", encoding="utf-8")

    checked = subprocess.run(
        [sys.executable, str(_GENERATOR), "--check", "--output", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert checked.returncode == 1
    assert output.read_text(encoding="utf-8") == "{}\n"
