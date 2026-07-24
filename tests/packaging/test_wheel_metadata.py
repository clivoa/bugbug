"""
Packaging tests: the built wheel's dependency metadata must reconcile with
pyproject.toml, and the entry point must be present.
"""

import glob
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def wheel_metadata():
    # build fresh so the test reflects current pyproject
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_wheel.py")],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    whl = sorted(glob.glob(str(ROOT / "dist/hackbot-*.whl")))[-1]
    z = zipfile.ZipFile(whl)
    md = next(n for n in z.namelist() if n.endswith("METADATA"))
    text = z.read(md).decode()
    ep = z.read(next(n for n in z.namelist() if n.endswith("entry_points.txt"))).decode()
    return text, ep


def _pyproject():
    with open(ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]


def test_requires_python_matches(wheel_metadata):
    text, _ = wheel_metadata
    proj = _pyproject()
    assert f"Requires-Python: {proj['requires-python']}" in text


def test_extras_declared_in_metadata(wheel_metadata):
    text, _ = wheel_metadata
    proj = _pyproject()
    for extra, deps in proj.get("optional-dependencies", {}).items():
        assert f"Provides-Extra: {extra}" in text
        for dep in deps:
            assert f'Requires-Dist: {dep}; extra == "{extra}"' in text


def test_keyring_is_secrets_extra_not_core(wheel_metadata):
    text, _ = wheel_metadata
    # keyring must NOT be a bare core dependency
    assert "Requires-Dist: keyring>=25.0\n" not in text
    assert 'Requires-Dist: keyring>=25.0; extra == "secrets"' in text


def test_core_has_no_runtime_deps(wheel_metadata):
    """Core CLI is stdlib-only: no bare Requires-Dist (all are extra-gated)."""
    text, _ = wheel_metadata
    bare = [
        ln for ln in text.splitlines() if ln.startswith("Requires-Dist:") and "; extra ==" not in ln
    ]
    assert bare == [], f"unexpected core deps: {bare}"


def test_console_entry_point(wheel_metadata):
    _, ep = wheel_metadata
    assert "hackbot = hackbot.cli.main:app" in ep
