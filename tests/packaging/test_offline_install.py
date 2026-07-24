"""
Installed-package regression: `hackbot secrets import-claude-settings --dry-run`
must work from a stdlib-only install with NO keychain backend present.

Builds the wheel, installs it into a throwaway venv WITHOUT dependencies, and runs
the dry-run against a synthetic fixture — asserting exit 0, no traceback, and that
no token value is echoed.
"""

import glob
import json
import subprocess
import sys
import venv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def offline_venv(tmp_path_factory):
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_wheel.py")],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    whl = sorted(glob.glob(str(ROOT / "dist/hackbot-*.whl")))[-1]
    vdir = tmp_path_factory.mktemp("offline_venv")
    venv.EnvBuilder(with_pip=True).create(vdir)
    py = vdir / "bin" / "python"
    subprocess.run(
        [str(py), "-m", "pip", "install", "--no-index", "--no-deps", "--quiet", whl],
        check=True,
        capture_output=True,
    )
    return vdir


def _run(offline_venv, args, **kw):
    hb = offline_venv / "bin" / "hackbot"
    return subprocess.run([str(hb), *args], capture_output=True, text=True, **kw)


def test_offline_venv_has_no_keyring(offline_venv):
    r = subprocess.run(
        [
            str(offline_venv / "bin" / "python"),
            "-c",
            "import importlib.util as u; print(bool(u.find_spec('keyring')))",
        ],
        capture_output=True,
        text=True,
    )
    assert r.stdout.strip() == "False"


def test_import_dry_run_offline(offline_venv, tmp_path):
    syn = tmp_path / "syn"
    syn.mkdir()
    (syn / "settings.deepseek.json").write_text(
        json.dumps(
            {
                "env": {
                    "ANTHROPIC_AUTH_TOKEN": "sk-syn-REGRESSION-0123",
                    "ANTHROPIC_MODEL": "deepseek-chat",
                }
            }
        )
    )
    r = _run(offline_venv, ["secrets", "import-claude-settings", "--dir", str(syn), "--dry-run"])
    assert r.returncode == 0, r.stderr
    assert "Traceback" not in (r.stdout + r.stderr)
    assert "WOULD IMPORT" in r.stdout
    assert "sk-syn-REGRESSION" not in r.stdout  # value never echoed


def test_secrets_list_degrades_offline(offline_venv):
    r = _run(offline_venv, ["secrets", "list"])
    assert r.returncode == 3
    assert "Traceback" not in r.stderr
    assert "hackbot[secrets]" in r.stderr
