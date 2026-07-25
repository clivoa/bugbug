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


def test_risk_help_offline(offline_venv):
    r = _run(offline_venv, ["risk", "--help"])
    assert r.returncode == 0
    assert "evaluate" in r.stdout


def test_approval_help_offline(offline_venv):
    r = _run(offline_venv, ["approval", "--help"])
    assert r.returncode == 0
    assert "grant" in r.stdout
    assert "status" in r.stdout


def test_risk_evaluate_without_config_extra_fails_cleanly(offline_venv, tmp_path):
    # A YAML engagement needs hackbot[config]; without it the CLI must fail
    # closed with exit 2, installation guidance, no traceback, no TTY prompt,
    # and without creating any approval directories.
    engagement = tmp_path / "sample-engagement"
    engagement.mkdir()
    (engagement / "program.yaml").write_text(
        "schema_version: 1\nprogram:\n  name: acme\n  platform: generic-vdp\n"
        "scope:\n  in_scope:\n    domains: [acme.example]\n",
        encoding="utf-8",
    )
    (engagement / "scope.yaml").write_text(
        "schema_version: 1\nin_scope:\n  domains: [acme.example]\n", encoding="utf-8"
    )
    (engagement / "authorization.json").write_text(
        json.dumps(
            {
                "confirmed": True,
                "confirmation_timestamp": "2000-01-01T00:00:00Z",
                "confirmed_by": "operator",
            }
        ),
        encoding="utf-8",
    )
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"action_id": "fixture.passive"}), encoding="utf-8")
    r = _run(
        offline_venv,
        ["risk", "evaluate", str(request), "--engagement", str(engagement), "--json"],
    )
    combined = r.stdout + r.stderr
    assert r.returncode == 2, combined
    assert "Traceback" not in combined
    assert "hackbot[config]" in combined
    assert not (engagement / "approvals").exists()
