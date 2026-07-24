"""Publication-guard tests: pre-push hook blocks recon artifacts by default."""
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / ".githooks" / "pre-push"
GITATTR = ROOT / ".gitattributes"


def test_hook_exists_and_executable():
    assert HOOK.exists(), "pre-push guard hook missing"
    assert HOOK.stat().st_mode & 0o111, "pre-push hook must be executable"


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="not a git repo")
def test_hook_blocks_without_override():
    r = subprocess.run(["bash", str(HOOK)], cwd=ROOT, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True)
    assert r.returncode != 0, "guard must block push by default"
    assert "publication-guard" in r.stderr.lower()
    assert "recon-bundle" in r.stderr or "Recon-bundle" in r.stderr


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="not a git repo")
def test_hook_allows_with_override():
    r = subprocess.run(["bash", str(HOOK)], cwd=ROOT, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True,
                       env={"HACKBOT_ALLOW_PUBLISH_RECON": "1", "PATH": "/usr/bin:/bin"})
    assert r.returncode == 0


def test_gitattributes_export_ignores_protected():
    text = GITATTR.read_text()
    for p in ("references/recon/Recon-bundle.html", "generated/recon-bundle",
              "docs/recon-bundle-review.md"):
        assert p in text and "export-ignore" in text
