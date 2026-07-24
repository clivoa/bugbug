"""
programs.engagement — atomic, no-overwrite engagement directory creation.

  * NO-OVERWRITE: refuses if the target engagement directory already exists.
  * ATOMIC: the tree is built in a sibling temp dir and moved into place with a
    single os.rename; a failure leaves NO partial engagement behind.
  * Local files only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from datetime import date
from pathlib import Path

from hackbot.programs.loader import ProgramError

_SUBDIRS = (
    "notes",
    "recon",
    "requests",
    "responses",
    "evidence",
    "hypotheses",
    "findings",
    "reports",
    "logs",
    "cleanup",
)
_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


class EngagementExists(ProgramError):
    pass


def _slug(s: str) -> str:
    s = _SLUG_RE.sub("-", (s or "").strip().lower()).strip("-")
    return s or "unnamed"


def engagement_path(
    base_dir: str | Path, platform: str, program: str, day: str | None = None
) -> Path:
    day = day or date.today().isoformat()
    return Path(base_dir) / _slug(platform) / _slug(program) / day


def create_engagement(
    base_dir: str | Path,
    *,
    platform: str,
    program: str,
    program_doc: dict,
    scope_doc: dict,
    rules_md: str | None = None,
    day: str | None = None,
) -> Path:
    """Create engagements/<platform>/<program>/<date>/ atomically. Raise if it exists."""
    import yaml  # config extra; caller path already ensured availability

    target = engagement_path(base_dir, platform, program, day)
    if target.exists():
        raise EngagementExists(f"engagement already exists: {target} (refusing to overwrite)")

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".engagement-tmp-", dir=target.parent))
    try:
        for sub in _SUBDIRS:
            (tmp / sub).mkdir()
        (tmp / "program.yaml").write_text(
            yaml.safe_dump(program_doc, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        (tmp / "scope.yaml").write_text(
            yaml.safe_dump(scope_doc, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        if rules_md is not None:
            (tmp / "rules.md").write_text(rules_md, encoding="utf-8")
        (tmp / "authorization.json").write_text(
            json.dumps(
                {
                    "confirmed": False,
                    "confirmation_timestamp": None,
                    "confirmed_by": None,
                    "note": "authorization NOT confirmed; confirm before any active testing",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        (tmp / "engagement.yaml").write_text(
            yaml.safe_dump(
                {
                    "platform": platform,
                    "program": program,
                    "created": (day or date.today().isoformat()),
                    "state": "created",
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        # atomic publish: rename temp dir onto the (still non-existent) target
        os.rename(tmp, target)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)  # leave NO partial engagement
        raise
    return target
