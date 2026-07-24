#!/usr/bin/env python3
"""
build_wheel — produce a valid PEP-427 wheel for hackbot using ONLY the standard
library, so the package can be built and installed fully offline (no build
backend, no network). Output: dist/hackbot-<version>-py3-none-any.whl

Dependency metadata (Requires-Dist / Provides-Extra) is generated FROM
pyproject.toml (via stdlib tomllib) so the wheel can never drift from the declared
dependencies.

Usage: python3 scripts/build_wheel.py
"""
from __future__ import annotations

import base64
import hashlib
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DIST = ROOT / "dist"


def _load_project() -> dict:
    with open(ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]


def _metadata(proj: dict) -> str:
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {proj['name']}",
        f"Version: {proj['version']}",
        "Summary: bugbug — local, safety-controlled bug bounty research workstation",
        f"Requires-Python: {proj.get('requires-python', '>=3.11')}",
    ]
    # core runtime deps
    for dep in proj.get("dependencies", []):
        lines.append(f"Requires-Dist: {dep}")
    # extras
    extras = proj.get("optional-dependencies", {})
    for extra in sorted(extras):
        lines.append(f"Provides-Extra: {extra}")
        for dep in extras[extra]:
            lines.append(f'Requires-Dist: {dep}; extra == "{extra}"')
    return "\n".join(lines) + "\n"


WHEEL = """Wheel-Version: 1.0
Generator: hackbot-stdlib-build 0.2
Root-Is-Purelib: true
Tag: py3-none-any
"""

ENTRY_POINTS = """[console_scripts]
hackbot = hackbot.cli.main:app
"""


def _hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def main() -> int:
    proj = _load_project()
    name, version = proj["name"], proj["version"]
    DIST.mkdir(exist_ok=True)
    wheel_path = DIST / f"{name}-{version}-py3-none-any.whl"
    distinfo = f"{name}-{version}.dist-info"

    members: list[tuple[str, bytes]] = []
    for py in sorted((SRC / name).rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        members.append((str(py.relative_to(SRC)), py.read_bytes()))

    members.append((f"{distinfo}/METADATA", _metadata(proj).encode()))
    members.append((f"{distinfo}/WHEEL", WHEEL.encode()))
    members.append((f"{distinfo}/entry_points.txt", ENTRY_POINTS.encode()))

    record_lines = [f"{arc},{_hash(data)},{len(data)}" for arc, data in members]
    record_lines.append(f"{distinfo}/RECORD,,")
    members.append((f"{distinfo}/RECORD", ("\n".join(record_lines) + "\n").encode()))

    if wheel_path.exists():
        wheel_path.unlink()
    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, data in members:
            zf.writestr(arc, data)

    print(f"built {wheel_path.relative_to(ROOT)} ({wheel_path.stat().st_size} bytes, "
          f"{len(members)} members)")
    print("  extras: " + ", ".join(sorted(proj.get("optional-dependencies", {}))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
