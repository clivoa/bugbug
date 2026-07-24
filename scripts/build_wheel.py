#!/usr/bin/env python3
"""
build_wheel — produce a valid PEP-427 wheel for hackbot using ONLY the standard
library, so the package can be built and installed fully offline (no build
backend, no network). Output: dist/hackbot-<version>-py3-none-any.whl

Usage: python3 scripts/build_wheel.py
"""
from __future__ import annotations

import base64
import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
NAME = "hackbot"
VERSION = "0.1.0"
DIST = ROOT / "dist"

METADATA = f"""Metadata-Version: 2.1
Name: {NAME}
Version: {VERSION}
Summary: bugbug — local, safety-controlled bug bounty research workstation
Requires-Python: >=3.11
"""

WHEEL = """Wheel-Version: 1.0
Generator: hackbot-stdlib-build 0.1
Root-Is-Purelib: true
Tag: py3-none-any
"""

ENTRY_POINTS = """[console_scripts]
hackbot = hackbot.cli.main:app
"""


def _hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def main() -> int:
    DIST.mkdir(exist_ok=True)
    wheel_path = DIST / f"{NAME}-{VERSION}-py3-none-any.whl"
    distinfo = f"{NAME}-{VERSION}.dist-info"

    # Collect package files (skip caches / compiled).
    members: list[tuple[str, bytes]] = []
    for py in sorted((SRC / NAME).rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        arc = str(py.relative_to(SRC))
        members.append((arc, py.read_bytes()))

    members.append((f"{distinfo}/METADATA", METADATA.encode()))
    members.append((f"{distinfo}/WHEEL", WHEEL.encode()))
    members.append((f"{distinfo}/entry_points.txt", ENTRY_POINTS.encode()))

    # RECORD (hashes + sizes; the RECORD line itself has empty hash/size)
    record_lines = [f"{arc},{_hash(data)},{len(data)}" for arc, data in members]
    record_lines.append(f"{distinfo}/RECORD,,")
    record = ("\n".join(record_lines) + "\n").encode()
    members.append((f"{distinfo}/RECORD", record))

    if wheel_path.exists():
        wheel_path.unlink()
    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, data in members:
            zf.writestr(arc, data)

    print(f"built {wheel_path.relative_to(ROOT)} ({wheel_path.stat().st_size} bytes, "
          f"{len(members)} members)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
