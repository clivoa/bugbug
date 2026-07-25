"""Pytest bootstrap: make `src/` importable and expose shared paths."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

BUNDLE = ROOT / "references/recon/Recon-bundle.html"
GENERATED = ROOT / "generated/recon-bundle"
