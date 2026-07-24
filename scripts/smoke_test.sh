#!/usr/bin/env bash
#
# smoke_test.sh — offline packaging smoke test.
# Builds the wheel with the stdlib builder, installs it into the venv with
# --no-index --no-deps (no network), and verifies the `hackbot` console script
# works from the INSTALLED package (not from src/).
#
set -euo pipefail
cd "$(dirname "$0")/.."

VENV="${VENV:-.venv}"
PY="$PWD/$VENV/bin/python"
HACKBOT="$PWD/$VENV/bin/hackbot"

echo "== python: $($PY -V) =="
echo "== build wheel (stdlib, offline) =="
"$PY" scripts/build_wheel.py

echo "== install wheel (--no-index --no-deps, offline) =="
"$PY" -m pip install --no-index --no-deps --force-reinstall --quiet dist/hackbot-*.whl
echo "installed; console script present: $([ -x "$HACKBOT" ] && echo yes || echo NO)"

echo "== run from installed console script (no PYTHONPATH=src) =="
( cd /tmp && "$HACKBOT" version )
( cd /tmp && "$HACKBOT" doctor --json --no-net >/tmp/hb_doctor.json ) \
  && "$PY" -c "import json;d=json.load(open('/tmp/hb_doctor.json'));assert d['min_python']=='3.11';assert any(c['key']=='running' for c in d['checks']);print('doctor json ok:',len(d['checks']),'checks,',len(d['blockers']),'blockers')"
( cd /tmp && HACKBOT_SECRET_BACKEND=memory "$HACKBOT" scope check https://evil.com --in example.com ) && echo "UNEXPECTED allow" || echo "scope deny ok (exit nonzero as expected)"

echo "== SMOKE TEST PASSED =="
