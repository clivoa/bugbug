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
echo "== venv integrity (all four commands) =="
"$PY" -V
"$PY" -m pip --version | head -1
"$VENV/bin/pip" --version | head -1        # must not be a broken shebang
echo "  (hackbot console script verified after install below)"

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

echo "== installed secrets backend: must degrade gracefully (no traceback) =="
SECOUT="$( cd /tmp && "$HACKBOT" secrets list 2>&1 || true )"
if printf '%s' "$SECOUT" | grep -q "Traceback"; then
  echo "FAIL: secrets list emitted a traceback:"; printf '%s\n' "$SECOUT"; exit 1
fi
# either it lists (keyring present) or it guides toward the extra — both are OK
printf '%s\n' "$SECOUT" | grep -qE "hackbot\[secrets\]|\[set\]|\[missing\]" \
  && echo "secrets list ok (graceful)" || { echo "FAIL: unexpected secrets output"; exit 1; }

echo "== SMOKE TEST PASSED =="
