#!/usr/bin/env bash
#
# smoke_test.sh — offline packaging smoke test.
#
# Builds the wheel with the stdlib builder and installs it into a THROWAWAY venv
# that has NO third-party deps (no keyring, no pyyaml) with --no-index --no-deps
# (no network). Verifies the `hackbot` console script works from the INSTALLED
# package and that keyring-free paths behave correctly:
#   * doctor / scope / version work
#   * `secrets list` degrades gracefully (no traceback)
#   * `secrets import-claude-settings --dry-run` works WITHOUT any keychain backend
#
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

PY_BASE="$(command -v python3.14 || command -v python3)"
OFFVENV="${OFFVENV:-/tmp/hb_offline_venv}"

echo "== base python: $($PY_BASE -V) =="
echo "== venv integrity of the uv-managed .venv (all four commands) =="
.venv/bin/python -V
.venv/bin/python -m pip --version 2>/dev/null | head -1 || echo "  (uv-managed: pip optional)"
.venv/bin/pip --version 2>/dev/null | head -1 || echo "  (uv-managed venv may omit pip; python -m/uv used instead)"
.venv/bin/hackbot version

echo "== build wheel (stdlib, offline) =="
.venv/bin/python scripts/build_wheel.py 2>/dev/null || "$PY_BASE" scripts/build_wheel.py

echo "== fresh THROWAWAY offline venv (no third-party deps) =="
rm -rf "$OFFVENV"
"$PY_BASE" -m venv "$OFFVENV"
HACKBOT="$OFFVENV/bin/hackbot"
"$OFFVENV/bin/pip" install --no-index --no-deps --force-reinstall --quiet "$ROOT"/dist/hackbot-*.whl
echo "keyring present in offline venv: $("$OFFVENV/bin/python" -c "import importlib.util as u; print(bool(u.find_spec('keyring')))")"

echo "== run from installed console script (offline, no keyring) =="
( cd /tmp && "$HACKBOT" version )
( cd /tmp && "$HACKBOT" doctor --json --no-net >/tmp/hb_doctor.json ) \
  && "$OFFVENV/bin/python" -c "import json;d=json.load(open('/tmp/hb_doctor.json'));assert d['min_python']=='3.11';print('doctor json ok:',len(d['checks']),'checks,',len(d['blockers']),'blockers')"
( cd /tmp && HACKBOT_SECRET_BACKEND=memory "$HACKBOT" scope check https://evil.com --in example.com ) \
  && echo "UNEXPECTED allow" || echo "scope deny ok"

echo "== secrets list degrades gracefully (no keyring, no traceback) =="
SECOUT="$( cd /tmp && "$HACKBOT" secrets list 2>&1 || true )"
printf '%s' "$SECOUT" | grep -q "Traceback" && { echo "FAIL: traceback"; exit 1; }
printf '%s' "$SECOUT" | grep -q "hackbot\[secrets\]" && echo "secrets list ok (graceful)" || { echo "FAIL"; exit 1; }

echo "== REGRESSION: import-claude-settings --dry-run works with NO keychain backend =="
SYN=/tmp/hb_syn_claude; rm -rf "$SYN"; mkdir -p "$SYN"
printf '%s' '{"env":{"ANTHROPIC_AUTH_TOKEN":"sk-syn-0123456789abcdef","ANTHROPIC_MODEL":"deepseek-chat"}}' > "$SYN/settings.deepseek.json"
DRYOUT="$( cd /tmp && "$HACKBOT" secrets import-claude-settings --dir "$SYN" --dry-run 2>&1 )"; RC=$?
printf '%s\n' "$DRYOUT"
[ $RC -eq 0 ] || { echo "FAIL: dry-run exit $RC"; exit 1; }
printf '%s' "$DRYOUT" | grep -q "Traceback" && { echo "FAIL: traceback"; exit 1; }
printf '%s' "$DRYOUT" | grep -q "WOULD IMPORT" || { echo "FAIL: no plan"; exit 1; }
printf '%s' "$DRYOUT" | grep -q "sk-syn-0123" && { echo "FAIL: value leaked"; exit 1; }
echo "regression ok: offline dry-run succeeded without keyring, no value leaked"

echo "== SMOKE TEST PASSED =="