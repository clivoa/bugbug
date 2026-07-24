#!/usr/bin/env bash
#
# bootstrap-macos.sh — minimal, just-in-time, idempotent base-env setup for hackbot.
#
# SAFETY / SCOPE:
#   * --dry-run (default) installs NOTHING. It only reads local state and prints
#     exactly what --install would do.
#   * Fail-fast: `set -euo pipefail`. If `brew bundle` fails, the run aborts and NO
#     manifest is written (no misleading success record).
#   * --install runs only on macOS. No sudo. No shell-init modification. No secrets.
#   * Minimal plan: installs only `uv` now (reproducible dependency management).
#     Go, a JRE, and other tools are DEFERRED to the phase that needs them.
#
# Usage:
#   scripts/bootstrap-macos.sh --dry-run     # show the plan (no changes)
#   scripts/bootstrap-macos.sh --install     # apply (macOS only)
#
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="dry-run"
for a in "$@"; do
  case "$a" in
    --dry-run) MODE="dry-run" ;;
    --install) MODE="install" ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

BREWFILE="Brewfile"
MANIFEST="generated/install-manifest.json"
OS="$(uname -s)"

say()  { printf "%s\n" "$*"; }
plan() { printf "  [%s] %s\n" "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

say "== hackbot bootstrap ($MODE) =="
say "OS: $OS  arch: $(uname -m)"
say ""

# --- prerequisites (report only) ---
say "-- prerequisites --"
if have brew; then
  plan "OK" "Homebrew present: $(brew --version | head -1) @ $(brew --prefix)"
else
  plan "MISSING" "Homebrew not found — install from https://brew.sh (no auto curl|sh here)."
fi
PYOK="no"
for alt in python3.14 python3.13 python3.12 python3.11; do
  if have "$alt"; then plan "OK" "Python 3.11+ present: $alt ($($alt --version 2>&1))"; PYOK="yes"; break; fi
done
[ "$PYOK" = "no" ] && plan "PLAN" "would install python@3.14 (no >=3.11 interpreter found)"
say ""

# --- already on PATH (skip; do NOT duplicate via Homebrew) ---
say "-- already on PATH (not duplicated) --"
for t in git jq rg fd yq wget; do
  if have "$t"; then plan "skip" "$t present at $(command -v "$t")"; fi
done
say ""

# --- Brewfile plan (what --install applies now) ---
say "-- would install now (Brewfile) --"
INSTALL_NOW=()
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if have brew && brew list --versions "$f" >/dev/null 2>&1; then
    plan "present" "$f ($(brew list --versions "$f" | awk '{print $2}'))"
  else
    plan "WOULD INSTALL" "$f"; INSTALL_NOW+=("$f")
  fi
done < <(awk -F'"' '/^[[:space:]]*brew[[:space:]]/{print $2}' "$BREWFILE")
say ""

# --- deferred (installed later, by the phase that needs it) ---
say "-- deferred (NOT installed now) --"
plan "later" "go            -> when recon adapters land (ProjectDiscovery tools)"
plan "later" "openjdk@21    -> when the Burp Suite MCP is set up. NOTE: keg-only —"
plan "later" "              use an absolute JAVA_HOME via 'brew --prefix openjdk@21'"
plan "later" "              (project-local; NO sudo symlink, NO shell-init edits)."
plan "later" "pipx          -> only if a tool needs isolated install AND uv can't (often redundant with uv)"
plan "later" "coreutils/gnu-sed -> only if a recon adapter needs a GNU-only flag on macOS"
plan "later" "recon/offensive tools -> scripts/install-tools.sh (feature-gated)"
say ""

# --- summary ---
say "-- summary --"
say "  install now : ${#INSTALL_NOW[@]}${INSTALL_NOW:+  (${INSTALL_NOW[*]})}"
say "  sudo: NOT used   |   shell init: NOT modified   |   secrets: NOT touched"
say ""

if [ "$MODE" = "dry-run" ]; then
  say "Dry-run only. Nothing was installed or modified."
  say "Re-run with --install to apply (macOS only)."
  exit 0
fi

# ---------------------------- install path -----------------------------------
if [ "$OS" != "Darwin" ]; then
  say "ERROR: --install runs on macOS only (OS=$OS). Use the Linux path (later phase)." >&2
  exit 1
fi
if ! have brew; then
  say "ERROR: Homebrew is required for --install." >&2
  exit 1
fi

say "Applying Brewfile via 'brew bundle' (no sudo, no shell changes)..."
# set -e aborts here if brew bundle fails, so the manifest below is only ever
# written after a SUCCESSFUL install.
brew bundle --file="$BREWFILE"

say "Verifying installed formulae..."
mkdir -p "$(dirname "$MANIFEST")"
tmp="$(mktemp)"
{
  printf '{\n  "generated_by": "bootstrap-macos.sh",\n  "os": "%s",\n  "installed": [\n' "$OS"
  first=1
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    v="$(brew list --versions "$f" | awk '{print $2}')"   # set -e: aborts if not installed
    [ $first -eq 0 ] && printf ',\n'; first=0
    printf '    {"formula": "%s", "version": "%s"}' "$f" "$v"
  done < <(awk -F'"' '/^[[:space:]]*brew[[:space:]]/{print $2}' "$BREWFILE")
  printf '\n  ]\n}\n'
} > "$tmp"
mv "$tmp" "$MANIFEST"
say "Verified. Wrote install manifest -> $MANIFEST"
say "Next: scripts/doctor.sh   then   uv pip install -e '.[dev,secrets,config]'"
