#!/usr/bin/env bash
#
# bootstrap-macos.sh — idempotent base dev-environment setup for hackbot.
#
# SAFETY / SCOPE:
#   * --dry-run (default) installs NOTHING. It only reads local `brew` state and
#     prints exactly what --install would do.
#   * No sudo. No shell-init modification (~/.zshrc etc. are never touched).
#   * No secrets are read or written. No unaudited `curl | sh`.
#   * --install runs `brew bundle` against ./Brewfile only (checksums/provenance
#     handled by Homebrew) and writes a machine-readable manifest.
#
# Usage:
#   scripts/bootstrap-macos.sh --dry-run     # show the plan (no changes)
#   scripts/bootstrap-macos.sh --install     # apply (asks nothing destructive)
#
set -uo pipefail
cd "$(dirname "$0")/.."

MODE="dry-run"
for a in "$@"; do
  case "$a" in
    --dry-run) MODE="dry-run" ;;
    --install) MODE="install" ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

BREWFILE="Brewfile"
MANIFEST="generated/install-manifest.json"
OS="$(uname -s)"

say() { printf "%s\n" "$*"; }
plan() { printf "  [%s] %s\n" "$1" "$2"; }

say "== hackbot bootstrap ($MODE) =="
say "OS: $OS  arch: $(uname -m)"
if [ "$OS" != "Darwin" ]; then
  say "NOTE: this is the macOS bootstrap. On Linux, the equivalent packages come"
  say "      from your distro package manager (a linux bootstrap is a later phase)."
fi
say ""

# --- prerequisites (report only) ---
say "-- prerequisites --"
if command -v brew >/dev/null 2>&1; then
  plan "OK" "Homebrew present: $(brew --version | head -1) @ $(brew --prefix)"
else
  plan "MISSING" "Homebrew not found. Install it first (see https://brew.sh);"
  plan "MISSING" "this script will NOT auto-run a remote install script."
fi
# Python >= 3.11
PYOK="no"
for alt in python3.14 python3.13 python3.12 python3.11; do
  command -v "$alt" >/dev/null 2>&1 && { plan "OK" "Python 3.11+ present: $alt ($($alt --version 2>&1))"; PYOK="yes"; break; }
done
[ "$PYOK" = "no" ] && plan "PLAN" "would install python@3.14 (no >=3.11 interpreter found)"
say ""

# --- Brewfile plan ---
say "-- Brewfile packages --"
TO_INSTALL=()
PRESENT=()
if [ -f "$BREWFILE" ]; then
  # extract formula names from lines like: brew "name"
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    short="${f##*/}"          # openjdk@21 stays; homebrew/core/x -> x
    if command -v brew >/dev/null 2>&1 && brew list --versions "$f" >/dev/null 2>&1; then
      plan "present" "$f ($(brew list --versions "$f" 2>/dev/null | awk '{print $2}'))"
      PRESENT+=("$f")
    else
      plan "WOULD INSTALL" "$f"
      TO_INSTALL+=("$f")
    fi
  done < <(awk -F'"' '/^[[:space:]]*brew[[:space:]]/{print $2}' "$BREWFILE")
else
  say "  (no Brewfile found)"
fi
say ""

# --- summary ---
say "-- summary --"
say "  already present : ${#PRESENT[@]}"
say "  would install   : ${#TO_INSTALL[@]}${TO_INSTALL:+  (${TO_INSTALL[*]})}"
say "  recon/offensive tools are NOT installed here (see scripts/install-tools.sh)"
say "  shell init files: NOT modified   |   sudo: NOT used   |   secrets: NOT touched"
say ""

if [ "$MODE" = "dry-run" ]; then
  say "Dry-run only. Nothing was installed or modified."
  say "Re-run with --install to apply (Homebrew will verify package provenance)."
  exit 0
fi

# --- install path ---
if ! command -v brew >/dev/null 2>&1; then
  say "ERROR: Homebrew is required for --install." >&2
  exit 1
fi
say "Applying Brewfile via 'brew bundle' (no sudo, no shell changes)..."
brew bundle --file="$BREWFILE"
mkdir -p "$(dirname "$MANIFEST")"
{
  printf '{\n  "generated_by": "bootstrap-macos.sh",\n  "os": "%s",\n  "installed": [\n' "$OS"
  first=1
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    v="$(brew list --versions "$f" 2>/dev/null | awk '{print $2}')"
    [ $first -eq 0 ] && printf ',\n'; first=0
    printf '    {"formula": "%s", "version": "%s"}' "$f" "$v"
  done < <(awk -F'"' '/^[[:space:]]*brew[[:space:]]/{print $2}' "$BREWFILE")
  printf '\n  ]\n}\n'
} > "$MANIFEST"
say "Wrote install manifest -> $MANIFEST"
say "Next: scripts/doctor.sh   (verify)   then  hackbot doctor"
