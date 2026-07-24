#!/usr/bin/env bash
#
# hackbot doctor — read-only environment diagnostic (macOS + Linux).
#
# SAFETY: This script is strictly read-only. It never installs, modifies, or
# elevates. It NEVER prints secret VALUES (API keys, tokens, cookies, Keychain
# contents, Burp project data). It only reports whether things exist/are present.
#
# Usage:
#   scripts/doctor.sh              # human-readable report
#   scripts/doctor.sh --json       # machine-readable JSON (for `hackbot doctor`)
#   scripts/doctor.sh --no-net     # skip the single outbound egress-IP check
#
set -uo pipefail

JSON=0
NET=1
for arg in "$@"; do
  case "$arg" in
    --json) JSON=1 ;;
    --no-net) NET=0 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

# ------------------------------------------------------------------ helpers ---
OS="$(uname -s)"          # Darwin | Linux
ARCH="$(uname -m)"        # arm64 | x86_64 | aarch64
declare -a JROWS=()       # collected "key\tvalue\tstatus" rows for JSON

has() { command -v "$1" >/dev/null 2>&1; }

# ver <cmd> [args...] -> first line of version output, or "" if absent
ver() {
  local c="$1"; shift
  has "$c" || { echo ""; return 1; }
  "$c" "$@" 2>&1 | head -1
}

emit() { # emit <group> <key> <value> <status: ok|warn|missing|info>
  local g="$1" k="$2" v="$3" s="$4"
  JROWS+=("$g"$'\x1f'"$k"$'\x1f'"$v"$'\x1f'"$s")
  if [ "$JSON" -eq 0 ]; then
    local mark
    case "$s" in
      ok) mark=" ok " ;;
      warn) mark="warn" ;;
      missing) mark="MISS" ;;
      *) mark="info" ;;
    esac
    printf "  [%s] %-22s %s\n" "$mark" "$k" "$v"
  fi
}

section() { [ "$JSON" -eq 0 ] && printf "\n== %s ==\n" "$1"; return 0; }

# ------------------------------------------------------------------ system ---
section "System"
if [ "$OS" = "Darwin" ]; then
  emit system os "macOS $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))" ok
  MEM_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
  CPU="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
else
  DISTRO="$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || echo Linux)"
  emit system os "$DISTRO" ok
  MEM_BYTES=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0) * 1024 ))
  CPU="$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null | sed 's/^ *//' || echo unknown)"
fi
emit system arch "$ARCH" ok
emit system cpu "$CPU" info
if [ "${MEM_BYTES:-0}" -gt 0 ] 2>/dev/null; then
  emit system memory "$(( MEM_BYTES / 1073741824 )) GB" info
else
  emit system memory "unknown" info
fi
DISK_AVAIL=$(df -h / 2>/dev/null | awk 'NR==2{print $4}')
emit system disk_free "${DISK_AVAIL:-unknown} on /" info
emit system shell "${SHELL:-unknown}" info

# ------------------------------------------------------------- toolchains ---
section "Toolchains"
if has brew; then emit toolchain homebrew "$(brew --version 2>/dev/null | head -1) @ $(brew --prefix)" ok
elif [ "$OS" = "Darwin" ]; then emit toolchain homebrew "not installed" missing
else emit toolchain homebrew "n/a (Linux)" info; fi

PYV="$(ver python3 --version)"
if [ -n "$PYV" ]; then
  # require Python >= 3.11 (hackbot minimum)
  PYNUM="$(printf '%s' "$PYV" | sed -E 's/[^0-9.]//g')"
  PYMAJ="${PYNUM%%.*}"; PYREST="${PYNUM#*.}"; PYMIN="${PYREST%%.*}"
  if [ "${PYMAJ:-0}" -gt 3 ] 2>/dev/null || { [ "${PYMAJ:-0}" -eq 3 ] && [ "${PYMIN:-0}" -ge 11 ]; } 2>/dev/null; then
    emit toolchain python3 "$PYV" ok
  else
    emit toolchain python3 "$PYV (INCOMPATIBLE: need >= 3.11)" warn
  fi
  # note a newer interpreter if the default python3 is too old
  for alt in python3.14 python3.13 python3.12 python3.11; do
    if command -v "$alt" >/dev/null 2>&1; then
      emit toolchain python311plus "$alt -> $($alt --version 2>&1)" ok; break
    fi
  done
else
  emit toolchain python3 "not found" missing
fi
has uv   && emit toolchain uv   "$(uv --version 2>/dev/null)" ok   || emit toolchain uv   "not installed (recommended)" warn
has pipx && emit toolchain pipx "$(pipx --version 2>/dev/null)" ok || emit toolchain pipx "not installed (recommended)" warn
NODEV="$(ver node --version)"; [ -n "$NODEV" ] && emit toolchain node "$NODEV" ok || emit toolchain node "not found" warn
GOV="$(ver go version)"; [ -n "$GOV" ] && emit toolchain go "$GOV" ok || emit toolchain go "not installed (needed for PD tools)" warn
JAVA_LINE="$(java -version 2>&1 | head -1)"
if has java && ! printf '%s' "$JAVA_LINE" | grep -qiE 'unable to locate|no java|not found'; then
  emit toolchain java "$JAVA_LINE" ok
else
  emit toolchain java "not installed (Burp MCP needs a JRE 17/21)" warn
fi
GITV="$(ver git --version)"; [ -n "$GITV" ] && emit toolchain git "$GITV" ok || emit toolchain git "not found" missing

# ----------------------------------------------------------- containers ---
section "Containers"
CT_FOUND=0
for c in docker orbstack colima podman; do
  if has "$c"; then CT_FOUND=1
    if [ "$c" = docker ]; then
      if docker info >/dev/null 2>&1; then emit container docker "present, daemon running" ok
      else emit container docker "present, daemon NOT running" warn; fi
    else emit container "$c" "present" ok; fi
  fi
done
[ "$CT_FOUND" -eq 0 ] && emit container runtime "none (labs will need one)" warn

# --------------------------------------------------------- claude / burp ---
section "Claude Code & Burp"
if has claude; then emit claude cli "$(claude --version 2>/dev/null)" ok
else emit claude cli "not installed" warn; fi
# existence only — never read contents
for f in "$HOME/.claude/settings.json" "$HOME/.claude.json"; do
  [ -e "$f" ] && emit claude "global_config" "exists: ${f/#$HOME/~} (untouched by hackbot)" info
done
if [ "$OS" = "Darwin" ]; then
  if ls -d /Applications/Burp*.app >/dev/null 2>&1; then
    emit burp app "$(ls -d /Applications/Burp*.app 2>/dev/null | head -1)" ok
  else emit burp app "not found in /Applications" warn; fi
else
  has burpsuite && emit burp app "burpsuite on PATH" ok || emit burp app "not detected" warn
fi

# ----------------------------------------------------- security tooling ---
section "Security tools"
FOUND=""
for t in subfinder dnsx httpx katana naabu nuclei amass gau waybackurls gowitness \
         ffuf feroxbuster arjun dalfox semgrep gitleaks trufflehog osv-scanner trivy \
         nmap masscan sqlmap shodan jq yq rg fd; do
  has "$t" && FOUND="$FOUND $t"
done
if [ -n "$FOUND" ]; then emit tools installed "${FOUND# }" ok
else emit tools installed "none yet (clean slate)" info; fi

# ------------------------------------------------------------- network ---
section "Network"
# loopback listeners (names + ports only; never payloads)
if [ "$OS" = "Darwin" ]; then
  LOOP=$(lsof -nP -iTCP@127.0.0.1 -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1":"$9}' | sed 's/.*://; s/^/:/' >/dev/null; \
         lsof -nP -iTCP@127.0.0.1 -sTCP:LISTEN 2>/dev/null | awk 'NR>1{n=$1; sub(/.*:/,"",$9); print n"("$9")"}' | sort -u | tr '\n' ' ')
else
  LOOP=$( (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null) | awk '/127.0.0.1:/{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' ')
fi
emit network loopback_listeners "${LOOP:-none}" info
# VPN interface presence (active inet only)
VPN="none"
if [ "$OS" = "Darwin" ]; then
  for i in $(ifconfig 2>/dev/null | awk -F: '/^(utun|ppp|ipsec|tun|tap)/{print $1}'); do
    ifconfig "$i" 2>/dev/null | grep -q 'inet ' && VPN="$i active"
  done
else
  for i in $(ip -o link 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(tun|tap|ppp|wg)'); do
    ip -o addr show "$i" 2>/dev/null | grep -q 'inet ' && VPN="$i active"
  done
fi
emit network vpn_interface "$VPN" info
if [ "$NET" -eq 1 ]; then
  EGRESS=$(curl -s --max-time 8 https://api.ipify.org 2>/dev/null)
  emit network egress_ip "${EGRESS:-unavailable} (baseline; re-checked per engagement)" info
else
  emit network egress_ip "skipped (--no-net)" info
fi

# --------------------------------------------------------------- output ---
if [ "$JSON" -eq 1 ]; then
  printf '{\n  "os": "%s",\n  "arch": "%s",\n  "generated_by": "hackbot doctor",\n  "checks": [\n' "$OS" "$ARCH"
  n=${#JROWS[@]}; i=0
  for row in "${JROWS[@]}"; do
    IFS=$'\x1f' read -r g k v s <<<"$row"
    # minimal JSON escaping
    v=${v//\\/\\\\}; v=${v//\"/\\\"}
    i=$((i+1)); comma=,; [ "$i" -eq "$n" ] && comma=
    printf '    {"group":"%s","key":"%s","value":"%s","status":"%s"}%s\n' "$g" "$k" "$v" "$s" "$comma"
  done
  printf '  ]\n}\n'
else
  printf "\nDiagnostic complete. Nothing was installed or modified.\n"
  printf "Next: review the plan, then run  scripts/bootstrap-macos.sh --dry-run\n"
fi
