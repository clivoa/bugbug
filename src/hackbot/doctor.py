"""
doctor — read-only environment diagnostic, available from the installed package.

SAFETY: strictly read-only. Never installs, modifies, or elevates. NEVER prints
secret values (API keys, tokens, cookies, keychain contents, Burp project data).
It reports only presence/versions. The single outbound check (public egress IP) is
skipped when ``no_net=True``.

Cross-platform (macOS + Linux). Exposed as ``hackbot doctor``.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass

MIN_PY = (3, 11)

SECURITY_TOOLS = [
    "subfinder",
    "dnsx",
    "httpx",
    "katana",
    "naabu",
    "nuclei",
    "amass",
    "gau",
    "waybackurls",
    "gowitness",
    "ffuf",
    "feroxbuster",
    "arjun",
    "dalfox",
    "semgrep",
    "gitleaks",
    "trufflehog",
    "osv-scanner",
    "trivy",
    "nmap",
    "masscan",
    "sqlmap",
    "shodan",
    "jq",
    "yq",
    "rg",
    "fd",
    "go",
]


@dataclass
class Check:
    group: str
    key: str
    value: str
    status: str  # ok | warn | missing | incompatible | info


def _run(cmd: list[str], timeout: float = 6.0) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (out.stdout or out.stderr).strip()
    except Exception:
        return ""


def _first_line(s: str) -> str:
    return s.splitlines()[0].strip() if s else ""


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _py_status(version: tuple[int, ...]) -> str:
    return "ok" if version >= MIN_PY else "incompatible"


def collect(no_net: bool = False) -> list[Check]:
    c: list[Check] = []
    system = platform.system()  # Darwin | Linux
    is_mac = system == "Darwin"

    # --- system ---
    if is_mac:
        ver = _run(["sw_vers", "-productVersion"])
        build = _run(["sw_vers", "-buildVersion"])
        c.append(Check("system", "os", f"macOS {ver} ({build})".strip(), "ok"))
    else:
        pretty = ""
        try:
            with open("/etc/os-release") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        pretty = line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pretty = system
        c.append(Check("system", "os", pretty or system, "ok"))
    c.append(Check("system", "arch", platform.machine(), "ok"))

    # --- python (running interpreter + PATH python3) ---
    rv = sys.version_info
    running = f"{rv.major}.{rv.minor}.{rv.micro} (running hackbot)"
    c.append(Check("python", "running", running, _py_status((rv.major, rv.minor))))
    path_py = _first_line(_run(["python3", "--version"]))
    if path_py:
        nums = path_py.replace("Python", "").strip().split(".")
        try:
            pv = (int(nums[0]), int(nums[1]))
        except (IndexError, ValueError):
            pv = (0, 0)
        note = "" if pv >= MIN_PY else f" — need >= {MIN_PY[0]}.{MIN_PY[1]}"
        c.append(Check("python", "path_python3", f"{path_py}{note}", _py_status(pv)))
    else:
        c.append(Check("python", "path_python3", "not found", "missing"))
    c.append(
        Check(
            "python",
            "uv",
            _first_line(_run(["uv", "--version"])) or "not installed",
            "ok" if _has("uv") else "warn",
        )
    )
    c.append(
        Check(
            "python",
            "pipx",
            _first_line(_run(["pipx", "--version"])) or "not installed",
            "ok" if _has("pipx") else "warn",
        )
    )

    # --- toolchains ---
    if is_mac:
        c.append(
            Check(
                "toolchain",
                "homebrew",
                (_first_line(_run(["brew", "--version"])) + " @ " + _run(["brew", "--prefix"]))
                if _has("brew")
                else "not installed",
                "ok" if _has("brew") else "missing",
            )
        )
    node = _first_line(_run(["node", "--version"]))
    c.append(Check("toolchain", "node", node or "not found", "ok" if node else "warn"))
    go = _first_line(_run(["go", "version"]))
    c.append(
        Check(
            "toolchain", "go", go or "not installed (needed for PD tools)", "ok" if go else "warn"
        )
    )
    java = _first_line(_run(["java", "-version"]))
    java_ok = (
        _has("java") and "unable to locate" not in java.lower() and "no java" not in java.lower()
    )
    c.append(
        Check(
            "toolchain",
            "java",
            java if java_ok else "not installed (Burp MCP needs JRE 17/21)",
            "ok" if java_ok else "warn",
        )
    )
    git = _first_line(_run(["git", "--version"]))
    c.append(Check("toolchain", "git", git or "not found", "ok" if git else "missing"))

    # --- containers ---
    ct = None
    for name in ("docker", "orbstack", "colima", "podman"):
        if _has(name):
            ct = name
            break
    if ct == "docker":
        running_daemon = _run(["docker", "info", "--format", "{{.ServerVersion}}"])
        c.append(
            Check(
                "container",
                "docker",
                f"present, daemon {'running' if running_daemon else 'NOT running'}",
                "ok" if running_daemon else "warn",
            )
        )
    elif ct:
        c.append(Check("container", ct, "present", "ok"))
    else:
        c.append(Check("container", "runtime", "none (labs will need one)", "warn"))

    # --- claude / burp ---
    claude = _first_line(_run(["claude", "--version"]))
    c.append(Check("claude", "cli", claude or "not installed", "ok" if claude else "warn"))
    if is_mac:
        burp = _run(["/bin/sh", "-c", "ls -d /Applications/Burp*.app 2>/dev/null | head -1"])
        c.append(
            Check("burp", "app", burp or "not found in /Applications", "ok" if burp else "warn")
        )
    else:
        c.append(
            Check(
                "burp",
                "app",
                "burpsuite on PATH" if _has("burpsuite") else "not detected",
                "ok" if _has("burpsuite") else "warn",
            )
        )

    # --- security tools ---
    found = [t for t in SECURITY_TOOLS if _has(t)]
    c.append(
        Check(
            "tools",
            "installed",
            " ".join(found) if found else "none yet (clean slate)",
            "ok" if found else "info",
        )
    )

    # --- network ---
    if not no_net:
        egress = _run(["/bin/sh", "-c", "curl -s --max-time 8 https://api.ipify.org"])
        c.append(
            Check(
                "network",
                "egress_ip",
                f"{egress or 'unavailable'} (baseline; re-checked per engagement)",
                "info",
            )
        )
    else:
        c.append(Check("network", "egress_ip", "skipped (--no-net)", "info"))

    return c


def as_dict(no_net: bool = False) -> dict:
    checks = collect(no_net=no_net)
    return {
        "os": platform.system(),
        "arch": platform.machine(),
        "min_python": f"{MIN_PY[0]}.{MIN_PY[1]}",
        "generated_by": "hackbot doctor",
        "checks": [asdict(x) for x in checks],
        "blockers": [asdict(x) for x in checks if x.status in ("missing", "incompatible")],
    }


def render_text(no_net: bool = False) -> str:
    checks = collect(no_net=no_net)
    marks = {
        "ok": " ok ",
        "warn": "warn",
        "missing": "MISS",
        "incompatible": "INCOMPAT",
        "info": "info",
    }
    lines: list[str] = []
    last_group = None
    for ch in checks:
        if ch.group != last_group:
            lines.append(f"\n== {ch.group} ==")
            last_group = ch.group
        lines.append(f"  [{marks.get(ch.status, 'info'):>8}] {ch.key:<20} {ch.value}")
    blockers = [x for x in checks if x.status in ("missing", "incompatible")]
    lines.append("")
    if blockers:
        lines.append(f"Blockers: {', '.join(b.key for b in blockers)}")
    lines.append("Diagnostic complete. Nothing was installed or modified.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="hackbot doctor", description="read-only environment diagnostic"
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-net", action="store_true", help="skip the egress-IP check")
    args = p.parse_args(argv)
    if args.json:
        print(json.dumps(as_dict(no_net=args.no_net), indent=2))
    else:
        print(render_text(no_net=args.no_net))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
