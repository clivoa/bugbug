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
