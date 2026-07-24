"""
bundle_classify — risk/scope/portability classification for recon-bundle notes.

This module encodes POLICY, not execution. It maps each bundle note to:
  * recon_type      passive | active | mixed
  * assessment      external | internal
  * bug_bounty      applicable | restricted | disabled
  * risk_level      0 (passive) | 1 (low active) | 2 (approval) | disabled
  * approval_level  none | auto-if-in-scope | explicit | forbidden-by-default
  * skill_target    destination skill directory (recon/** or internal-recon/**)
  * internal_pack   True => disabled by default, needs private-pentest/local-lab
  * macos           per-command portability findings (detected heuristically)

The default-deny philosophy: a note's HIGHEST-risk section sets its approval
level. Discovering an asset never authorizes testing it, so ASN/CDN/cert/PTR
follow-up that leaves named in-scope assets is demoted to L2 or disabled.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any


# ---- macOS / portability signal detection (heuristic, over the command text)
# Each entry: (regex, short_id, severity, adaptation)
_PORTABILITY_RULES: list[tuple[str, str, str, str]] = [
    (r"/dev/tcp/", "bash-dev-tcp", "incompatible-zsh",
     "zsh has no /dev/tcp; run under bash, or use `nc -z` / naabu adapter"),
    (r"/dev/udp/", "bash-dev-udp", "incompatible-zsh",
     "no /dev/udp in zsh; use nmap -sU adapter (L2, approval)"),
    (r"/proc/net/arp", "proc-net-arp", "linux-only",
     "no /proc on macOS; use `arp -an` (BSD) — Linux-runner only feature"),
    (r"\bscapy\b|from scapy", "scapy", "needs-root+deps",
     "raw sockets need root; prefer nmap; Linux-runner recommended"),
    (r"\bp0f\b", "p0f", "linux-oriented",
     "p0f rarely packaged on macOS; Linux-runner or exclude"),
    (r"\barp-scan\b", "arp-scan", "linux-oriented",
     "arp-scan needs libpcap+root; Linux-runner or `arp -an`"),
    (r"\bnetexec\b|\bnxc\b|\bcrackmapexec\b", "netexec", "internal-tool",
     "AD/internal only; disabled in bug-bounty profile"),
    (r"\bbloodhound\b|\bwindapsearch\b|\bldapdomaindump\b", "ad-tooling", "internal-tool",
     "Active Directory tooling; internal-recon pack only"),
    # match the tool invocation (responder -I ...), not the pt-BR verb "responder"
    (r"\bresponder(?:\.py)?\s+-[a-zA-Z]", "responder", "internal-tool",
     "LLMNR/NBT poisoning; internal-recon pack only, never bug-bounty"),
    (r"\bip\s+(addr|route|link|neigh)\b", "iproute2", "linux-only",
     "iproute2 not on macOS; use ifconfig/route/arp shims"),
    (r"\bsed\s+-r\b", "gnu-sed-r", "gnu-flag",
     "BSD sed uses -E not -r; platform shim rewrites the flag"),
    (r"\bgrep\s+-P\b", "gnu-grep-P", "gnu-flag",
     "BSD grep lacks -P (PCRE); use ripgrep or -E adapter"),
    (r"\btimeout\s", "gnu-timeout", "coreutils",
     "macOS lacks `timeout` unless coreutils/gtimeout installed; adapter provides one"),
    (r"\bxargs\b.*\-P", "xargs-parallel", "portable-ok",
     "xargs -P works on both; enforce concurrency cap in adapter"),
]


# ---- Per-note policy table. skill_target is relative to skills/.
#      risk_level: 0/1/2 or "disabled". Highest section governs.
_POLICY: dict[str, dict[str, Any]] = {
    # ---------- external, bug-bounty applicable ----------
    "note-consulta-dns": dict(
        recon_type="mixed", risk_level=1, approval="auto-if-in-scope",
        skill_target="recon/dns-recon",
        note="passive DNS/DoH is L0; active resolution/brute is L1; zone-transfer against 3rd parties excluded"),
    "note-consulta-certificado-tls": dict(
        recon_type="passive", risk_level=0, approval="none",
        skill_target="recon/tls-certificate-recon",
        note="CT logs / crt.sh / censys are passive; live openssl fetch to in-scope host is L1"),
    "note-subdomain-discovery": dict(
        recon_type="mixed", risk_level=1, approval="auto-if-in-scope",
        skill_target="recon/subdomain-discovery",
        note="passive sources L0; DNS bruteforce L1 rate-limited; validation httpx L1"),
    "note-github-recon": dict(
        recon_type="passive", risk_level=0, approval="none",
        skill_target="recon/github-recon",
        note="public code search/secret discovery is L0; exposed .git fetch to in-scope host is L1"),
    "note-google-dorking": dict(
        recon_type="passive", risk_level=0, approval="none",
        skill_target="recon/osint",
        note="search-engine dorking is fully passive"),
    "note-osint-tools": dict(
        recon_type="passive", risk_level=0, approval="none",
        skill_target="recon/osint",
        note="OSINT aggregation; Shodan/censys via adapters; no active probing"),
    "note-js-analysis": dict(
        recon_type="mixed", risk_level=1, approval="auto-if-in-scope",
        skill_target="recon/javascript-analysis",
        note="collecting JS from in-scope host is L1; local secret extraction is L0"),
    "note-web-crawling": dict(
        recon_type="mixed", risk_level=1, approval="auto-if-in-scope",
        skill_target="recon/web-crawling",
        note="wayback/gau L0; live crawl (katana) L1 with strict scope + rate limit"),
    "note-waf-cdn-detection": dict(
        recon_type="mixed", risk_level=1, approval="auto-if-in-scope",
        skill_target="recon/waf-cdn-detection",
        note="passive WAF/CDN detection L1; ORIGIN-IP BYPASS sections DISABLED (defeats protection)",
        disabled_sections=["origin ip discovery (bypass do cdn)", "bypass via host header"]),
    "note-recon-pipeline": dict(
        recon_type="mixed", risk_level=1, approval="auto-if-in-scope",
        skill_target="recon/recon-pipeline",
        note="passive pipeline L0; active pipeline L1; ASN+netblock stage inherits L2/disabled"),
    # ---------- external but L2 (explicit approval) ----------
    "note-asn-netblock": dict(
        recon_type="active", risk_level=2, approval="explicit",
        skill_target="recon/asn-netblock-analysis",
        note="ASN/netblock is a HYPOTHESIS source; probing ranges = L2; CDN/cloud ranges DISABLED; favicon-hash is L0 evidence only",
        disabled_sections=["5. cloud & cdn (cuidado com escopo)", "scan nos ranges descobertos"]),
    "note-banner-scanning": dict(
        recon_type="active", risk_level=2, approval="explicit",
        skill_target="recon/service-fingerprinting",
        note="active banner grabbing across ports needs explicit approval"),
    "note-port-scanning-bash": dict(
        recon_type="active", risk_level=2, approval="explicit",
        skill_target="recon/service-fingerprinting",
        note="port scanning is L2; /dev/tcp & /dev/udp need macOS adaptation or naabu/nmap adapter"),
    "note-tcp-fin-fingerprint": dict(
        recon_type="active", risk_level=2, approval="explicit",
        skill_target="recon/service-fingerprinting",
        note="TCP FIN/JARM/JA3 active fingerprinting = L2; scapy needs root/Linux-runner; JA3/JARM passive-ish subset L1"),
    "note-param-fuzzing": dict(
        recon_type="active", risk_level=2, approval="explicit",
        skill_target="recon/parameter-discovery",
        note="parameter/endpoint fuzzing = L2 (high request volume); only when program allows automated testing"),
    "note-enumeracao-diretorios": dict(
        recon_type="active", risk_level=2, approval="explicit",
        skill_target="recon/parameter-discovery",
        note="directory brute-force = L2 high-volume; low-rate limited discovery may be L1 if program allows"),
    # ---------- internal pack (disabled by default) ----------
    "note-descoberta-hosts-rede-interna": dict(
        recon_type="active", risk_level="disabled", approval="forbidden-by-default",
        skill_target="internal-recon/internal-host-discovery", internal=True,
        note="internal network host discovery; requires private-pentest/local-lab profile + explicit auth"),
    "note-enumeracao-ldap": dict(
        recon_type="active", risk_level="disabled", approval="forbidden-by-default",
        skill_target="internal-recon/ldap-enumeration", internal=True,
        note="AD/LDAP enumeration; internal only; never enabled by an internal hostname appearing in data"),
    "note-enumeracao-linux": dict(
        recon_type="active", risk_level="disabled", approval="forbidden-by-default",
        skill_target="internal-recon/linux-enumeration", internal=True,
        note="internal Linux host/network enumeration; internal profile only"),
}


# ---- Operational attributes per note: tools, API keys, noise, volume, scope
#      risk, third-party impact. Values are conservative defaults for planning.
_ATTRS: dict[str, dict[str, Any]] = {
    "note-consulta-dns": dict(tools=["dig", "dnsx", "dog", "massdns"], api_keys=[],
        noise="low", volume="low", scope_risk="low", third_party="none"),
    "note-consulta-certificado-tls": dict(tools=["curl", "openssl", "tlsx", "certspotter"],
        api_keys=["censys(optional)"], noise="none", volume="low", scope_risk="low", third_party="none"),
    "note-subdomain-discovery": dict(tools=["subfinder", "amass", "dnsx", "httpx", "puredns"],
        api_keys=["various-passive-sources(optional)"], noise="low", volume="medium",
        scope_risk="medium", third_party="possible"),
    "note-github-recon": dict(tools=["gh", "trufflehog", "gitleaks", "github-subdomains"],
        api_keys=["GITHUB_TOKEN"], noise="none", volume="low", scope_risk="low", third_party="none"),
    "note-google-dorking": dict(tools=["browser", "curl"], api_keys=[],
        noise="none", volume="low", scope_risk="low", third_party="none"),
    "note-osint-tools": dict(tools=["shodan", "theHarvester", "amass"],
        api_keys=["SHODAN_API_KEY", "censys(optional)"], noise="none", volume="low",
        scope_risk="low", third_party="none"),
    "note-js-analysis": dict(tools=["katana", "gau", "subjs", "linkfinder", "jsluice"],
        api_keys=[], noise="low", volume="medium", scope_risk="low", third_party="none"),
    "note-web-crawling": dict(tools=["katana", "gau", "waybackurls", "httpx", "hakrawler"],
        api_keys=[], noise="low", volume="medium", scope_risk="medium", third_party="possible"),
    "note-waf-cdn-detection": dict(tools=["wafw00f", "httpx", "dig", "whatweb"],
        api_keys=[], noise="low", volume="low", scope_risk="high",
        third_party="likely (CDN/shared infra)"),
    "note-recon-pipeline": dict(tools=["subfinder", "dnsx", "httpx", "katana", "nuclei"],
        api_keys=["SHODAN_API_KEY(optional)"], noise="medium", volume="medium",
        scope_risk="medium", third_party="possible"),
    "note-asn-netblock": dict(tools=["whois", "amass", "asnmap", "mapcidr", "dnsx"],
        api_keys=["SHODAN_API_KEY(optional)"], noise="high", volume="high",
        scope_risk="high", third_party="likely (ranges may not belong to target)"),
    "note-banner-scanning": dict(tools=["nc", "nmap", "httpx"], api_keys=[],
        noise="high", volume="medium", scope_risk="medium", third_party="possible"),
    "note-port-scanning-bash": dict(tools=["nc", "naabu", "nmap"], api_keys=[],
        noise="high", volume="high", scope_risk="medium", third_party="possible"),
    "note-tcp-fin-fingerprint": dict(tools=["nmap", "scapy", "p0f", "jarm"], api_keys=[],
        noise="high", volume="medium", scope_risk="medium", third_party="possible"),
    "note-param-fuzzing": dict(tools=["arjun", "ffuf", "x8", "paramspider"], api_keys=[],
        noise="high", volume="high", scope_risk="medium", third_party="none"),
    "note-enumeracao-diretorios": dict(tools=["ffuf", "feroxbuster", "gobuster", "dirb"],
        api_keys=[], noise="high", volume="high", scope_risk="medium", third_party="none"),
    "note-descoberta-hosts-rede-interna": dict(tools=["nmap", "arp-scan", "netdiscover", "fping"],
        api_keys=[], noise="high", volume="high", scope_risk="internal-only", third_party="n/a"),
    "note-enumeracao-ldap": dict(tools=["ldapsearch", "nmap", "netexec", "bloodhound"],
        api_keys=[], noise="high", volume="high", scope_risk="internal-only", third_party="n/a"),
    "note-enumeracao-linux": dict(tools=["nmap", "ss", "arp"], api_keys=[],
        noise="high", volume="medium", scope_risk="internal-only", third_party="n/a"),
}


@dataclass
class NoteClassification:
    note_id: str
    title: str
    recon_type: str
    assessment: str           # external | internal
    bug_bounty: str           # applicable | restricted | disabled
    risk_level: Any           # 0 | 1 | 2 | "disabled"
    approval_level: str
    skill_target: str
    internal_pack: bool
    macos_findings: list[dict[str, str]] = field(default_factory=list)
    disabled_sections: list[str] = field(default_factory=list)
    policy_note: str = ""
    required_tools: list[str] = field(default_factory=list)
    required_api_keys: list[str] = field(default_factory=list)
    network_noise: str = "unknown"
    request_volume: str = "unknown"
    scope_risk: str = "unknown"
    third_party_impact: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_portability(commands: list[str]) -> list[dict[str, str]]:
    """Scan captured command STRINGS for macOS/portability issues (no execution)."""
    joined = "\n".join(commands)
    findings: list[dict[str, str]] = []
    seen: set[str] = set()
    for pattern, sid, severity, adaptation in _PORTABILITY_RULES:
        if re.search(pattern, joined, re.I) and sid not in seen:
            seen.add(sid)
            findings.append({"id": sid, "severity": severity, "adaptation": adaptation})
    return findings


def classify(note: Any) -> NoteClassification:
    """Classify a parsed ReconNote (duck-typed: needs .note_id/.title/.commands)."""
    pol = _POLICY.get(note.note_id, dict(
        recon_type="active", risk_level=2, approval="explicit",
        skill_target="recon/uncategorized", note="unmapped note -> conservative L2"))
    attrs = _ATTRS.get(note.note_id, {})
    internal = bool(pol.get("internal", False))
    risk = pol["risk_level"]
    if internal or risk == "disabled":
        bug_bounty = "disabled"
    elif risk == 2:
        bug_bounty = "restricted"
    else:
        bug_bounty = "applicable"
    return NoteClassification(
        note_id=note.note_id,
        title=getattr(note, "title", ""),
        recon_type=pol["recon_type"],
        assessment="internal" if internal else "external",
        bug_bounty=bug_bounty,
        risk_level=risk,
        approval_level=pol["approval"],
        skill_target=pol["skill_target"],
        internal_pack=internal,
        macos_findings=detect_portability(getattr(note, "commands", [])),
        disabled_sections=pol.get("disabled_sections", []),
        policy_note=pol.get("note", ""),
        required_tools=attrs.get("tools", []),
        required_api_keys=attrs.get("api_keys", []),
        network_noise=attrs.get("noise", "unknown"),
        request_volume=attrs.get("volume", "unknown"),
        scope_risk=attrs.get("scope_risk", "unknown"),
        third_party_impact=attrs.get("third_party", "unknown"),
    )


def classify_all(notes: list[Any]) -> list[NoteClassification]:
    return [classify(n) for n in notes]
