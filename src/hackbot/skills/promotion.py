"""Provenance linking code-owned actions to reviewed recon-bundle skills.

Bundle commands stay data; only generic single-tool argv subsets become
code-owned actions. Attribution to @reeshasx is recorded per the bundle's
local-reuse-with-attribution terms (no redistribution of the bundle's creative
content). ``internal-recon`` skills are never promoted.
"""

from __future__ import annotations

from dataclasses import dataclass

ATTRIBUTION = "@reeshasx (CyberNeon Recon Bundle) — https://x.com/reeshasx"


@dataclass(frozen=True, slots=True)
class SkillProvenance:
    skill_id: str
    source_note: str
    bundle_risk_level: str
    approval_level: str
    attribution: str = ATTRIBUTION


def _p(skill_id: str, note: str, risk: str, approval: str) -> SkillProvenance:
    return SkillProvenance(skill_id, note, risk, approval)


PROMOTED_ACTIONS: dict[str, SkillProvenance] = {
    "tls.cert": _p("recon/tls-certificate-recon", "note-consulta-certificado-tls", "0", "none"),
    "dns.lookup": _p("recon/dns-recon", "note-consulta-dns", "1", "auto-if-in-scope"),
    "dns.txt": _p("recon/dns-recon", "note-consulta-dns", "1", "auto-if-in-scope"),
    "dns.mx": _p("recon/dns-recon", "note-consulta-dns", "1", "auto-if-in-scope"),
    "dns.ns": _p("recon/dns-recon", "note-consulta-dns", "1", "auto-if-in-scope"),
    "net.http-get": _p("recon/web-crawling", "note-web-crawling", "1", "auto-if-in-scope"),
    "net.http-head": _p("recon/web-crawling", "note-web-crawling", "1", "auto-if-in-scope"),
    "net.http-options": _p("recon/web-crawling", "note-web-crawling", "1", "auto-if-in-scope"),
    "net.port-scan": _p("recon/service-fingerprinting", "note-port-scanning-bash", "2", "explicit"),
    "web.dir-enum": _p("recon/parameter-discovery", "note-enumeracao-diretorios", "2", "explicit"),
    "web.dir-enum-gobuster": _p(
        "recon/parameter-discovery", "note-enumeracao-diretorios", "2", "explicit"
    ),
}

__all__ = ["ATTRIBUTION", "PROMOTED_ACTIONS", "SkillProvenance"]
