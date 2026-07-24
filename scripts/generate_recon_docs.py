#!/usr/bin/env python3
"""
generate_recon_docs — emit the three recon-bundle review docs from the parser +
classifier (accurate, regenerable). Reads the bundle as inert data.

  docs/recon-bundle-review.md              full inventory + multi-axis classification
  docs/recon-bundle-macos-compatibility.md portability findings + adaptations
  docs/recon-bundle-risk-classification.md risk levels + approval policy

Usage: PYTHONPATH=src python3 scripts/generate_recon_docs.py
"""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hackbot.skills.bundle_parser import parse_bundle, bundle_metadata  # noqa: E402
from hackbot.skills.bundle_classify import classify_all  # noqa: E402

BUNDLE = ROOT / "references/recon/Recon-bundle.html"
DOCS = ROOT / "docs"
ATTRIB = "@reeshasx (CyberNeon Recon Bundle)"
GEN_NOTE = ("> GENERATED from the immutable bundle via "
            "`scripts/generate_recon_docs.py`. The bundle is parsed as inert data; "
            "no command is executed. Source attribution: " + ATTRIB + ".\n")


def esc(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ").strip()


def build(notes, cls):
    meta = bundle_metadata(BUNDLE)
    by_id = {c.note_id: c for c in cls}

    # ---- 1. review (inventory) ------------------------------------------
    r = ["# Recon Bundle Review\n", GEN_NOTE,
         f"\n**Bundle:** {esc(meta['title'])} · **Author:** {esc(meta['author'])} "
         f"({meta['author_link']}) · **License:** {meta['license_declared']} "
         f"→ reference-only, local reuse authorized with attribution.\n",
         f"\n**Notes:** {len(notes)} · **External/applicable:** "
         f"{sum(1 for c in cls if not c.internal_pack)} · **Internal (disabled):** "
         f"{sum(1 for c in cls if c.internal_pack)}\n",
         "\n## Inventory & multi-axis classification\n",
         "| Note | Difficulty | Updated | Type | Assess. | Bug-bounty | Risk | Approval | Noise | Volume | Scope risk | 3rd-party |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for n in notes:
        c = by_id[n.note_id]
        r.append("| {t} | {d} | {u} | {rt} | {a} | {bb} | {rl} | {ap} | {no} | {vo} | {sr} | {tp} |".format(
            t=esc(n.title), d=esc(n.difficulty), u=esc(n.updated), rt=c.recon_type,
            a=c.assessment, bb=c.bug_bounty, rl=c.risk_level, ap=c.approval_level,
            no=c.network_noise, vo=c.request_volume, sr=c.scope_risk, tp=esc(c.third_party_impact)))
    r.append("\n## Per-note detail\n")
    for n in notes:
        c = by_id[n.note_id]
        r.append(f"### {esc(n.title)}  ·  `{n.note_id}`")
        r.append(f"- **Skill target:** `skills/{c.skill_target}`  ·  **Tags:** {' '.join(n.tags)}")
        r.append(f"- **Intro:** {esc(n.intro)[:300]}")
        r.append(f"- **Sections ({len(n.sections)}):** {', '.join(esc(s) for s in n.sections)}")
        r.append(f"- **Commands captured (as data):** {len(n.commands)}  ·  "
                 f"**Warnings:** {len(n.warnings)}  ·  **Checklist items:** {len(n.checklist)}")
        r.append(f"- **Required tools:** {', '.join(c.required_tools) or 'n/a'}")
        r.append(f"- **Required API keys:** {', '.join(c.required_api_keys) or 'none'}")
        if c.disabled_sections:
            r.append(f"- **Excluded sections:** {', '.join(esc(s) for s in c.disabled_sections)}")
        if c.macos_findings:
            r.append(f"- **macOS notes:** {'; '.join(f['id'] for f in c.macos_findings)}")
        r.append(f"- **Policy:** {esc(c.policy_note)}")
        r.append(f"- **Source:** `references/recon/Recon-bundle.html` → {ATTRIB}\n")

    # ---- 2. macOS compatibility -----------------------------------------
    m = ["# Recon Bundle — macOS / Portability Compatibility\n", GEN_NOTE,
         "\nHackbot targets macOS **and** Linux. GNU-only and Linux-only commands "
         "from the bundle are adapted by a platform shim or routed to the optional "
         "Linux SSH runner; a few are excluded. Findings below are detected by "
         "`detect_portability()` over the captured command strings.\n",
         "\n## Findings by note\n",
         "| Note | Finding | Severity | Adaptation |", "|---|---|---|---|"]
    any_find = False
    for n in notes:
        c = by_id[n.note_id]
        for f in c.macos_findings:
            any_find = True
            m.append(f"| {esc(n.title)} | `{f['id']}` | {f['severity']} | {esc(f['adaptation'])} |")
    if not any_find:
        m.append("| _(none detected)_ | | | |")
    m.append("\n## Adaptation policy\n"
             "- **`/dev/tcp`, `/dev/udp`** → not available in zsh; adapters use `nc -z`, "
             "`naabu`, or `nmap`. Bash-only snippets run under an explicit `bash -c` stage.\n"
             "- **`/proc/net/arp`, `iproute2`, `arp-scan`, `p0f`, `scapy`** → Linux-only or "
             "root/pcap; available **only** through the optional Linux runner, never in the "
             "default macOS bug-bounty profile.\n"
             "- **GNU flags** (`sed -r`, `grep -P`, `timeout`) → the platform shim rewrites to "
             "BSD equivalents or requires `coreutils`/`gnu-sed` (recorded in the install manifest).\n"
             "- **AD/internal tooling** (`netexec`, `bloodhound`, `windapsearch`, `responder`) → "
             "internal-recon pack only; disabled by default.\n")

    # ---- 3. risk classification -----------------------------------------
    levels = {0: [], 1: [], 2: [], "disabled": []}
    for n in notes:
        c = by_id[n.note_id]
        levels[c.risk_level].append((n.title, c))
    k = ["# Recon Bundle — Risk Classification\n", GEN_NOTE,
         "\nRisk levels follow the Hackbot risk model. A note's **highest-risk "
         "section governs** its level. Discovering an asset never authorizes testing "
         "it: ASN/CIDR/Shodan/cert/favicon/SPF/PTR/DNS-history are **hypothesis "
         "evidence only** and never auto-expand scope.\n"]
    titles = {0: "Level 0 — Passive (auto after scope init)",
              1: "Level 1 — Low-impact active (auto only if in-scope + allowed + rate-limited)",
              2: "Level 2 — Intrusive / high-volume (explicit approval each run)",
              "disabled": "Disabled by default — internal-recon (needs private-pentest/local-lab profile)"}
    for lvl in (0, 1, 2, "disabled"):
        k.append(f"\n## {titles[lvl]}\n")
        if not levels[lvl]:
            k.append("_(none)_")
            continue
        k.append("| Note | Skill | Approval | Excluded sections |")
        k.append("|---|---|---|---|")
        for title, c in levels[lvl]:
            k.append(f"| {esc(title)} | `{c.skill_target}` | {c.approval_level} | "
                     f"{', '.join(esc(s) for s in c.disabled_sections) or '—'} |")
    k.append("\n## Cross-cutting exclusions (never automated)\n"
             "- CDN/cloud origin-IP **bypass** (defeats a protection) — excluded.\n"
             "- Probing **IP ranges** inferred from ASN ownership — L2, and only for "
             "assets whose ownership + program scope are proven.\n"
             "- Shared CDN/cloud ranges not explicitly listed in scope — rejected.\n"
             "- Internal host/LDAP/Linux enumeration — disabled outside an authorized "
             "internal profile; an internal hostname/RFC1918/LDAP endpoint appearing in "
             "collected data does **not** enable them.\n")

    (DOCS / "recon-bundle-review.md").write_text("\n".join(r) + "\n", encoding="utf-8")
    (DOCS / "recon-bundle-macos-compatibility.md").write_text("\n".join(m) + "\n", encoding="utf-8")
    (DOCS / "recon-bundle-risk-classification.md").write_text("\n".join(k) + "\n", encoding="utf-8")


def main() -> int:
    notes = parse_bundle(BUNDLE)
    cls = classify_all(notes)
    build(notes, cls)
    print("wrote docs/recon-bundle-review.md")
    print("wrote docs/recon-bundle-macos-compatibility.md")
    print("wrote docs/recon-bundle-risk-classification.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
