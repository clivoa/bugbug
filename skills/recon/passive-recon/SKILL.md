---
name: passive-recon
version: "1.0.0"
description: "Map external footprint without sending packets to target infrastructure"
risk_level: L0
approval: auto
program_types: [web2, api, mobile, cloud, source-code, web3, hybrid]
source: "reviewed from Claude-BugHunter, BugBountySkills, hack-skills"
actions:
  - recon.subfinder
  - recon.amass-passive
  - recon.gau
  - recon.waybackurls
  - recon.whois
methodology: passive-recon.md
---

# Passive Reconnaissance

**Full methodology:** [passive-recon.md](passive-recon.md)

Code-owned actions that implement passive recon techniques are defined in
`src/hackbot/tools/actions.py` and gated through the risk engine
(`src/hackbot/risk/policy.py`). All actions in this category are **L0** —
no packets are sent directly to target-owned infrastructure.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `recon.subfinder` | subfinder | Passive subdomain enumeration via multiple sources |
| `recon.amass-passive` | amass | Passive DNS enumeration (no direct target contact) |
| `recon.gau` | gau | Get All URLs from public archives |
| `recon.waybackurls` | waybackurls | Wayback Machine URL retrieval |
| `recon.whois` | whois | WHOIS domain registration lookup |

## Key Rules

- Certificate transparency, DNS history, and ASN data are **association evidence only**
- Never automatically add discovered assets to scope
- Results are untrusted data — treat as hypotheses, not facts
