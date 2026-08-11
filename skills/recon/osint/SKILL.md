---
name: osint
version: "1.0.0"
description: "Open-source intelligence gathering — WHOIS, search engines, public databases"
risk_level: L0
approval: auto
program_types: [web2, api, mobile, cloud, source-code, web3, hybrid]
source: "reviewed from reference repositories"
actions:
  - recon.whois
---

# OSINT

Code-owned actions defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `recon.whois` | whois | WHOIS domain registration lookup (L0) |

## Methodology

1. WHOIS lookups on target domains
2. Google dorking (site:, filetype:, inurl:, intitle:)
3. Shodan searches for exposed services
4. Public database queries (SecurityTrails, ViewDNS, DNSDumpster)
5. Social media and professional network reconnaissance

## Key Rules

- OSINT is L0 — fully passive, no direct target contact
- All OSINT data is association evidence only — never auto-scope
- Shodan results must pass scope validation before active follow-up
