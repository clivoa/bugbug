---
name: subdomain-discovery
version: "1.0.0"
description: "DNS brute-force, permutation, and subdomain enumeration techniques"
risk_level: L1
approval: auto
program_types: [web2, api, cloud]
source: "reviewed from reference repositories"
actions:
  - recon.subfinder
  - recon.dnsx-brute
  - recon.alterx
methodology: subdomain-discovery.md
---

# Subdomain Discovery

**Full methodology:** [subdomain-discovery.md](subdomain-discovery.md)

Code-owned actions defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `recon.subfinder` | subfinder | Passive subdomain enumeration (L0) |
| `recon.dnsx-brute` | dnsx | DNS brute-force with wordlist (L1) |
| `recon.alterx` | alterx | Subdomain permutation generation (L0) |

## Key Rules

- Subdomain discovery is L1 — rate-limited, scope-checked
- Discovered subdomains must pass scope validation before active testing
- Max 10,000 subdomains by default (configurable per-engagement)
