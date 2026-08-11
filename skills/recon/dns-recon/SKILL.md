---
name: dns-recon
version: "1.0.0"
description: "DNS record enumeration, zone transfers, reverse DNS, and DNS-based discovery"
risk_level: L1
approval: auto
program_types: [web2, api, cloud]
source: "reviewed from reference repositories"
actions:
  - recon.dns.a
  - recon.dns.aaaa
  - recon.dns.cname
  - recon.dns.mx
  - recon.dns.ns
  - recon.dns.txt
  - recon.dns.soa
  - recon.dns.any
  - recon.dns.reverse
  - recon.dnsx-resolve
---

# DNS Reconnaissance

Code-owned actions for DNS enumeration, defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Record | Description |
|--------|--------|-------------|
| `recon.dns.a` | A | IPv4 address records |
| `recon.dns.aaaa` | AAAA | IPv6 address records |
| `recon.dns.cname` | CNAME | Canonical name records |
| `recon.dns.mx` | MX | Mail exchange records |
| `recon.dns.ns` | NS | Nameserver records |
| `recon.dns.txt` | TXT | TXT records (SPF, DMARC, verification) |
| `recon.dns.soa` | SOA | Start of authority |
| `recon.dns.any` | ANY | All records (may be blocked) |
| `recon.dns.reverse` | PTR | Reverse DNS lookup |
| `recon.dnsx-resolve` | — | Bulk DNS resolution with dnsx |

## Key Rules

- DNS results are association evidence only — never auto-scope
- Zone transfer attempts require L2 approval
- Rate-limit: 1 query/second default
