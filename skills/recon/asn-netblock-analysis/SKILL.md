---
name: asn-netblock-analysis
version: "1.0.0"
description: "ASN ownership mapping, netblock enumeration, BGP data analysis"
risk_level: L0-L1
approval: "L0 auto, L1 auto"
program_types: [web2, api, cloud]
source: "reviewed from reference repositories"
actions:
  - recon.amass-intel
---

# ASN & Netblock Analysis

Code-owned actions defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `recon.amass-intel` | amass | ASN intel gathering and netblock enumeration (L1) |

## Methodology

1. Use BGP.HE.NET to identify organization ASNs and announced prefixes
2. Cross-reference with WHOIS data for ownership verification
3. Map netblocks to identify potential attack surface

## Critical Warning

**ASN ownership is association evidence only — NEVER auto-scope.**
CIDR ranges discovered through ASN analysis must be explicitly confirmed
as in-scope before any active testing. Shared cloud/CDN ranges are rejected
unless explicitly listed in scope.
