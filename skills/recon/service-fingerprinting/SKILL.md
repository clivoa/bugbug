---
name: service-fingerprinting
version: "1.0.0"
description: "Technology stack detection, HTTP response fingerprinting, server identification"
risk_level: L0-L1
approval: "L0 auto, L1 auto"
program_types: [web2, api, cloud]
source: "reviewed from reference repositories"
actions:
  - recon.httpx-probe
  - web.scan-nuclei-tech
---

# Service Fingerprinting

Code-owned actions defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `recon.httpx-probe` | httpx | HTTP probe with technology detection (L1) |
| `web.scan-nuclei-tech` | nuclei | Technology stack detection templates (L0) |

## Methodology

1. Identify web server, framework, and technology stack
2. Fingerprint exposed services on common ports
3. Map technology to known vulnerability surfaces
4. Feed fingerprinting results into attack surface classification
