---
name: recon-pipeline
version: "1.0.0"
description: "End-to-end reconnaissance pipeline orchestration with scope enforcement"
risk_level: L0-L1
approval: "L0 auto, L1 auto"
program_types: [web2, api, cloud]
source: "original design"
actions: []
---

# Recon Pipeline

The recon pipeline orchestrates multiple recon skills in sequence, with
scope enforcement at every step. Each stage feeds the next:

```
1. Passive Recon (L0)
   ├── Certificate transparency
   ├── Passive DNS
   ├── WHOIS / ASN
   └── Public archives
         │
2. DNS Recon (L1)
   ├── Record enumeration
   └── Zone transfer attempt (L2)
         │
3. Subdomain Discovery (L1)
   ├── Brute-force
   └── Permutation
         │
4. Service Fingerprinting (L1)
   ├── HTTP probe
   └── Technology detection
         │
5. Web Crawling (L1)
   ├── Endpoint discovery
   └── Parameter extraction
         │
6. Attack Surface Classification
   └── Feed into hypothesis generation
```

## Key Rules

- Each stage's output is scope-checked before feeding the next
- The pipeline does NOT automatically progress to intrusive validation
- ASN/CIDR/cert/DNS data is hypothesis evidence only — never auto-scope
- Shared CDN/cloud ranges are rejected unless explicitly in scope
