---
name: recon-router
version: "1.0.0"
description: "Master router that selects appropriate recon skills based on program profile and surface"
risk_level: L0-L1
approval: "L0 auto, L1 auto"
program_types: [web2, api, mobile, cloud, source-code, ai-llm, web3, hybrid]
source: "original design"
actions:
  - net.http-get
  - net.http-head
  - net.http-headers
---

# Recon Router

The recon router is the master entry point for reconnaissance. It selects
appropriate recon skills based on:

1. **Program type** (web2, api, cloud, mobile, web3, etc.)
2. **Attack surface classification**
3. **Scope constraints**
4. **Authorization level**
5. **Model routing preferences**

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `net.http-get` | curl | HTTP GET request (L0) |
| `net.http-head` | curl | HTTP HEAD request (L0) |
| `net.http-headers` | curl | HTTP headers retrieval (L0) |

## Routing Logic

- **web2** → passive-recon, dns-recon, tls-certificate-recon, subdomain-discovery, web-crawling, waf-cdn-detection
- **api** → passive-recon, dns-recon, parameter-discovery, javascript-analysis
- **cloud** → asn-netblock-analysis, dns-recon, service-fingerprinting
- **source-code** → github-recon, osint
- **mobile** → passive-recon, osint, javascript-analysis
- **web3** → github-recon, osint
