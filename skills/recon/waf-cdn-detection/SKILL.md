---
name: waf-cdn-detection
version: "1.0.0"
description: "Identify WAF, CDN, and reverse-proxy technologies in front of targets"
risk_level: L0
approval: auto
program_types: [web2, api]
source: "reviewed from reference repositories"
actions:
  - web.detect-waf
---

# WAF & CDN Detection

Code-owned actions defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `web.detect-waf` | wafw00f | Detect Web Application Firewall presence (L0) |

## Methodology

1. Identify WAF/CDN technology through response fingerprinting
2. Check for common headers: `Server`, `X-CDN`, `X-Cache`, `CF-Ray`
3. Determine if WAF bypass techniques may be needed

## Critical Warning

**Shared CDN/cloud ranges are rejected unless explicitly listed in scope.**
Do not attempt to bypass CDN protections merely to reach an origin server.
The CDN/origin distinction is a scope enforcement matter, not a challenge.
