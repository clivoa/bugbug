---
name: tls-certificate-recon
version: "1.0.0"
description: "Certificate transparency, TLS handshake analysis, cipher enumeration"
risk_level: L0-L1
approval: "L0 auto, L1 auto"
program_types: [web2, api, cloud]
source: "reviewed from reference repositories"
actions:
  - recon.tls.cert
  - recon.tls.ciphers
  - recon.tls-full
---

# TLS Certificate Reconnaissance

Code-owned actions for TLS/certificate analysis, defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `recon.tls.cert` | openssl | Retrieve and display TLS certificate (L0) |
| `recon.tls.ciphers` | openssl | Enumerate supported TLS ciphers (L1) |
| `recon.tls-full` | testssl | Full TLS/SSL configuration audit (L1, remote) |

## Methodology

- Extract SAN entries from certificates for subdomain discovery
- Flag wildcard certificates — they hide subdomains
- Check certificate expiration and issuer
- Certificate data is association evidence only — never auto-scope
