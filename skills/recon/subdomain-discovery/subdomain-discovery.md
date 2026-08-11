# Subdomain Discovery

**status:** active
**risk:** L0–L1
**approval:** L0 auto, L1 auto (with rate limits)
**program_types:** [web2, api, cloud]
**source:** reviewed from reference repositories 

## Objective

Enumerate subdomains using multiple independent sources. Cross-reference results to reduce false positives and prioritize high-value targets.

## Methodology

### Passive (L0) — Automatic
- Certificate transparency (crt.sh, CertSpotter, Facebook CT API)
- DNSDumpster, SecurityTrails, AlienVault OTX
- Chaos (ProjectDiscovery) — public dataset
- Shodan hostname search
- GitHub search for domain references
- CSP header parsing from known hosts

### Active (L1) — Automatic with rate limits
- DNS brute-force with curated wordlist
- DNS resolution of discovered names
- Wildcard detection (critical — avoid phantom subdomains)
- Zone transfer attempt (single try, then stop)
- HTTP probe on ports 80/443 to confirm live hosts

## Tools (code-owned adapters)

| Tool | Risk | Notes |
|------|------|-------|
| subfinder | L0 | Passive sources only |
| dnsx | L1 | DNS resolution, wildcard filter |
| httpx | L1 | HTTP probe, tech fingerprint |
| alterx | L1 | Permutation generation |

## Detection Indicators

- Wildcard DNS (*.example.com resolves to same IP) — invalidates brute-force
- High-count subdomains on non-production services (staging, dev, test)
- Internal hostnames leaking via cert transparency (ldap, vpn, admin, internal)
- Recently created subdomains (potential new attack surface)
- Subdomains pointing to decommissioned cloud services

## Output

- `subdomain-discovery/all-subdomains.txt` — deduplicated
- `subdomain-discovery/live-hosts.txt` — HTTP-responding hosts
- `subdomain-discovery/wildcard-detected.txt` — wildcard IP for exclusion
- `subdomain-discovery/sources-manifest.yaml` — which tool found each name

## Stop Conditions

- Wildcard DNS confirmed: pause brute-force, flag for manual review
- Rate-limiting detected: back off, reduce concurrency
- >10,000 subdomains discovered: flag for scoping review
