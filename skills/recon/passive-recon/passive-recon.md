# Passive Reconnaissance

**status:** active
**risk:** L0
**approval:** auto
**program_types:** [web2, api, mobile, cloud, source-code, web3]
**source:** reviewed from reference repositories  ()

## Objective

Map the target's external footprint without sending a single packet directly to target-owned infrastructure. All data comes from third-party sources, public archives, and certificate transparency logs.

## Methodology

### 1. Certificate Transparency
- Query crt.sh for subdomains: `https://crt.sh/?q=%25.{domain}&output=json`
- Query CertSpotter API for recent certificates
- Cross-reference SAN entries across certificates
- Flag wildcard certificates — they hide subdomains

### 2. DNS History & Passive DNS
- SecurityTrails (API) — historical DNS records
- DNSDumpster — free domain research
- ViewDNS.info — IP history, reverse IP, DNS records
- Flag recently changed records (potential infrastructure changes)

### 3. WHOIS & ASN Metadata
- WHOIS history via WhoisXML API or DomainTools
- BGP.HE.NET — ASN owner, announced prefixes, peers
- Identify organization's ASN and all announced netblocks
- Warning: ASN ownership is association evidence only — never auto-scope

### 4. Public Archives
- Wayback Machine (web.archive.org) — historical URLs, JS files, endpoints
- CommonCrawl index — broader historical coverage
- Archived robots.txt often reveals hidden paths
- Extract API endpoints from archived JS files

### 5. Search Engine Discovery
- Google dorking (site: operator, filetype:, inurl:, intitle:)
- GitHub code search — org: operator, API keys, config files
- Shodan — org: filter, SSL certificate search, favicon hash
- Censys — certificate search, host search by domain

### 6. DNS Record Inventory
- A, AAAA, CNAME, MX, NS, SOA, TXT, SPF, DMARC records
- Zone transfer attempt (AXFR) — rare but worth checking
- SPF records may reveal IP ranges and third-party services
- DMARC policy reveals email security maturity

## Detection Indicators

- Subdomains pointing to cloud services (potential takeovers)
- CNAME records pointing to unregistered services
- SPF records with overly broad includes
- Old certificates still valid for deprecated services
- Archived endpoints no longer present on the main site
- Staging/dev/internal hostnames in certificate transparency

## Output

- `passive-recon/subdomains.txt` — clean domain list
- `passive-recon/ip-addresses.txt` — resolved IPs
- `passive-recon/asn-netblocks.txt` — announced prefixes
- `passive-recon/urls-archived.txt` — Wayback/CommonCrawl URLs
- `passive-recon/third-party-services.txt` — cloud/SAAS dependencies
- `passive-recon/hypothesis-notes.md` — observations and leads

## Warnings

- ASN/cert/favicon/DNS-history associations are hypothesis evidence only
- Never add discovered assets to scope automatically
- Respect rate limits on crt.sh and other free services
- Wayback Machine CDX API has strict rate limits
