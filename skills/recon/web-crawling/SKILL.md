---
name: web-crawling
version: "1.0.0"
description: "Safe, scope-respecting web crawling for endpoint and parameter discovery"
risk_level: L1
approval: auto
program_types: [web2, api]
source: "reviewed from reference repositories"
actions:
  - recon.katana-crawl
  - recon.httpx-probe
---

# Web Crawling

Code-owned actions defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `recon.katana-crawl` | katana | Web crawler with JS rendering (L1) |
| `recon.httpx-probe` | httpx | HTTP probe with tech detection (L1) |

## Key Rules

- Crawling is L1 — rate-limited, scope-checked
- Must respect robots.txt and sitemap.xml (katana flag: `-kf robotstxt,sitemapxml`)
- Redirects outside scope are blocked automatically
- Never follow links to out-of-scope domains
