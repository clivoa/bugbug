---
name: github-recon
version: "1.0.0"
description: "Source code discovery, secret scanning, organization enumeration via GitHub"
risk_level: L0
approval: auto
program_types: [web2, api, cloud, source-code, web3]
source: "reviewed from BugBountySkills, claude-bug-bounty"
actions:
  - source.secrets-gitleaks
  - source.secrets-trufflehog
---

# GitHub Reconnaissance

Code-owned actions defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `source.secrets-gitleaks` | gitleaks | Detect secrets in source code (L0, local) |
| `source.secrets-trufflehog` | trufflehog | Find and verify secrets in repositories (L0, local) |

## Methodology

1. Search for organization's public repositories
2. Scan for exposed secrets, API keys, and credentials
3. Review commit history for accidentally committed secrets
4. Check code for hardcoded endpoints and internal paths

## Key Rules

- GitHub data is association evidence only — never auto-scope
- Found secrets must be reported, never used
- Local analysis only — no authenticated GitHub API scraping without explicit authorization
