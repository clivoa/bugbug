---
name: parameter-discovery
version: "1.0.0"
description: "Discover hidden HTTP parameters via arjun and manual techniques"
risk_level: L1
approval: auto
program_types: [web2, api]
source: "reviewed from BugBountySkills"
actions:
  - web.param-discover
---

# Parameter Discovery

Code-owned actions defined in `src/hackbot/tools/actions.py`.

## Available Actions

| Action | Tool | Description |
|--------|------|-------------|
| `web.param-discover` | arjun | HTTP parameter discovery (L1) |

## Methodology

1. Use arjun to brute-force hidden GET/POST parameters
2. Extract parameters from JavaScript files and HTML comments
3. Test discovered parameters with safe reflection markers
4. Flag parameters that affect server behavior for further testing

## Key Rules

- Parameter discovery is L1 — rate-limited, scope-checked
- Discovered parameters that affect stored state require L2 approval to test
