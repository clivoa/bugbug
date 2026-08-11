---
name: linux-enumeration
version: "1.0.0"
description: "Local Linux host enumeration after gaining access — DISABLED BY DEFAULT"
risk_level: L3
approval: "requires private-pentest or local-lab profile with explicit operator confirmation"
program_types: [private-pentest, local-lab]
source: "reviewed from reference repositories"
disabled_by_default: true
profile_required: [private-pentest, local-lab]
actions: []
---

# Linux Host Enumeration

**⚠️ DISABLED BY DEFAULT.** L3 actions requiring explicit operator confirmation
under a private-pentest or local-lab profile.

Linux enumeration actions are defined in the L3 catalog
(`src/hackbot/engagement_v2/l3_catalog.py`) and require:
- Confirmed authorization
- Asset in code-checked scope
- Every exact capability flag Boolean `true`
- Explicit operator confirmation

See [../credential-l3-catalog.md](../credential-l3-catalog.md) for the full
L3 credential catalog.
