---
name: ldap-enumeration
version: "1.0.0"
description: "Anonymous and authenticated LDAP directory enumeration — DISABLED BY DEFAULT"
risk_level: L2-L3
approval: "requires private-pentest or local-lab profile with explicit operator confirmation"
program_types: [private-pentest, local-lab]
source: "reviewed from L3 credential catalog"
disabled_by_default: true
profile_required: [private-pentest, local-lab]
actions:
  - operator.internal.ldap.naming-contexts
  - operator.internal.ldap.anonymous-users
  - internal.ldapsearch
catalog: non-credential-catalog.md
---

# LDAP Enumeration

**Code-owned catalogs:**
- [../non-credential-catalog.md](../non-credential-catalog.md) — anonymous LDAP (P5a)
- [../credential-l3-catalog.md](../credential-l3-catalog.md) — authenticated LDAP (P5b)

**⚠️ DISABLED BY DEFAULT.** Requires explicit authorization and profile.

## Available Actions

| Action | Category | Level |
|--------|----------|-------|
| `operator.internal.ldap.naming-contexts` | anonymous LDAP | L2 |
| `operator.internal.ldap.anonymous-users` | anonymous LDAP | L2 |
| `internal.ldapsearch` | authenticated LDAP | L3 |
