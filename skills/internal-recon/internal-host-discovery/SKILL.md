---
name: internal-host-discovery
version: "1.0.0"
description: "ARP/ICMP sweeps, local network enumeration — DISABLED BY DEFAULT"
risk_level: L1-L2
approval: "requires private-pentest or local-lab profile with explicit operator confirmation"
program_types: [private-pentest, local-lab]
source: "reviewed from internal-recon catalog"
disabled_by_default: true
profile_required: [private-pentest, local-lab]
actions:
  - operator.internal.discovery.arp-sweep
  - operator.internal.discovery.icmp-sweep
  - operator.internal.netstate.interfaces
  - operator.internal.netstate.routes
  - operator.internal.netstate.neighbors
  - operator.internal.netstate.listeners
catalog: non-credential-catalog.md
---

# Internal Host Discovery

**Code-owned catalog:** [../non-credential-catalog.md](../non-credential-catalog.md)

**⚠️ DISABLED BY DEFAULT.** This skill loads only under a `private-pentest`,
`local-lab`, or explicitly-authorized internal profile with explicit operator
confirmation.

A discovered internal hostname, RFC1918 address, or LDAP endpoint in collected
data does NOT enable this skill.

## Available Actions

| Action | Category | Level |
|--------|----------|-------|
| `operator.internal.netstate.interfaces` | local network state | L1 |
| `operator.internal.netstate.routes` | local network state | L1 |
| `operator.internal.netstate.neighbors` | local network state | L1 |
| `operator.internal.netstate.listeners` | local network state | L1 |
| `operator.internal.discovery.arp-sweep` | host discovery | L2 |
| `operator.internal.discovery.icmp-sweep` | host discovery | L2 |
