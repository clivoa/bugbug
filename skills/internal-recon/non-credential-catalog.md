# Internal-recon: reviewed non-credential catalog (P5a)

**Status:** reviewed, code-owned, **disabled by default**. These actions load
only under a `private-pentest` or `local-lab` profile with explicit operator
confirmation (`src/hackbot/engagement_v2/recon_catalog.py`). Presence in code
never self-enables internal recon; a discovered internal hostname / RFC1918
address / LDAP endpoint never enables it. Credential and L3 categories are P5b.

Only a **reviewed generic single-tool argv subset** is promoted — never a copied
multi-tool bundle pipeline, never a shell string. Attribution:
`@reeshasx (CyberNeon Recon Bundle)`, local reuse with attribution, no
redistribution. The raw bundle HTML is never read.

## Actions

| Action | Category | Level | Capabilities | Tool (argv subset) |
|---|---|---|---|---|
| `operator.internal.netstate.interfaces` | local network state | L0 | — | `ip addr show` |
| `operator.internal.netstate.routes` | local network state | L0 | — | `ip route show` |
| `operator.internal.netstate.neighbors` | local network state | L1 | — | `ip neigh show` |
| `operator.internal.netstate.listeners` | local network state | L1 | — | `ss -tulpn` |
| `operator.internal.discovery.arp-sweep` | host discovery | L2 | automated-scanning | `nmap -sn -PR --max-rate {} --min-parallelism {} {subnet}` |
| `operator.internal.discovery.icmp-sweep` | host discovery | L2 | automated-scanning | `nmap -sn -PE --max-rate {} --min-parallelism {} {subnet}` |
| `operator.internal.enum.service-ports` | service enumeration | L2 | automated-scanning | `nmap -Pn -sV --top-ports {} --max-rate {} --min-parallelism {} {host}` |
| `operator.internal.ldap.naming-contexts` | anonymous LDAP | L2 | automated-scanning | `ldapsearch -x -LLL -H {endpoint} -s base -b {base_dn} namingContexts +` |
| `operator.internal.ldap.anonymous-users` | anonymous LDAP | L2 | automated-scanning | `ldapsearch -x -LLL -H {endpoint} -b {base_dn} (objectClass=organizationalPerson) cn` |

## Classification rules

- **Local network state** is read-only local inspection (interfaces, routes,
  neighbor cache, listening sockets) → L0/L1, no capability. It performs no active
  target interaction.
- **Host discovery** and **service enumeration** (nmap host discovery, version
  scan) are active and volume-bearing → L2 with `automated-scanning`, rate/
  parallelism bound by whole-token argv parameters.
- **Anonymous LDAP** is the **unauthenticated** naming-context / user-listing read
  → L2 with `automated-scanning`. Anything reading sensitive directory data or
  credential material (authenticated enumeration, ADCS, SPNs, AS-REP,
  Kerberoasting, LAPS/gMSA) is **excluded** and belongs to P5b (L3,
  `credential-access`/`sensitive-data-access`).

No action in this catalog declares `credential-access`, `credential-capture`,
`sensitive-data-access`, or any L3 capability — a disjointness test enforces it.

## Provenance

Every action maps to a `ReconProvenance` record (category, source skill,
classification, attribution) in `recon_catalog.provenance()`; a test asserts every
action has one and none maps to a credential/L3 source. Each action validates
against the P2 action-manifest contract (`validate_manifest`), so its
identifiers, executable, placeholders, rate control, and capabilities are
contract-checked.
