# Recon Bundle — macOS / Portability Compatibility

> GENERATED from the immutable bundle via `scripts/generate_recon_docs.py`. The bundle is parsed as inert data; no command is executed. Source attribution: CyberNeon Recon Bundle (public source; no formal license).


Hackbot targets macOS **and** Linux. GNU-only and Linux-only commands from the bundle are adapted by a platform shim or routed to the optional Linux SSH runner; a few are excluded. Findings below are detected by `detect_portability()` over the captured command strings.


## Findings by note

| Note | Finding | Severity | Adaptation |
|---|---|---|---|
| asn & netblock enumeration | `xargs-parallel` | portable-ok | xargs -P works on both; enforce concurrency cap in adapter |
| descoberta de hosts numa rede interna | `proc-net-arp` | linux-only | no /proc on macOS; use `arp -an` (BSD) — Linux-runner only feature |
| descoberta de hosts numa rede interna | `p0f` | linux-oriented | p0f rarely packaged on macOS; Linux-runner or exclude |
| descoberta de hosts numa rede interna | `arp-scan` | linux-oriented | arp-scan needs libpcap+root; Linux-runner or `arp -an` |
| descoberta de hosts numa rede interna | `responder` | internal-tool | LLMNR/NBT poisoning; internal-recon pack only, never bug-bounty |
| enumeracao de diretorios | `gnu-timeout` | coreutils | macOS lacks `timeout` unless coreutils/gtimeout installed; adapter provides one |
| enumeracao ldap | `netexec` | internal-tool | AD/internal only; disabled in bug-bounty profile |
| enumeracao ldap | `ad-tooling` | internal-tool | Active Directory tooling; internal-recon pack only |
| enumeracao de rede em linux | `proc-net-arp` | linux-only | no /proc on macOS; use `arp -an` (BSD) — Linux-runner only feature |
| port scanning com bash e /dev/tcp | `bash-dev-tcp` | incompatible-zsh | zsh has no /dev/tcp; run under bash, or use `nc -z` / naabu adapter |
| port scanning com bash e /dev/tcp | `bash-dev-udp` | incompatible-zsh | no /dev/udp in zsh; use nmap -sU adapter (L2, approval) |
| port scanning com bash e /dev/tcp | `gnu-timeout` | coreutils | macOS lacks `timeout` unless coreutils/gtimeout installed; adapter provides one |
| port scanning com bash e /dev/tcp | `xargs-parallel` | portable-ok | xargs -P works on both; enforce concurrency cap in adapter |
| subdomain discovery | `gnu-timeout` | coreutils | macOS lacks `timeout` unless coreutils/gtimeout installed; adapter provides one |
| tcp fin fingerprint | `scapy` | needs-root+deps | raw sockets need root; prefer nmap; Linux-runner recommended |
| tcp fin fingerprint | `p0f` | linux-oriented | p0f rarely packaged on macOS; Linux-runner or exclude |

## Adaptation policy
- **`/dev/tcp`, `/dev/udp`** → not available in zsh; adapters use `nc -z`, `naabu`, or `nmap`. Bash-only snippets run under an explicit `bash -c` stage.
- **`/proc/net/arp`, `iproute2`, `arp-scan`, `p0f`, `scapy`** → Linux-only or root/pcap; available **only** through the optional Linux runner, never in the default macOS bug-bounty profile.
- **GNU flags** (`sed -r`, `grep -P`, `timeout`) → the platform shim rewrites to BSD equivalents or requires `coreutils`/`gnu-sed` (recorded in the install manifest).
- **AD/internal tooling** (`netexec`, `bloodhound`, `windapsearch`, `responder`) → internal-recon pack only; disabled by default.

