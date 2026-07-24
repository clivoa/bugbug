# Recon Bundle — Risk Classification

> GENERATED from the immutable bundle via `scripts/generate_recon_docs.py`. The bundle is parsed as inert data; no command is executed. Source attribution: @reeshasx (CyberNeon Recon Bundle).


Risk levels follow the Hackbot risk model. A note's **highest-risk section governs** its level. Discovering an asset never authorizes testing it: ASN/CIDR/Shodan/cert/favicon/SPF/PTR/DNS-history are **hypothesis evidence only** and never auto-expand scope.


## Level 0 — Passive (auto after scope init)

| Note | Skill | Approval | Excluded sections |
|---|---|---|---|
| consulta de certificado tls | `recon/tls-certificate-recon` | none | — |
| github recon & leaked secrets | `recon/github-recon` | none | — |
| google dorking | `recon/osint` | none | — |
| ferramentas de osint | `recon/osint` | none | — |

## Level 1 — Low-impact active (auto only if in-scope + allowed + rate-limited)

| Note | Skill | Approval | Excluded sections |
|---|---|---|---|
| consulta de dns | `recon/dns-recon` | auto-if-in-scope | — |
| js analysis & secrets extraction | `recon/javascript-analysis` | auto-if-in-scope | — |
| recon pipeline completo | `recon/recon-pipeline` | auto-if-in-scope | — |
| subdomain discovery | `recon/subdomain-discovery` | auto-if-in-scope | — |
| waf & cdn detection | `recon/waf-cdn-detection` | auto-if-in-scope | origin ip discovery (bypass do cdn), bypass via host header |
| web crawling & js analysis | `recon/web-crawling` | auto-if-in-scope | — |

## Level 2 — Intrusive / high-volume (explicit approval each run)

| Note | Skill | Approval | Excluded sections |
|---|---|---|---|
| asn & netblock enumeration | `recon/asn-netblock-analysis` | explicit | 5. cloud & cdn (cuidado com escopo), scan nos ranges descobertos |
| banner scanning | `recon/service-fingerprinting` | explicit | — |
| enumeracao de diretorios | `recon/parameter-discovery` | explicit | — |
| fuzzing de parametros & api discovery | `recon/parameter-discovery` | explicit | — |
| port scanning com bash e /dev/tcp | `recon/service-fingerprinting` | explicit | — |
| tcp fin fingerprint | `recon/service-fingerprinting` | explicit | — |

## Disabled by default — internal-recon (needs private-pentest/local-lab profile)

| Note | Skill | Approval | Excluded sections |
|---|---|---|---|
| descoberta de hosts numa rede interna | `internal-recon/internal-host-discovery` | forbidden-by-default | — |
| enumeracao ldap | `internal-recon/ldap-enumeration` | forbidden-by-default | — |
| enumeracao de rede em linux | `internal-recon/linux-enumeration` | forbidden-by-default | — |

## Cross-cutting exclusions (never automated)
- CDN/cloud origin-IP **bypass** (defeats a protection) — excluded.
- Probing **IP ranges** inferred from ASN ownership — L2, and only for assets whose ownership + program scope are proven.
- Shared CDN/cloud ranges not explicitly listed in scope — rejected.
- Internal host/LDAP/Linux enumeration — disabled outside an authorized internal profile; an internal hostname/RFC1918/LDAP endpoint appearing in collected data does **not** enable them.

