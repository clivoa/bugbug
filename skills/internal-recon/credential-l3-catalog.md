# Internal-recon: reviewed credential/L3 catalog (P5b)

**Status:** code-owned, L3, disabled by default. The catalog is inert unless a
`private-pentest` or `local-lab` profile is active **and** internal recon was
explicitly confirmed. Every action still requires confirmed engagement
authority, an in-scope target, and every declared `testing_rules` capability.

This note records a reviewed single-action subset inspired by the CyberNeon
Recon Bundle (local reuse, no redistribution). It does not execute or
parse the raw bundle and does not reproduce any multi-tool pipeline. Shells,
inline evaluation, command strings, DoS, destruction, bulk exfiltration, and
evasion are excluded.

## Reviewed actions

| Action(s) | Classification | Exact capabilities | Executable / reviewed argv shape |
|---|---|---|---|
| `operator.internal.directory.policies`, `.spns` | authenticated directory enumeration | `authenticated-testing`, `sensitive-data-access` | `/usr/bin/ldapsearch`; GSSAPI, one scoped LDAP endpoint, fixed attributes/filter |
| `operator.internal.directory.adcs` | authenticated ADCS enumeration | `authenticated-testing`, `sensitive-data-access` | `/usr/local/bin/certipy find`; one scoped host, JSON output in private CWD |
| `operator.internal.directory.graph` | bounded AD graph collection | `authenticated-testing`, `sensitive-data-access` | `/usr/local/bin/bloodhound-python`; closed collection enum, one scoped DC |
| `operator.internal.credential.asrep`, `.kerberoast` | credential material access | `credential-access`, `sensitive-data-access` | fixed Impacket request mode against one scoped host; metadata-only evidence |
| `operator.internal.credential.laps`, `.gmsa` | authorized directory secret read | `credential-access`, `sensitive-data-access` | `/usr/local/bin/nxc ldap`; credential reference transported by protected file |
| `operator.internal.validation.password-spray` | bounded credential validation | `credential-capture`, `automated-scanning`, `state-changing` | `/usr/local/bin/nxc smb`; one scoped host, protected candidate file, native rate adapter |
| `operator.internal.responder.analyze` | analyze-only | `authenticated-testing`, `sensitive-data-access` | code-owned Responder adapter, analyze mode, one scoped subnet |
| `operator.internal.responder.capture` | credential capture / poisoning | `credential-capture`, `state-changing` | code-owned Responder adapter, explicit poison/capture mode, one scoped subnet |
| `operator.internal.exploit.verify` | exploit verification | `exploit-execution` | code-owned adapter, single scoped target and minimal proof |
| `operator.internal.payload.verify` | payload/post-exploitation | `payload-execution`, `state-changing` | code-owned adapter, single scoped target and minimal proof |
| `operator.internal.lateral.verify` | lateral movement | `lateral-movement`, `credential-access` | `/usr/bin/ssh`; `BatchMode=yes`, one scoped host, fixed `/usr/bin/true` proof |
| `operator.internal.persistence.verify` | controlled persistence | `persistence`, `state-changing` | code-owned adapter, one scoped host, install/remove test marker workflow |

All argv placeholders occupy a whole token. Target-shaped values use
`{target:...}` and therefore pass P2 scope binding. Every action declares a
code-owned native rate adapter, including tools whose native CLI has no adequate
rate flag. Credential-bearing actions declare `metadata-only`; the closed native
structured schemas accept only bounded counts/names/metadata and reject bytes or
unknown fields.

## Capture is not analyze

The analyze and capture responder actions are deliberately separate. Analyze
does not declare `credential-capture`. Capture is always L3, declares
`credential-capture` and `state-changing`, and is labeled capture/poisoning/
third-party — never passive or discovery.

## Exercise boundary

CI validates only manifest data, policy decisions, provenance, and synthetic
fixtures. It imports no credential/exploit tool and performs no live network
operation. A real end-to-end exercise is permitted only in an operator-owned,
isolated, disposable lab with explicit authority and cleanup verification.
