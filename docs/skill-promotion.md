# Recon-bundle skill promotion

The recon bundle (`references/recon/Recon-bundle.html`, author @reeshasx) is an
immutable, unlicensed reference. Its commands are **data** — never executed as
written. This phase promotes *reviewed* bundle skills into code-owned, gated
actions, recording provenance and attribution.

## What "promotion" means

- Only a **generic single-tool argv subset** of a reviewed skill becomes a
  code-owned `ActionDefinition` (e.g. `dig +short {target} TXT`). The bundle's
  multi-tool shell pipelines stay data.
- The raw HTML is **never** loaded; only the generated, normalized manifest
  (`generated/recon-bundle/manifest.yaml`) and notes are read.
- Every promoted action runs through the unchanged gate: scope check, risk level,
  and (for L2) explicit TTY approval. It executes only against in-scope targets.
- `internal-recon/*` skills are **never** promoted (disabled by default).
- These are **reconnaissance** (discovery) techniques, not exploitation. Nothing
  L3.

## Provenance and attribution

`src/hackbot/skills/promotion.py` maps each bundle-derived action to a
`SkillProvenance` (source skill, source note, the bundle's risk level, approval
level, and attribution `@reeshasx (CyberNeon Recon Bundle)`). A test validates
every entry against the generated manifest and asserts no `internal_pack` skill
is ever promoted. This satisfies the bundle's *local reuse with attribution, no
redistribution* terms and makes each promotion auditable.

## Promoted actions

| Action | Tool | Level | Reviewed skill |
|--------|------|-------|----------------|
| `tls.cert` | openssl | L0 | recon/tls-certificate-recon |
| `dns.lookup` | dig | L0 | recon/dns-recon |
| `dns.txt` / `dns.mx` / `dns.ns` | dig | L0 | recon/dns-recon |
| `net.http-get` / `-head` / `-options` | curl | L0 | recon/web-crawling |
| `net.port-scan` | nmap | **L2** | recon/service-fingerprinting |
| `web.dir-enum` | ffuf | **L2** | recon/parameter-discovery |

`net.port-scan` is the first active-recon (intrusive) promotion:
`nmap -Pn -T3 --top-ports 100 {target}`, `high_volume` → **L2**, so it requires
explicit TTY approval (`hackbot tool run net.port-scan REQUEST.json --engagement
DIR --approve`) and only runs against in-scope targets. It is registered only
when `nmap` resolves; **install nmap** to use it. Timing is polite (`-T3`), the
top 100 ports only, no aggressive scripts.

`web.dir-enum` is directory enumeration: `ffuf -s -u {target} -w <bundled
wordlist>`, where the operator's `{target}` is the full URL with the `FUZZ`
keyword (e.g. `http://host/FUZZ`). It is `high_volume` → **L2** → requires TTY
approval, runs only in-scope, and uses a small **code-owned bundled** wordlist
(`src/hackbot/tools/wordlists/web-content.txt`, packaged in the wheel). Install
ffuf to use it. Custom operator wordlists (a `{wordlist}` placeholder) are a later
increment.

`net.http-post` is a generic POST, not a bundle skill, so it carries no
provenance.

## Listing

```text
hackbot skills list [--json]
```

Lists every code-owned action, whether its tool is available on this host, and —
for bundle-derived actions — the source skill/note, the bundle risk level, the
approval level, and attribution.

## Boundary

Promoted skills are recon-only, code-owned single-tool argv subsets of reviewed
bundle skills, gated (scope + risk + approval), and attributed. `internal-recon`
and any L3/exploitation capability are excluded. Fuzzing/wordlist tools
(ffuf/gobuster) need an argv-placeholder extension and are a later increment.
