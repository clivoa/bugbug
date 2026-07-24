# bugbug — AI-assisted bug bounty research workstation

A **local, modular, auditable, safety-controlled** bug-bounty research workstation
for macOS **and** Linux, operated primarily through the Claude Code CLI with
multi-provider model support behind a local gateway. Primary command: `hackbot`.

> **Authorized use only.** Assets you own · explicitly authorized pentests ·
> in-scope bug-bounty assets · local labs / CTFs / research. Never for
> unauthorized scanning, persistence, evasion, DoS, phishing, or mass exploitation.
> See [`SECURITY.md`](./SECURITY.md) and [`CLAUDE.md`](./CLAUDE.md).

## Status

Early build. Implemented and tested so far:
- Cross-platform read-only diagnostic (`scripts/doctor.sh`, macOS + Linux).
- Reference review of 17 upstream projects + PortSwigger MCP
  ([`docs/reference-review.md`](docs/reference-review.md),
  [`docs/licenses-and-attribution.md`](docs/licenses-and-attribution.md)).
- Recon-bundle normalization pipeline (parser → classifier → generated manifest +
  review docs), with a 20-test safety suite. See below.

## Design principles

- **Scope enforced in code** (default-deny, deny-wins), not by the model.
- **Four-level risk model** (L0 passive → L3 prohibited); L2 needs explicit approval.
- **Discovery ≠ authorization** — ASN/cert/Shodan/etc. are hypotheses, never scope.
- **Secrets in the OS keychain**, never in files/args/logs.
- **Untrusted target content** — treated as data, never instructions.
- **Loopback-only** gateway and Burp MCP.
- **OS-agnostic** with a Darwin/Linux focus; an optional Linux SSH runner handles
  Linux-only / GPU tooling under an authorized profile.

## Layout

```
config/      YAML policy (providers, routing, tool/risk policy, reporting)
src/hackbot/ engine (cli, providers, gateway, scope, programs, workflows,
             tools, mcp, skills, evidence, findings, reporting, audit, security)
skills/      Agent-Skills packs (recon, internal-recon [disabled], web, api, ...)
templates/   platform report templates (hackerone, bugcrowd, ...)
engagements/ per-engagement state (git-ignored; only sanitized samples tracked)
labs/        local vulnerable labs (Juice Shop, crAPI, ...)
scripts/     bootstrap / install / doctor / generators
docs/        architecture, threat model, guides, reviews
generated/   normalized (reviewed) layer built from immutable references
references/  immutable source material (recon bundle; external clones git-ignored)
```

## Quick start (diagnostic only — installs nothing)

```bash
scripts/doctor.sh            # human-readable environment report
scripts/doctor.sh --json     # machine-readable
```

## Recon bundle pipeline

```bash
PYTHONPATH=src python3 scripts/generate_recon_bundle.py   # -> generated/recon-bundle/
PYTHONPATH=src python3 scripts/generate_recon_docs.py     # -> docs/recon-bundle-*.md
.venv/bin/pytest tests/recon_bundle -q                    # safety tests
```

## Documentation

- [`docs/reference-review.md`](docs/reference-review.md) — upstream project analysis
- [`docs/licenses-and-attribution.md`](docs/licenses-and-attribution.md) — license ledger
- [`docs/recon-bundle-review.md`](docs/recon-bundle-review.md) — bundle inventory + classification
- [`docs/recon-bundle-risk-classification.md`](docs/recon-bundle-risk-classification.md)
- [`docs/recon-bundle-macos-compatibility.md`](docs/recon-bundle-macos-compatibility.md)
- `CLAUDE.md`, `SECURITY.md` — operating rules and safety model

Roadmap and architecture: `docs/architecture.md` (next).
