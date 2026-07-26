# bugbug — AI-assisted bug bounty research workstation

A **local, modular, auditable, safety-controlled** bug-bounty research workstation
for macOS **and** Linux, operated primarily through the Claude Code CLI with
multi-provider model support behind a local gateway. Primary command: `hackbot`.

> **Authorized use only.** Assets you own · explicitly authorized pentests ·
> in-scope bug-bounty assets · local labs / CTFs / research. Never for
> unauthorized scanning, persistence, evasion, DoS, phishing, or mass exploitation.
> See [`SECURITY.md`](./SECURITY.md) and [`CLAUDE.md`](./CLAUDE.md).

## Status

Early build; **800 automated tests passing** on **Python 3.14** (project minimum
3.11). Implemented and verified so far:
- **`hackbot` CLI** (`doctor`, `scope`, `secrets`, `program`, `risk`, `approval`,
  `tool`, `finding`, `skills`, `version`) — stdlib-only core, runs offline; installable as a wheel
  (`scripts/build_wheel.py` + `scripts/smoke_test.sh`, both fully offline).
- **Risk & approval engine** (`src/hackbot/risk/`) — deterministic, fail-closed
  L0–L3 policy gate and single-use, five-minute L2 approval lifecycle that every
  future tool adapter must pass. Exposed through the **non-executing** commands
  `hackbot risk evaluate`, `hackbot approval grant` (interactive TTY only), and
  `hackbot approval status`. See [`docs/risk-and-approval.md`](docs/risk-and-approval.md).
- **Tool execution substrate** (`src/hackbot/tools/`, `src/hackbot/audit/`) — a
  validated, gate-bound subprocess runner that executes a code-owned argv array
  (no shell, sanitized env, timeout, output caps) **only** after an `ALLOW`, plus
  a secret-free audit trail. Actions promoted from reviewed recon-bundle skills
  (with attribution): HTTP probes, DNS record lookups, TLS cert (L0),
  `net.port-scan` (nmap) and `web.dir-enum` (ffuf directory fuzzing) (L2,
  approval-gated). L2 needs `tool run --approve` (TTY, single-use); all in-scope
  only. Actions can run **locally or on a remote SSH host** (`--runner remote`,
  e.g. a Kali box with the full arsenal; the gate stays local — see
  [`docs/remote-runner.md`](docs/remote-runner.md)). Executed runs persist
  **redacted, run-linked evidence** (`src/hackbot/evidence/`) per engagement. See
  [`docs/tool-execution.md`](docs/tool-execution.md) and
  [`docs/skill-promotion.md`](docs/skill-promotion.md).
- **Findings & reporting** (`src/hackbot/findings/`, `src/hackbot/reporting/`) —
  typed findings that separate demonstrated from plausible impact and require
  reproducible evidence (`hackbot finding add/report/list`); per-platform markdown
  reports (`--platform generic|hackerone|bugcrowd|yeswehack|intigriti|immunefi`)
  reference redacted evidence, never raw output. See
  [`docs/findings-and-reporting.md`](docs/findings-and-reporting.md).
- **Diagnostic** available two ways: packaged Python (`hackbot doctor [--json]`,
  cross-platform, flags Python <3.11 as incompatible) and the pre-install shell
  script (`scripts/doctor.sh`).
- **Scope engine** (`src/hackbot/scope/`) — default-deny, deny-wins, frozen
  instances (no runtime expansion), IPv4/IPv6 CIDRs, segment-aware URL/path rules,
  redirect re-checking, shared-CDN/cloud rejection.
- **Secrets** (`src/hackbot/security/`) — native keychain via `keyring`
  (values never in argv/logs), case-insensitive aliases, existence-only disclosure.
- **Reference review** of 17 upstream projects total (including the PortSwigger MCP
  server) ([`docs/reference-review.md`](docs/reference-review.md),
  [`docs/licenses-and-attribution.md`](docs/licenses-and-attribution.md)).
- **Recon-bundle normalization** pipeline (parser → classifier → generated manifest
  + review docs) with a 20-test safety suite, plus a **publication guard**
  ([`docs/publication-guard.md`](docs/publication-guard.md)) that blocks pushing the
  unlicensed bundle and its derivatives.

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

## Requirements

- **Python ≥ 3.11** (developed/tested on 3.14). The CLI core has no third-party
  runtime deps and runs offline.
- macOS or Linux.

## Quick start (read-only; installs nothing system-wide)

```bash
# 1) diagnostic — pre-install shell version
scripts/doctor.sh                       # human-readable
scripts/doctor.sh --json                # machine-readable

# 2) build + install the CLI offline into a local venv, then use it
python3.11 -m venv .venv                # or any >=3.11 interpreter
.venv/bin/python scripts/build_wheel.py
.venv/bin/python -m pip install --no-index --no-deps dist/hackbot-*.whl
.venv/bin/hackbot doctor --json
.venv/bin/hackbot scope explain https://api.example.com/v1 --in example.com
.venv/bin/hackbot secrets list          # existence only; values never shown
.venv/bin/hackbot risk evaluate request.json --engagement engagements/sample --json
.venv/bin/hackbot approval status <challenge-id> --engagement engagements/sample --json
.venv/bin/hackbot tool run net.http-get request.json --engagement engagements/local-lab --json
```

## Recon bundle pipeline

```bash
.venv/bin/python scripts/generate_recon_bundle.py   # -> generated/recon-bundle/
.venv/bin/python scripts/generate_recon_docs.py     # -> docs/recon-bundle-*.md
.venv/bin/python -m pytest tests -q                 # full safety suite (815 tests)
```

## Documentation

- [`docs/risk-and-approval.md`](docs/risk-and-approval.md) — L0–L3 gate + L2 approval lifecycle
- [`docs/tool-execution.md`](docs/tool-execution.md) — gate-bound subprocess substrate + actions
- [`docs/skill-promotion.md`](docs/skill-promotion.md) — recon-bundle provenance + promoted skills
- [`docs/remote-runner.md`](docs/remote-runner.md) — run gated actions on a remote SSH host
- [`docs/findings-and-reporting.md`](docs/findings-and-reporting.md) — typed findings + markdown reports
- [`docs/next-steps.md`](docs/next-steps.md) — current status and the roadmap for the next phase
- [`docs/reference-review.md`](docs/reference-review.md) — upstream project analysis
- [`docs/licenses-and-attribution.md`](docs/licenses-and-attribution.md) — license ledger
- [`docs/recon-bundle-review.md`](docs/recon-bundle-review.md) — bundle inventory + classification
- [`docs/recon-bundle-risk-classification.md`](docs/recon-bundle-risk-classification.md)
- [`docs/recon-bundle-macos-compatibility.md`](docs/recon-bundle-macos-compatibility.md)
- `CLAUDE.md`, `SECURITY.md` — operating rules and safety model

Roadmap and architecture: `docs/architecture.md` (next).
