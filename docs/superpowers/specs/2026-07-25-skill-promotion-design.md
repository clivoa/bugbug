# Recon-bundle skill promotion — design

**Status:** approved (2026-07-25)

**Goal:** Promote reviewed recon-bundle skills into code-owned, gated actions —
including a real active-recon skill for bug-bounty scenarios — with recorded
provenance and attribution, so an operator can run real recon skills through the
existing safety gate.

**Safety boundary (non-negotiable):**
- Every promoted action still passes the gate: scope check + risk level + (for
  L2) explicit TTY approval. It runs only against in-scope targets.
- The bundle is **reconnaissance** (discovery), not exploitation. No exploit
  payloads, no DoS, no mass targeting, nothing L3.
- `internal-recon/*` skills are **never** promoted (disabled by default).
- The raw bundle HTML is never loaded; only the generated manifest/notes are read
  (as data). Bundle commands stay data; only generic single-tool argv subsets
  become code-owned actions.
- Attribution to `@reeshasx (CyberNeon Recon Bundle)` is recorded for every
  bundle-derived action (local reuse with attribution; no redistribution of the
  bundle's creative content).

## Context

`generated/recon-bundle/manifest.yaml` maps each reviewed skill → source note,
`risk_level`, `approval_level`, `internal_pack`, attribution. Existing code-owned
actions (`tls.cert`, `dns.lookup`, `net.http-*`) already derive from reviewed
skills but record no provenance. `curl`/`dig`/`openssl` resolve on this host;
`nmap` does not (so the port-scan action registers conditionally and its e2e test
skips here).

## Architecture

### 1. Provenance — `src/hackbot/skills/promotion.py`

```python
@dataclass(frozen=True, slots=True)
class SkillProvenance:
    skill_id: str  # e.g. "recon/dns-recon"
    source_note: str  # e.g. "note-consulta-dns"
    bundle_risk_level: str  # "0".."2"
    approval_level: str  # "none" | "auto-if-in-scope" | "explicit"
    attribution: str  # "@reeshasx (CyberNeon Recon Bundle) — https://x.com/reeshasx"


PROMOTED_ACTIONS: dict[str, SkillProvenance]  # action_id -> provenance
```

Covers every bundle-derived action (existing + new). A test validates that each
`skill_id`/`source_note` exists in the generated manifest and that **no**
`internal_pack` skill is referenced.

### 2. Promoted actions — `src/hackbot/tools/actions.py`

New code-owned actions (each in `REAL_ACTIONS` with provenance), single-tool,
`{target}` whole-token, gated:

- **L0 passive** (from `recon/dns-recon`, dig): `dns.txt`, `dns.mx`, `dns.ns` —
  `(dig, "+short", "{target}", "<TYPE>")`. Narrow, passive record lookups.
- **L2 intrusive** (from `recon/service-fingerprinting`, nmap): `net.port-scan` —
  `(nmap, "-Pn", "-T3", "--top-ports", "100", "{target}")`. `high_volume=True` →
  L2 floor → requires explicit TTY approval; runs only in-scope. Registered only
  when nmap resolves; polite timing, top-100 ports, no aggressive scripts.

Add `nmap_path()` beside the existing tool resolvers.

### 3. CLI — `hackbot skills list [--json]`

Stdlib-only. Lists each code-owned action; for bundle-derived actions shows the
source skill, note, bundle risk level, approval level, and attribution;
non-bundle actions are marked as such.

## Error handling

- Gate unchanged: no `ALLOW` → no execution; L2 → TTY approval; out-of-scope →
  `DENY_SCOPE`.
- Unknown/absent tool → the action is simply not registered (CLI reports it
  unavailable). No traceback.

## Testing strategy (test-first)

- **provenance/manifest**: every `PROMOTED_ACTIONS` entry references a skill and
  source note present in the manifest; no promoted action maps to an
  `internal_pack` skill; every bundle-derived registered action has provenance.
- **DNS record actions**: registry shape (L0, dig-backed, argv ends with the
  record type after `{target}`); end-to-end `dig +short 127.0.0.1 TXT` runs and
  captures evidence (in-scope via CIDR).
- **port-scan**: registry shape (L2 floor, `high_volume`, nmap-backed) when nmap
  resolves; L2 requires approval (no execution without a grant); e2e against the
  loopback lab skips when nmap is absent.
- **CLI `skills list`**: shows attribution and promotion status for a
  bundle-derived action; marks a non-bundle action.
- **Regression**: full suite, Ruff, format, mypy, offline smoke (`skills --help`).

## Boundary

Promoted skills are recon-only, code-owned single-tool argv subsets of reviewed
bundle skills, gated (scope + risk + approval), attributed to `@reeshasx`, and
never include `internal-recon` or any L3/exploitation capability. Fuzzing/wordlist
tools (ffuf/gobuster) need an argv-placeholder extension and are a separate,
later increment.
