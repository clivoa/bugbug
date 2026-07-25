# Platform report renderers — design

**Status:** approved (2026-07-25)

**Goal:** Render a finding into each supported bug-bounty platform's submission
format, structured around the vulnerability scenario (weakness type, steps,
demonstrated vs plausible impact), for **authorized** reporting of findings that
already have reproducible evidence.

**Scope note:** This is *reporting* of demonstrated findings, not attack
generation. "Scenarios/attacks" enter only as vulnerability classes in the report
structure and as test fixtures describing already-demonstrated findings.

**Non-goals:** No external `.tmpl` template engine (renderers are code-owned), no
CVSS scoring, no auto-submission/upload, no changes to `hackbot.risk`/`tools`/
`evidence`.

## Context

`hackbot.findings.Finding` and `FindingStore` exist; `hackbot.reporting.render`
has `render_markdown` (the generic report). `hackbot finding report` prints the
generic markdown. `templates/{generic,hackerone,bugcrowd,yeswehack,intigriti,
immunefi}/` are empty placeholders. CLAUDE.md rule 10 requires separating
demonstrated from plausible impact and reproducible evidence for claims.

## Architecture

### 1. Extend `Finding` (additive, optional, backward-compatible)

Add two fields with defaults so the report can name the vulnerability scenario:

- `vulnerability_type: str = ""` — the weakness class (e.g. `reflected-xss`,
  `sqli`, `ssrf`, `idor`, `auth-bypass`, `rce`); bounded (≤128), may be empty.
- `reproduction_steps: str = ""` — steps to reproduce; bounded (≤8192), may be
  empty.

`FindingStore` `_to_dict`/`_from_dict` carry them; the CLI descriptor treats them
as optional (default `""`). A `demonstrated` finding still requires evidence and
`demonstrated_impact`.

### 2. Platform renderers — `src/hackbot/reporting/render.py`

Data-driven, code-owned. A `_PlatformSpec` names each platform's section
headings; a single `_render_finding(finding, spec)` walks them, always keeping
**Demonstrated impact** and **Plausible additional impact (untested)** as two
separate sections (rule 10) and referencing evidence by `run_id` (never raw
output). Sections per finding: weakness/type, summary, steps to reproduce
(falls back to an evidence pointer when empty), demonstrated impact, plausible
impact, evidence reference.

```python
PLATFORMS = ("generic", "hackerone", "bugcrowd", "yeswehack", "intigriti", "immunefi")

def render(findings, *, engagement_id: str, platform: str = "generic") -> str: ...
```

- `render_markdown(findings, *, engagement_id)` stays as a thin wrapper for
  `platform="generic"`; the generic spec reproduces the current output (the
  existing `test_render.py` assertions keep passing).
- Each platform spec uses that platform's conventional headings (HackerOne:
  Summary / Steps To Reproduce / Impact; Bugcrowd: Description / Steps to
  reproduce / Impact; Immunefi: Summary / Proof of Concept / Impact; etc.).
- An unknown platform raises `ValueError` (the CLI maps it to exit 2).

### 3. CLI

`hackbot finding report --engagement DIR [--platform NAME]` (default `generic`,
preserving current behavior). `NAME` ∈ `PLATFORMS`; an unknown platform → exit 2.

## Error handling

- Unknown platform → exit 2.
- Reports never embed raw output; they reference `evidence_run_id`. Findings and
  reports stay local under git-ignored `engagements/**`.
- Demonstrated and plausible impact never merge.

## Testing strategy (test-first)

- **model/store**: the two new fields round-trip; a descriptor may omit them
  (default `""`); a demonstrated finding still needs evidence.
- **renderers across vulnerability scenarios**: fixtures for several classes
  (reflected-xss, sqli, ssrf, idor, auth-bypass, rce) rendered on **every**
  platform assert the platform's section headings, the demonstrated/plausible
  split, the `vulnerability_type` and `reproduction_steps` appearing, the
  evidence `run_id` reference, and that no raw output appears.
- **CLI**: `finding report --platform hackerone|bugcrowd|…` selects the renderer;
  an unknown `--platform` → exit 2; default stays generic.
- **Regression**: full suite, Ruff, format, mypy, offline smoke (`finding report
  --help` shows `--platform`).

## Boundary

Platform reports describe demonstrated findings only, keep demonstrated impact
separate from plausible/untested impact, reference redacted evidence (never raw
output), and are code-owned (no template engine, no injection surface). They stay
local under the engagement directory.
