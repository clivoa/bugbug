# Findings & reporting — design

**Status:** approved (2026-07-25)

**Goal:** Turn run-linked evidence into typed, reproducible findings and a
markdown report, completing the path `context → evaluate → allow → run →
evidence → finding → report`.

**Non-goals:** No platform-specific templates yet (the `templates/*` dirs are
empty placeholders), no CVSS, no cloud upload, no auto-generated findings from
model output, no severity scoring engine. The reviewed `hackbot.risk`,
`hackbot.tools`, and `hackbot.evidence` packages are not modified.

## Context

Executed actions persist redacted, run-linked evidence under
`<engagement>/evidence/<run_id>/` (`hackbot.evidence`). `src/hackbot/findings/`
and `src/hackbot/reporting/` are empty stubs. `templates/{hackerone,bugcrowd,…}`
contain only `.gitkeep`.

CLAUDE.md rule 10 governs this phase: *never exaggerate impact; separate
demonstrated impact from plausible additional impact and untested assumptions;
require reproducible evidence before claiming a vulnerability.* The `Finding`
model encodes this structurally.

## Architecture

Three units plus a CLI.

### 1. `src/hackbot/findings/models.py`

```python
class Severity(str, Enum):     # info, low, medium, high, critical
class FindingStatus(str, Enum):  # demonstrated, plausible, untested

@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    title: str
    severity: Severity
    status: FindingStatus
    target: str
    action_id: str
    evidence_run_id: str | None
    summary: str
    demonstrated_impact: str
    plausible_impact: str
    created_at: datetime
```

Validation (`__post_init__`): `title`, `target`, `action_id`, `summary`
non-empty and length-bounded; `severity`/`status` are exact enum members; a
`DEMONSTRATED` finding **requires** a non-empty `evidence_run_id` and a non-empty
`demonstrated_impact` (rule 10 — no demonstrated claim without reproducible
proof); `plausible`/`untested` may omit both. `demonstrated_impact` and
`plausible_impact` are separate fields and never merged.

### 2. `src/hackbot/findings/store.py`

`FindingStore(engagement_dir)` with `FindingError`:

- `add(finding) -> None`: if `evidence_run_id` is set, verify
  `<engagement>/evidence/<run_id>/` exists (reproducible proof) else `FindingError`;
  secret-scan the finding via the approval store's `_reject_secrets` (a
  secret-bearing field raises and nothing is written); write
  `<engagement>/findings/<finding.finding_id>.json` with `O_EXCL` (dir `0700`,
  file `0600`). A `finding_id` collision raises `FindingError`.
- `load_all() -> list[Finding]`: read and validate every `findings/*.json`,
  sorted by `finding_id`.

The descriptor JSON omits `finding_id` and `created_at`. The CLI sets
`created_at = now(UTC)` and derives the id with a code-owned helper
`make_finding_id(title, created_at) = f"{created_at:%Y%m%dT%H%M%SZ}-{sha256(title)[:8]}"`
(filesystem-safe), then constructs the `Finding`. The store persists by
`finding.finding_id`; it does not derive ids.

### 3. `src/hackbot/reporting/render.py`

`render_markdown(findings: Sequence[Finding], *, engagement_id: str) -> str`:

- A header noting the engagement and that claims require reproducible evidence.
- Findings grouped by severity (critical → info). Each shows title, severity,
  status, target, action, the `evidence_run_id` pointer, the summary, and two
  **separate** sections — `Demonstrated impact` and `Plausible additional impact
  (untested)`. Raw evidence is **never embedded**; the report references the
  run id (the redacted proof lives under `evidence/`).

### CLI

```text
hackbot finding add FINDING.json --engagement DIR [--json]
hackbot finding report --engagement DIR
hackbot finding list --engagement DIR [--json]
```

- `add`: strict-parse the descriptor (reuse `risk_cmd._strict_parse`;
  finding-specific known-key check), build the `Finding`, `FindingStore.add`,
  report `finding_id`.
- `report`: `load_all` → `render_markdown` → print the markdown.
- `list`: a compact `finding_id / severity / status / title` summary.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | finding stored, or report/list emitted |
| `1` | persistence failure (e.g. `finding_id` collision) |
| `2` | invalid descriptor/context, or `demonstrated` without existing reproducible evidence |

## Error handling (fail-closed, rule 10)

- `status: demonstrated` without `evidence_run_id`, or with an `evidence_run_id`
  whose `<engagement>/evidence/<run_id>/` does not exist → `FindingError` →
  exit `2`.
- A secret in any finding field → `FindingError`, nothing written.
- The report never embeds raw output; it references `evidence_run_id`. Findings
  live under git-ignored `engagements/**`.
- Demonstrated and plausible impact stay in separate fields/sections; the report
  never merges or inflates them.

## Testing strategy (test-first)

- **models**: `demonstrated` requires `evidence_run_id` + `demonstrated_impact`;
  `plausible`/`untested` may omit; frozen; severity/status are exact enums.
- **store**: `add` writes a `0600` file; a `demonstrated` finding whose evidence
  dir is missing raises `FindingError`; a secret in the title raises and writes
  nothing; `load_all` round-trips; a duplicate `finding_id` raises.
- **render**: groups by severity, emits separate Demonstrated / Plausible
  sections, references `evidence_run_id`, embeds no raw output.
- **CLI**: `finding add` (valid → `0` + `finding_id`; demonstrated without
  evidence → `2`), `finding report` (markdown with both impact sections),
  `finding list`.
- **Regression**: full suite, Ruff, format, mypy, offline smoke (`finding --help`).

## Boundary

A finding claims impact only in structurally separated demonstrated vs plausible
fields; a `demonstrated` finding cannot be stored without an existing,
reproducible evidence run. Reports reference redacted evidence, never raw output,
and stay local under the engagement directory.
