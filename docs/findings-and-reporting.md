# Findings & reporting

`src/hackbot/findings/` and `src/hackbot/reporting/` turn run-linked evidence
into typed, reproducible findings and a markdown report — completing the path
`context → evaluate → allow → run → evidence → finding → report`.

These commands are **stdlib-only** (no `config` extra): a finding is a local file
under the engagement directory, not a policy decision.

## The Finding model (CLAUDE.md rule 10)

`hackbot.findings.models.Finding` encodes rule 10 structurally — *never
exaggerate impact; separate demonstrated from plausible; require reproducible
evidence before claiming a vulnerability*:

- `severity` ∈ {info, low, medium, high, critical}; `status` ∈ {demonstrated,
  plausible, untested}.
- `demonstrated_impact` and `plausible_impact` are **separate fields** and are
  never merged.
- A `demonstrated` finding **requires** a non-empty `evidence_run_id` and a
  non-empty `demonstrated_impact`. `plausible` / `untested` may omit both.
- `evidence_run_id` is format-validated (`<UTC-timestamp>-<12 hex>`); it cannot
  contain a path.
- Optional `vulnerability_type` (the weakness class, e.g. `reflected-xss`,
  `sqli`, `ssrf`, `idor`, `auth-bypass`, `rce`) and `reproduction_steps` name the
  vulnerability scenario for the report; both default to empty and may be omitted
  from the descriptor.

## Storage

`hackbot.findings.store.FindingStore` writes one file per finding under
`<engagement>/findings/<finding_id>.json` (dir `0700`, file `0600`, `O_EXCL`):

- If `evidence_run_id` is set, the store verifies that
  `<engagement>/evidence/<run_id>/` **exists** (reproducible proof) — otherwise
  `FindingError` and nothing is written.
- The finding is **secret-scanned** (the approval store's scanner) before writing;
  a secret in any field is refused.
- `finding_id = <UTC timestamp>-<8 hex of the title sha256>`.

## Report

`hackbot.reporting.render.render(findings, *, engagement_id, platform)` produces a
markdown report grouped by severity (critical → info). Each finding shows its
title, severity, status, weakness/type, target, action, the `evidence_run_id`
**pointer**, the summary, steps to reproduce, and two **separate** sections —
*Demonstrated impact* and *Plausible additional impact (untested)*. The report
**never embeds raw output**; the redacted proof lives under `evidence/<run_id>/`.
Reports stay local under the git-ignored engagement directory.

Code-owned per-platform renderers format the same finding into each platform's
conventional section layout: `generic`, `hackerone`, `bugcrowd`, `yeswehack`,
`intigriti`, `immunefi`. There is no template engine — the renderers are typed and
tested, with no injection surface. Every platform keeps demonstrated and plausible
impact separate and references redacted evidence by `run_id`.

## CLI

```text
hackbot finding add FINDING.json --engagement DIR [--json]
hackbot finding report --engagement DIR [--platform NAME]
hackbot finding list --engagement DIR [--json]
```

`add` strict-parses the descriptor (≤ 64 KiB, UTF-8, no duplicate keys /
non-finite constants, known keys only; `finding_id`/`created_at` are set by the
CLI, not the file), builds the `Finding`, and stores it. `report` renders all
findings to markdown on stdout in the chosen `--platform` format (default
`generic`; an unknown platform → exit `2`). `list` prints a compact
`finding_id / severity / status / title` summary.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | finding stored, or report / list emitted |
| `1` | persistence failure (e.g. a `finding_id` collision) |
| `2` | invalid descriptor, or `demonstrated` without existing reproducible evidence |

## Example

```bash
# After an executed run produced evidence/<run_id>/, record a finding that cites it:
hackbot finding add finding.json --engagement engagements/local-lab --json
hackbot finding report --engagement engagements/local-lab   # markdown to stdout
```

A descriptor lists the reviewed fields only, e.g.:

```json
{
  "title": "Reflected value on /echo",
  "severity": "medium",
  "status": "demonstrated",
  "target": "http://127.0.0.1/echo",
  "action_id": "net.http-get",
  "evidence_run_id": "20260725T120000Z-0123456789ab",
  "summary": "The q parameter is reflected unescaped.",
  "demonstrated_impact": "The response echoes attacker-controlled text.",
  "plausible_impact": "Script execution if a sink is reachable."
}
```

## Boundary

A `demonstrated` finding cannot be stored without existing, reproducible
evidence. Findings and reports are secret-free; reports reference redacted
evidence, never raw output; demonstrated and plausible impact stay structurally
separate. Platform-specific report templates (`templates/*`) are a later phase.
