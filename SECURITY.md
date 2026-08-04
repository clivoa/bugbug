# SECURITY.md

`bugbug`/`hackbot` is a **defensive, authorization-first** bug-bounty research
workstation. This document states the safety model and the boundaries the software
enforces.

## Authorized use only

Use is limited to: assets you own; explicitly authorized penetration tests;
bug-bounty assets demonstrably in scope; local intentionally-vulnerable labs;
CTFs and security research. Any other use is out of scope and unsupported.

## Enforced safety properties

- **Code-enforced scope.** Every network action passes a default-deny scope engine
  (deny wins). Target-controlled content cannot modify scope, authorization, or
  approval levels.
- **Four-level risk model.** The legacy v1 path uses L0 passive, L1 low-impact,
  L2 per-run approval, and prohibits L3. Engagement v2 uses a separate direct
  ALLOW/DENY gate: a reviewed L3 catalog action exists only under confirmed
  internal authority, code-checked scope, and every exact capability flag set to
  Boolean `true`; no profile name or per-action grant can bypass those checks.
  There is no "disable all safeguards" switch and
  `--dangerously-skip-permissions` is never used. See
  [`docs/risk-and-approval.md`](docs/risk-and-approval.md) and
  [`docs/engagement-v2-l3-catalog.md`](docs/engagement-v2-l3-catalog.md).
- **Discovery ≠ authorization.** ASN/CIDR/cert/favicon/PTR/SPF/DNS-history/Shodan/
  GitHub results are hypotheses only; they never auto-expand scope. Shared CDN/cloud
  ranges are rejected unless explicitly in scope.
- **Secrets never leave safe storage.** Secrets live in the OS keychain/secret
  service. They must never appear in shell history, process args, git history,
  logs, reports, crash dumps, provider traces, or test fixtures.
- **Untrusted-content boundary.** All target/tool/MCP output is treated as data,
  never as instructions (prompt-injection resistant).
- **Loopback-only services.** The provider gateway and Burp MCP bind to
  `127.0.0.1` only; never `0.0.0.0`.
- **Evidence minimization + redaction.** Only the minimum data needed to prove an
  issue is collected; sensitive fields are redacted before storage or cloud model use.
- **Append-only audit log** of scope decisions, approvals, tools, targets, and
  egress snapshots — with secrets redacted.
- **Gate-bound tool execution.** The first executing layer
  (`src/hackbot/tools/`) runs a subprocess **only** after an `ALLOW` from the
  risk gate, **only** a code-owned executable with a code-owned argv array (never
  a shell, never argv from model/target content), with a sanitized environment
  (no secret env leaks to children), a mandatory timeout, byte-capped output, and
  a secret-free audit line per run. Actions are `net.http-get` (L0) and
  `net.http-post` (L2) against in-scope targets. An **L2 action runs only after a
  fresh, TTY-typed, single-use approval** consumed atomically immediately before
  execution (`hackbot tool run --approve`); no TTY → it does not run. See
  [`docs/tool-execution.md`](docs/tool-execution.md).
- **Evidence stored redacted.** Executed runs persist their output to
  `<engagement>/evidence/` **redacted** of known secrets before writing (per the
  redact-before-storing rule), never raw, `0600`/`0700`, and never printed.
  Redaction is best-effort (known secret shapes); evidence files are sensitive
  and live in the git-ignored engagement directory.
- **Findings never exaggerate impact.** A finding separates demonstrated impact
  from plausible, untested impact in distinct fields, and a `demonstrated`
  finding cannot be stored without existing, reproducible evidence (CLAUDE.md
  rule 10). Findings are secret-scanned; markdown reports reference redacted
  evidence and never embed raw output. See
  [`docs/findings-and-reporting.md`](docs/findings-and-reporting.md).

## Prohibited (never automated)

Denial of service, resource exhaustion, phishing, social engineering, malware,
EDR/WAF evasion, CAPTCHA bypass at scale, mass account creation, destructive
file/DB operations, unnecessary PII/customer-data access, cloud credential
extraction, bulk exfiltration, internet-wide scanning, autonomous multi-target
exploitation, continuing after a block/rate-limit, and switching VPN endpoints
to bypass controls. Credential validation/capture, persistence, and lateral
movement are also prohibited outside the reviewed engagement v2 P5b actions and
their confirmed `private-pentest`/`local-lab` capability contract.

## Reporting a security issue in this project

This is a local research tool. If you find a defect that weakens a safety property
(e.g. a scope-engine bypass), open a private issue to the operator with a minimal
reproducer. Do not include real engagement data or secrets.

## Third-party components

See `docs/licenses-and-attribution.md`. GPL/AGPL references are used only via
process/protocol boundaries and are never vendored or linked.
