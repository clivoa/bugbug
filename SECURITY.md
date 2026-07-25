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
- **Four-level risk model.** L0 passive (auto), L1 low-impact active (gated auto),
  L2 intrusive/state-changing (explicit approval each run), L3 prohibited (never
  implemented). No "disable all safeguards" switch. `--dangerously-skip-permissions`
  is never used. The deterministic, fail-closed policy gate and single-use,
  five-minute L2 approval lifecycle are **implemented and enforced in code**
  (`src/hackbot/risk/`); see [`docs/risk-and-approval.md`](docs/risk-and-approval.md).
  Today these are exercised only against inert, non-executing fixture actions via
  `hackbot risk`/`hackbot approval` — no tool adapter runs anything yet. Real tool
  execution arrives in a later, separately reviewed phase and must pass this same
  gate before any action runs; an approval grant authorizes exactly one action and
  is consumed atomically once.
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
  a secret-free audit line per run. Today the only action is `net.http-get`
  (curl) against in-scope targets. See
  [`docs/tool-execution.md`](docs/tool-execution.md).
- **Evidence stored redacted.** Executed runs persist their output to
  `<engagement>/evidence/` **redacted** of known secrets before writing (per the
  redact-before-storing rule), never raw, `0600`/`0700`, and never printed.
  Redaction is best-effort (known secret shapes); evidence files are sensitive
  and live in the git-ignored engagement directory.

## Prohibited (never automated)

Denial of service, resource exhaustion, credential stuffing/spraying, phishing,
social engineering, malware, persistence, lateral movement, EDR/WAF evasion,
CAPTCHA bypass at scale, mass account creation, destructive file/DB operations,
unnecessary PII/customer-data access, cloud credential extraction, internet-wide
scanning, autonomous multi-target exploitation, continuing after a block/rate-limit,
and switching VPN endpoints to bypass controls.

## Reporting a security issue in this project

This is a local research tool. If you find a defect that weakens a safety property
(e.g. a scope-engine bypass), open a private issue to the operator with a minimal
reproducer. Do not include real engagement data or secrets.

## Third-party components

See `docs/licenses-and-attribution.md`. GPL/AGPL references are used only via
process/protocol boundaries and are never vendored or linked.
