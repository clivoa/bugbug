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
  is never used.
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
