# Non-curl tools: DNS (dig) and TLS (openssl) — design

**Status:** approved (2026-07-25)

**Goal:** Add the first non-curl external tools to the code-owned action
registry, proving the tool substrate generalizes beyond a single binary.

**Non-goals:** No parsing of tool output into structured fields, no new CLI
surface, no changes to the reviewed `hackbot.risk` package.

## Context

`hackbot.tools.actions.REAL_ACTIONS` holds four curl-backed HTTP actions, built
only when curl resolves (`resolve_executable` over an absolute-path allowlist).
The substrate (`CommandRunner`, `run_action`, audit, evidence, `hackbot tool
run`) and the loopback lab server fixture already exist and are tool-agnostic.

## Design

Generalize tool resolution and register two L0 passive actions, each added only
when its tool resolves:

- **`dns.lookup`** — `RiskLevel.L0`, `network_access=True`,
  `uses_external_tool=True`, `executable=<dig>`,
  `argv_template=(dig, "+short", "{target}")`. `target` is a hostname; scope is
  matched by domain. `dig +short` exits `0` on a successful query (output may be
  empty depending on the resolver — that is environment-dependent and not
  asserted).
- **`tls.cert`** — `RiskLevel.L0`, `network_access=True`,
  `uses_external_tool=True`, `executable=<openssl>`,
  `argv_template=(openssl, "s_client", "-connect", "{target}")`. `target` is
  `host:port`; scope is matched by CIDR. stdin is `DEVNULL`, so `s_client` closes
  after the handshake (the runner timeout is the backstop). Note: `s_client`
  exits non-zero when it cannot verify a self-signed certificate — that is
  expected for a probe; the certificate is still printed and captured.

Add allowlists and helpers `dig_path()` / `openssl_path()` beside the existing
`curl_path()`; `_build_actions` appends each action conditionally.

Both actions run through the unchanged substrate: gate → render code-owned argv →
`CommandRunner` → audit → redacted evidence.

## Test infrastructure

- The shared `lab_engagement` fixture gains `domains: [localhost]` alongside the
  existing `cidrs: [127.0.0.0/8]` (additive — existing CIDR-scoped tests still
  pass).
- A new `tls_server` fixture generates a **throwaway** self-signed certificate
  with the resolved `openssl` in `tmp_path` (never committed), wraps a loopback
  `ThreadingHTTPServer` socket with it, and yields `127.0.0.1:<port>`. It skips
  when openssl is unavailable.

## Error handling

Identical to the curl actions: no `ALLOW` → no execution; out-of-scope target →
`DENY_SCOPE`; sanitized env, timeout, output caps, secret-free audit, redacted
evidence.

## Testing strategy (test-first)

- **registry shape**: `dns.lookup` and `tls.cert` are registered (when their tool
  resolves), L0, `network_access`, `uses_external_tool`, tool-backed, argv ends
  with `{target}`; skip per-tool assertions when the tool is absent.
- **DNS end-to-end**: `dns.lookup` with target `localhost` (in-scope domain) →
  `executed`, `exit_code == 0`, evidence captured.
- **TLS end-to-end**: `tls.cert` against the `tls_server` (in-scope
  `127.0.0.1:<port>`) → `executed`, the certificate appears in stdout, evidence
  captured; an out-of-scope target → `DENY_SCOPE`, no execution.
- **Regression**: full suite, Ruff, format, mypy, offline smoke.

## Boundary

Both actions are L0 passive, code-owned, tool-backed, in-scope only, and run only
after an `ALLOW`. Two new external tools, no shell, no argv from model/target
content. The TLS test's private key is a throwaway generated at test time and is
never committed.
