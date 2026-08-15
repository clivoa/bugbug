# Tool Recipes — when to use which tool

A compact, opinionated guide for picking the right tool at the right moment in an
engagement. The recipes below are distilled from the HackerAI open pentesting
tool catalog ([hackerai-tech/hackerai](https://github.com/hackerai-tech/hackerai),
Apache-2.0) and re-expressed in bugbug's model: every step is a **code-owned
action** that already passed the scope engine and risk gate. There is no SaaS,
no paid tier, and no black box — the operator stays in control of every command.

> Attribution: HackerAI is Apache-2.0 *with commercial restrictions* and is
> primarily a hosted product. bugbug takes only the *tool-list and
> when-to-use-which-tool ideas* (facts about standard security tooling), not
> their application code or infrastructure. See
> [`docs/licenses-and-attribution.md`](licenses-and-attribution.md).

## The golden rule

**Use established tools before writing custom scripts.** A scoped, reviewed
action is safer and more auditable than an ad-hoc one-liner. Every recipe below
starts with the bugbug action id.

---

## OOB interaction testing (blind proof)

Use when a vulnerability gives no in-band confirmation.

| Step | Action | Why |
|------|--------|-----|
| 1 | `web.oob.interactsh` | Start the listener; it prints a unique callback domain |
| 2 | inject the domain into the suspected sink | one unique tag per test |
| 3 | watch for the callback | the callback *is* the evidence |

- **Blind SSRF** — `http://<interactsh>/ssrf-probe`
- **Blind XXE** — external entity resolving to `<interactsh>/xxe-probe`
- **Blind XSS** — `<script src="//<interactsh>/x"></script>`
- Start the listener *before* the payload; record the interaction; stop after proof.

Full methodology: `skills/web/oob-interaction-testing.md`.

---

## JWT testing

Use when an API or web app issues JSON Web Tokens.

| Step | Action | Why |
|------|--------|-----|
| 1 | `auth.jwt-decode` | decode header/payload/signature; read `alg`, `kid`, `jku`, role claims |
| 2 | pick a hypothesis | alg:none, RS256→HS256, kid injection, claim tampering |
| 3 | `auth.jwt-crack` | crack a weak HS256 secret (local, wordlist-driven) |

- RS256→HS256 key confusion is the highest-value JWT bug: sign with the *public*
  key as an HMAC secret.
- A cracked secret only proves a *weak key* — forge one token and prove acceptance
  before claiming forgery.

Full methodology: `skills/auth/jwt-testing.md`.

---

## Parameter discovery

Use after endpoints are known, before injection testing.

| Action | Notes |
|--------|-------|
| `web.param-discover` (arjun) | feed confirmed endpoints from crawling, proxy history, or manual mapping |

Run parameter discovery on **known** endpoints; broad blind fuzzing before the
surface is understood is noisy and low-yield.

---

## Directory / file discovery

| Action | Notes |
|--------|-------|
| `web.dir-enum` (ffuf) | rate-limited fuzzing, stack-aligned wordlists |
| `web.dir-enum-ferox` | recursive discovery with sane defaults |
| `web.dir-enum-gobuster` | remote-runner content discovery |

Keep wordlists and extensions aligned to the detected stack. Don't run broad
scans before scope is clear — start narrow and expand only when evidence justifies it.

---

## WAF / CDN fingerprinting (do this early)

| Action | Notes |
|--------|-------|
| `web.detect-waf` (wafw00f) | fingerprint WAF/CDN *before* noisy payload scans |

Tune rate, headers, and payload strategy from the result. A WAF in front of the
target changes everything about how you fuzz — know it first.

---

## CVE mapping

| Action | Notes |
|--------|-------|
| `recon.cvemap` (cvemap) | after identifying product name + version, map plausible CVEs |

Treat CVE output as **leads, not findings**. Manually validate exploitability
(and that the CVE applies to the exact version) before reporting. A CVE id is
hypothesis evidence, never a confirmed vulnerability.

---

## Technology fingerprinting

| Action | Notes |
|--------|-------|
| `recon.httpx-probe` | status code + title + tech-detect |
| `recon.whatweb` | deeper HTTP response fingerprinting |

Stack detection drives every downstream choice: wordlists, injection type, and
which scanner templates to run.

---

## Exposed git repository

| Action | Notes |
|--------|-------|
| `web.git-dump` (gitdumper) | dump a reachable `.git/` directory |

Detect first with a single `GET /.git/HEAD` (or `net.http-get`). Only dump when
the repository is demonstrably reachable — a full dump is high-volume and requires
L2 approval.

---

## SMB share enumeration

| Action | Notes |
|--------|-------|
| `ad.enum.smbmap` (smbmap) | anonymous share + permission enumeration |

Internal-recon territory — see `skills/internal-recon/internal-service-discovery.md`.
Requires the internal-recon profile and explicit confirmation.

---

## Browser-based authenticated testing

For visual, authenticated, JavaScript-heavy, or evidence-driven workflows, render
the page in a real headless browser instead of reading raw HTML:

| Action | Notes |
|--------|-------|
| `web.browser.dom` | dump the JS-rendered DOM — confirms client-side sinks/redirects fire |
| `web.browser.screenshot` | full-page PNG (`bugbug-screenshot.png` in cwd) for visual proof |

Render first (`web.browser.dom`), screenshot only when the report needs a visual
artifact, then redact PII before storing. For interactive form-fill / click flows,
combine with Burp Repeater/Scanner via MCP (`docs/burp-mcp-integration.md`) — the
headless-browser actions are a single-page fetch, not a driver.

Full methodology: `skills/web/browser-automation.md`.

---

## Artifact hygiene

Adapted from the HackerAI agent-hygiene guidance; applies to every engagement:

- **Bound reconnaissance** by target, declared scope, crawl depth, duration,
  concurrency, and output size. Start narrow, expand only with justification.
- **Distill before deleting.** Deduplicate useful evidence before removing raw
  output. Remove only artifacts you created for the current task — never user,
  project, or other-operator files.
- **Use task-unique PoC filenames** (`poc_<task-id>.py`), never generic
  `exploit.py` / `poc.py`.
- **Redact secrets** (tokens, cookies, keys, PII) before storing or sending
  evidence anywhere — see `src/hackbot/evidence/redact.py`.
- **Clean up** a task's disposable files before moving on, especially if the box
  runs low on disk.
