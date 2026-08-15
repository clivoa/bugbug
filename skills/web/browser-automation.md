---
name: browser-automation
version: "1.0.0"
description: "Headless-browser testing — JS-rendered DOM, screenshots, and evidence for authenticated / JavaScript-heavy workflows"
risk_level: "L0-L1"
approval: "L0 auto, L1 auto"
program_types: [web2, api]
source: "reviewed from HackerAI agent-browser concept, headless Chromium"
actions:
  - web.browser.dom
  - web.browser.screenshot
---

# Browser Automation

**status:** active
**risk:** L0–L1
**approval:** L0 auto, L1 auto
**program_types:** [web2, api]
**source:** reviewed from HackerAI agent-browser concept, headless Chromium

Headless Chromium renders the page **as a real browser would** — executing
JavaScript, following client-side navigation, and resolving the final DOM. Use it
when `curl`/`httpx` give you only the unrendered HTML, or when you need visual
proof of a client-side issue.

## When to use

- **JavaScript-heavy apps** — SPA/React/Vue where content only exists after JS runs
- **Evidence capture** — a screenshot is stronger proof than raw HTML for XSS,
  defacement, or UI-redressing findings
- **Authenticated flows** — render a page behind login to confirm a finding in the
  same context the victim would see (use Burp Repeater/MCP for the requests;
  screenshot the result)
- **Client-side DOM inspection** — read the post-render DOM to confirm injected
  markup or a client-side redirect actually fires

## Actions

### `web.browser.dom` (L1)
Dumps the fully-rendered DOM to stdout.

```text
web.browser.dom <url>
```

- Confirms JavaScript executed (content that exists only post-render appears here)
- Use to verify a DOM XSS sink fires, or a client-side redirect lands

### `web.browser.screenshot` (L1)
Captures a full-page screenshot to `bugbug-screenshot.png` in the current
working directory.

```text
web.browser.screenshot <url>
```

- Run from the engagement evidence directory so the PNG lands where you store it
- Move/rename the file into `evidence/` before reporting; redact anything sensitive
  visible in the frame before it leaves your machine

## Workflow (operator-controlled)

1. Identify a URL that needs a real browser (JS-heavy page, or a finding that needs
   visual proof).
2. Run `web.browser.dom` first — cheap, no file written, shows rendered markup.
3. Run `web.browser.screenshot` when you need a visual artifact for the report.
4. Inspect the PNG, redact PII/secrets, and store it as evidence.
5. Stop after capturing what proves the finding — this is a single-page fetch, not
   a crawler.

## Stop conditions

- One render/screenshot per target URL to prove the finding — do not spider with it
- Never screenshot or store pages containing third-party users' PII without
  redaction
- The headless browser makes a real request — it must stay in scope, same as any
  `httpx` probe
