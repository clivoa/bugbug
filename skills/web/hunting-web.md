---
name: hunting-web
version: "1.0.0"
description: "Full web vulnerability methodology — XSS, SQLi, CSRF, SSRF, SSTI, business logic"
risk_level: "L0-L2"
approval: "L0 auto, L1 auto, L2 requires explicit approval"
program_types: [web2]
source: "reviewed from Claude-BugHunter, BugBountySkills, hack-skills"
actions:
  - web.dir-enum
  - web.dir-enum-ext
  - web.dir-enum-ferox
  - web.scan-nuclei-safe
  - web.scan-nuclei-all
  - web.scan-xss
  - web.scan-sqli-detect
  - web.scan-sqli-time
  - web.param-discover
  - web.detect-waf
---

# Web Application Hunting

**status:** active
**risk:** L0–L2
**approval:** L0 auto, L1 auto, L2 requires explicit approval
**program_types:** [web2]
**source:** reviewed from Claude-BugHunter, BugBountySkills, hack-skills,

## Web Vulnerability Classes

### Authentication
- **Username enumeration** via error messages, timing, response length
- **Weak password policy** — test with common passwords on owned accounts only
- **2FA bypass** — response manipulation, status code flipping, direct endpoint access
- **Password reset** — token predictability, host header injection, email parameter pollution
- **OAuth** — redirect_uri validation, state parameter, CSRF, scope escalation
- **SAML** — signature validation, XML signature wrapping, assertion replay
- **JWT** — alg:none, RS256→HS256 confusion, weak HMAC secret, kid injection
- **Session fixation** — pre-authentication session survives login
- **Logout CSRF** — missing CSRF on logout endpoint

### Authorization (IDOR / Broken Access Control)
- **IDOR** — increment/decrement IDs, GUIDs (not auth), hash IDs (may be predictable)
- **Privilege escalation** — vertical (user→admin), horizontal (user A→user B)
- **Missing function-level access control** — admin endpoints accessible without role
- **CORS misconfiguration** — reflected Origin, null origin, trusted subdomain poisoning
- **Path traversal in auth** — /admin accessible as /ADMIN, /admin/, /admin%2f, /;/admin

### Injection
- **SQL injection** — parameterized or die. Test with sleep(5) only after confirming scope allows
- **NoSQL injection** — $ne, $regex, $gt operators in JSON body
- **Command injection** — ; whoami, | whoami, `whoami`, $(whoami) — stop after time-based confirmation
- **Template injection (SSTI)** — {{7*7}}, ${7*7}, <%= 7*7 %> — stop after math test
- **LDAP injection** — *)(uid=*))(|(uid=* — stop after blind confirmation
- **XPath injection** — ' or '1'='1 — test only on XML endpoints
- **Header injection** — CRLF in user-controlled headers (Location, Set-Cookie)
- **Email header injection** — bcc: in contact forms

### Client-Side
- **XSS** — reflected, stored, DOM. alert(document.domain) only, never exploit PoC
- **CSRF** — predictable tokens, missing tokens, token-reuse across sessions
- **CORS** — Access-Control-Allow-Origin: *, null origin allowed, regex bypass
- **Clickjacking** — missing X-Frame-Options, CSP frame-ancestors
- **Prototype pollution** — __proto__, constructor.prototype in JSON merge
- **DOM clobbering** — named elements overriding JS globals
- **PostMessage** — missing origin check (targetOrigin: "*")

### Business Logic
- **Race conditions** — apply coupon twice, withdraw > balance, redeem gift card twice
- **Parameter pollution** — duplicate parameters with different values
- **Integer overflow** — negative quantities, extreme values in financial endpoints
- **Workflow bypass** — skip steps in multi-step processes
- **Inconsistent validation** — different rules in app vs API, web vs mobile
- **Time-of-check/time-of-use** — change state between validation and action

## Detection Approach

1. Map all endpoints (crawl, JS analysis, sitemap, API docs)
2. Classify by function (auth, data access, file handling, search, export, admin)
3. Test auth/authorization first (highest-impact, often lowest-effort)
4. Test parameter behavior (type confusion, boundary values, special characters)
5. Test state transitions (sequences of requests, not just individual endpoints)

## Stop Conditions (all injection classes)

- **STOP** after confirming the injection vector exists with a minimal, harmless payload
- Never extract data beyond what's needed to prove the vulnerability class
- Time-based: sleep(5) or equivalent — no longer
- Error-based: trigger a single distinguishable error
- Out-of-band: DNS/HTTP callback to a service you control — one callback only
- Never use UNION SELECT to enumerate tables unless absolutely required for proof
