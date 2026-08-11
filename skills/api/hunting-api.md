---
name: hunting-api
version: "1.0.0"
description: "REST, GraphQL, and SOAP API security testing methodology (OWASP API Top 10 aligned)"
risk_level: "L0-L2"
approval: "L0 auto, L1 auto, L2 requires explicit approval"
program_types: [api, web2, mobile]
source: "reviewed from reference repositories (OWASP API Top 10 aligned)"
actions:
  - api.graphql-detect
  - web.param-discover
---

# API Security Testing

**status:** active
**risk:** L0–L2
**approval:** L0 auto, L1 auto, L2 requires explicit approval
**program_types:** [api, web2, mobile]
**source:** reviewed from reference repositories (OWASP API Top 10 aligned)

## API Vulnerability Classes

### API1 — Broken Object Level Authorization (BOLA/IDOR)
- Increment/decrement object IDs across user sessions
- Test with two accounts: user A should never access user B's resources
- Check GUID endpoints too (GUID ≠ authorization)
- Test nested resources: /users/{id}/orders, /orgs/{id}/members
- Bulk endpoints: POST /api/export with list of IDs including another user's

### API2 — Broken Authentication
- JWT weaknesses: alg:none, RS256→HS256, weak HMAC, kid injection, jku header
- Token in URL (logs, referrer leakage, browser history)
- Missing token validation on every endpoint
- Long-lived tokens without refresh/rotation
- Password reset token in response body, predictable tokens, enumeration
- OAuth: implicit flow, redirect_uri validation, state CSRF, PKCE missing

### API3 — Broken Object Property Level Authorization (Mass Assignment)
- Add sensitive fields to POST/PUT/PATCH: role, isAdmin, verified, balance, groupId
- Test with both owned and guessed fields: organizationId, plan, permissions[]
- PATCH should only update supplied fields — test with read-only fields

### API4 — Unrestricted Resource Consumption
- Missing or weak rate limiting on expensive endpoints
- GraphQL: deeply nested queries, alias-based amplification
- Pagination abuse: ?limit=999999, ?page=-1
- File upload: repeated uploads filling storage
- Search endpoints: computationally expensive regex queries

### API5 — Broken Function Level Authorization (BFLA)
- User accessing admin endpoints directly
- OPTIONS/PUT/DELETE on endpoints where only GET is expected
- HTTP method override: X-HTTP-Method-Override: DELETE

### API6 — Unrestricted Access to Sensitive Business Flows
- Automated purchases bypassing limits
- Coupon/promo code brute-force or reuse
- Referral system abuse
- Comment/vote manipulation through automated requests

### API7 — Server-Side Request Forgery (SSRF)
- URL/webhook/web link parameters calling internal services
- File imports from user-supplied URLs
- PDF generation with external resources
- Cloud metadata endpoints: 169.254.169.254, metadata.google.internal
- Stop after confirming HTTP interaction — never pivot to internal scanning

### API8 — Security Misconfiguration
- Verbose error messages, stack traces in responses
- Missing security headers (CSP, HSTS, X-Content-Type-Options)
- Unnecessary HTTP methods enabled
- CORS: overly permissive Access-Control-Allow-Origin
- Debug endpoints, API documentation exposed (/swagger, /graphiql, /redoc)
- Default credentials on non-production endpoints

### API9 — Improper Inventory Management
- Old API versions still accessible: /v1/, /v2/ after deprecation
- Staging/testing endpoints exposed: /api/staging/, /api/beta/, /api/internal/
- Undocumented endpoints discovered via JS analysis
- Non-production data in production endpoints
- Debug parameters: ?debug=true, ?test=true, ?env=dev

### API10 — Unsafe Consumption of APIs
- Third-party API keys in client-side code
- Over-trusting third-party API responses (SSRF, injection via upstream)
- Missing input validation on data from integrated services

## GraphQL-Specific

- **Introspection enabled** — query __schema { types { name fields { name } } }
- **Depth limiting** — test with deeply nested queries
- **Alias amplification** — same field aliased many times to bypass rate limits
- **Field suggestion** — error messages revealing field names
- **Batching attacks** — multiple mutations in one request bypassing rate limits

## Stop Conditions

- IDOR: confirm access to one other user's resource (non-sensitive), stop
- JWT: confirm algorithm confusion with a self-signed token, stop
- Mass assignment: confirm a single sensitive field is writable, stop
- SSRF: confirm a single HTTP callback to controlled infrastructure, stop
- Never enumerate all users, extract all data, or chain vulnerabilities
