---
name: oauth-and-sso
version: "1.0.0"
description: "OAuth 2.0, OIDC, SAML, and JWT security testing methodology"
risk_level: "L0-L2"
approval: "L0 auto, L1 auto, L2 requires explicit approval"
program_types: [web2, api, mobile]
source: "reviewed from reference repositories, PortSwigger research, OAuth 2.0 RFCs"
actions:
  - net.http-post
  - net.http-headers
---

# OAuth 2.0 & SSO Security Testing

**status:** active
**risk:** L0–L2
**approval:** L0 auto, L1 auto, L2 requires explicit approval
**program_types:** [web2, api, mobile]
**source:** reviewed from reference repositories, PortSwigger research, OAuth 2.0 RFCs

## OAuth 2.0 Authorization Code Flow — Attack Surface

### redirect_uri Validation
- **Open redirector CSRF** — if redirect_uri validation is weak, leak authorization code
- **Path traversal** — https://app.com/callback/../../evil.com
- **Subdomain bypass** — https://app.com.evil.com/callback (domain suffix match)
- **Parameter pollution** — redirect_uri=https://app.com/callback&redirect_uri=https://evil.com
- **Fragment handling** — redirect_uri=https://app.com/callback#@evil.com
- **Wildcard/regex bypass** — https://app.com.evil.com if pattern is *.app.com

### state Parameter (CSRF Protection)
- **Missing state** — attacker can bind victim's authorization code to attacker's session
- **Predictable state** — if state is sequential or timestamp-based, CSRF is possible
- **State reuse** — same state accepted for multiple authorization codes
- **State reflected in redirect** — leaked in Referrer header

### Token Endpoint
- **Client secret exposure** — in mobile apps, SPAs, client-side JS
- **PKCE missing** — SPA/mobile without PKCE is CSRF-vulnerable at authorization endpoint
- **Code reuse** — authorization code accepted more than once
- **Code for different client_id** — auth code from client A used with client B's credentials

### Scope Escalation
- Add extra scopes: scope=openid%20profile%20admin
- Test scope removal — is user prompted to re-consent?
- Scope downgrade attack: request narrower scope, check if broader token returned
- Implicit flow: scope injection in hash fragment

### Token Storage and Validation
- JWT access tokens: test alg:none, RS256→HS256 confusion
- Refresh token rotation: does old refresh token get invalidated?
- Token in URL fragment: accessible to JS, leaked via Referrer
- Token in browser history: accessible to browser extensions

## OpenID Connect (OIDC)

### id_token JWT Attacks
- alg:none — accept unsigned tokens
- RS256→HS256 — sign with public HMAC key
- kid injection — path traversal to /dev/null for HS256
- jku/jwk header — point to attacker-controlled keyset
- sub claim mismatch — id_token sub ≠ access token sub
- aud claim — accept token issued for different client
- azp claim — authorized party not validated
- exp/nbf — accept expired or not-yet-valid tokens

### Discovery and Dynamic Registration
- /.well-known/openid-configuration — reveals endpoints, supported flows
- Dynamic client registration: register a malicious client if open
- logo_uri, client_uri SSRF through OIDC metadata fields

## SAML

### XML Signature Attacks
- Signature wrapping — move signed element, inject unsigned content
- XML signature exclusion — remove signature entirely
- Canonicalization — different c14n algorithms produce different signed content
- Comment injection in signed XML — <!-- --> within SignedInfo
- SWA (Simple Web Auth) token replay

### SAML Assertion Attacks
- Missing signature on assertion (only signed at response level)
- Assertion replay — use same assertion multiple times
- Assertion expiry — long validity window
- Recipient validation — assertion accepted by wrong SP
- InResponseTo missing — no binding to original request

## Stop Conditions

- OAuth CSRF: confirm state parameter missing, stop (no victim accounts)
- redirect_uri bypass: confirm code sent to controlled server, stop (one test)
- JWT alg:none: confirm token accepted with alg:none, stop
- SAML signature wrapping: confirm unsigned content accepted, stop
- Never access other users' data in production without explicit authorization
