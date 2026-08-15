---
name: jwt-testing
version: "1.0.0"
description: "JWT security testing — alg confusion, weak signing keys, claim tampering, and jwt_tool usage"
risk_level: "L0-L2"
approval: "L0 auto, L1 auto, L2 requires explicit approval"
program_types: [web2, api]
source: "reviewed from HackerAI tool recipes, PortSwigger JWT research, jwt_tool docs"
actions:
  - auth.jwt-decode
  - auth.jwt-crack
---

# JWT Security Testing

**status:** active
**risk:** L0–L2
**approval:** L0 auto, L1 auto, L2 requires explicit approval
**program_types:** [web2, api]
**source:** reviewed from HackerAI tool recipes, PortSwigger JWT research, jwt_tool docs

JSON Web Tokens are self-contained signed (not encrypted) blobs. The signature
protects integrity, but dozens of implementation mistakes let an attacker forge
or tamper with tokens. Most bugs are found with a decode, a targeted hypothesis,
and one forged token — no brute force needed.

## Decode first (L0)

- `auth.jwt-decode` (`jwt_tool <token>`) decodes header, payload, and signature
- Identify `alg` (HS256 / RS256 / none), `kid` / `jku` / `jwk` headers, and claims
  (`sub`, `exp`, `aud`, `iss`, `scope`, role/permission claims)
- Note whether the token is used for authN (identity) or authZ (roles) — that
  tells you which claim to target.

## Algorithm confusion

### alg:none
- Set `"alg":"none"` and remove the signature. Some servers accept unsigned tokens.
- Try empty signature, or just `header.payload.` (trailing dot).

### RS256 → HS256 (key confusion)
- The server verifies HS256 with the *public* key as the HMAC secret.
- Sign a forged token using the public key you can read from `/.well-known/jwks.json`
  or a `jku` URL. This is the single highest-value JWT bug.

### kid injection
- `kid` pointing to a predictable file (`/dev/null`, `/etc/hostname`) with HS256
- `kid` as a path traversal to read a signing key
- SQLi / command injection inside `kid`

### jku / jwk header
- `jku` pointing to your JWKS endpoint — server fetches attacker keys
- Embedded `jwk` with a self-generated key pair

## Claim tampering

- **sub / role / scope / isAdmin** — change `sub` to another user, flip an
  `"admin": false` claim to `true`
- **exp / nbf** — extend expiry, or replay an expired token
- **aud / iss** — accept a token issued for a different client / tenant
- **alg confusion + claim tampering** — the two compose: forge the alg, then
  change the claim you care about

## Weak secret cracking (L2 — local)

- `auth.jwt-crack` (`jwt_tool <token> -C -d <wordlist>`) brute-forces the HS256
  secret against a wordlist.
- Use only against tokens you are authorized to test; use the bundled wordlists
  (`small` / `common`) or a program-approved list.
- A cracked secret proves the token can be forged **only if** you can then
  demonstrate a forged token is accepted — otherwise report it as a weak-key
  finding, not a forged-token finding.

## Stop conditions

- alg:none / key confusion: forge **one** token, prove it is accepted, stop.
- Claim tampering: change **one** claim, confirm the resulting authZ change, stop.
- Never use a forged token to access another real user's data — prove impact on a
  test account or with a single harmless request.
- Redact the token and any cracked secret from stored evidence.
