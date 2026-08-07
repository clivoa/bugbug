# Core Bug Bounty Methodology

**status:** active
**risk:** L0
**approval:** auto
**program_types:** [all]
**source:** reviewed from multiple reference repositories and recon bundle

## Engagement Lifecycle

```
Program Import → Authorization → Scope Lock → Passive Recon → Surface Map
    → Hypothesis Generation → Prioritized Testing → Finding Validation
    → Evidence Collection → Report → Cleanup
```

## Phase 1: Program Understanding (L0)
1. Read and parse program policy, scope, rules
2. Identify: allowed vulnerability classes, prohibited techniques, rate limits
3. Map in-scope assets to categories: web, API, mobile, cloud, source
4. Note: required headers, source IP requirements, restricted hours
5. Check for known duplicates and common vulnerability patterns
6. Review previous disclosures and write-ups for the target

## Phase 2: Surface Mapping (L0)
1. Passive subdomain enumeration (multiple sources)
2. Technology fingerprinting (Wappalyzer, BuiltWith, headers)
3. Endpoint discovery (JS analysis, Wayback, sitemap, API docs)
4. Third-party dependency identification
5. Authentication flow mapping (login, registration, password reset, MFA, OAuth)
6. Role/authorization tier mapping (anonymous, user, admin, super-admin)

## Phase 3: Hypothesis Generation (L0)
For each surface element, ask:
- What vulnerability class fits this pattern?
- What would the impact be if exploitable?
- What is the minimal test to confirm or rule out?
- Is there a safe first step vs. an intrusive follow-up?

Rank by: scope confidence × potential impact ÷ test invasiveness

## Phase 4: Controlled Testing (L1-L2)
- L0/L1: passive observation, low-rate probes, safe GET requests
- L2: requires explicit approval with rationale, expected impact, stop condition
- Test one hypothesis at a time
- Record all requests and responses
- Stop immediately when: target blocks you, IP changes, scope changes unexpectedly

## Phase 5: Validation Gate (L0)
Before considering any finding "confirmed":
1. Asset is unquestionably in scope
2. Vulnerability class is accepted by the program
3. Behavior is reproducible
4. Clear security boundary violation exists
5. Impact demonstrated with minimal data
6. Behavior is not expected functionality
7. Sufficient evidence for another researcher to reproduce
8. Test artifacts have been removed
9. Sensitive data has been redacted
10. Severity matches demonstrated (not theoretical) impact

## Phase 6: Reporting
- Separate: demonstrated impact, plausible additional impact, untested assumptions
- Never exaggerate
- Include minimal proof sufficient for triager to reproduce
- Recommend specific remediation
- Confirm cleanup

## Safety Principles

1. **Default-deny scope** — anything not explicitly in scope is OUT
2. **Discovery ≠ authorization** — finding an asset does not authorize testing it
3. **Deny wins** — an excluded asset beats any in-scope match
4. **Stop conditions are binding** — block/rate-limit = stop, not pivot
5. **Evidence before claims** — never report without reproducible proof
6. **Minimal data access** — access only what's needed to prove the vulnerability
7. **Redact secrets** — never store cookies, tokens, keys, PII in evidence
