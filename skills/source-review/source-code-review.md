---
name: source-code-review
version: "1.0.0"
description: "SAST, secret scanning, dependency analysis, code review methodology"
risk_level: L0
approval: auto
program_types: [source-code, web3, web2, api, mobile]
source: "reviewed from semgrep, gitleaks, trufflehog, trailofbits methodologies"
actions:
  - source.sast-semgrep
  - source.sast-semgrep-owasp
  - source.sast-semgrep-secrets
  - source.sast-semgrep-rce
  - source.sast-semgrep-jwt
  - source.sast-semgrep-xss
  - source.sast-semgrep-sql-injection
  - source.secrets-gitleaks
  - source.secrets-trufflehog
---

# Source Code Security Review

**status:** active
**risk:** L0
**approval:** auto
**program_types:** [source-code, web3, web2, api, mobile]
**source:** reviewed from semgrep, gitleaks, trufflehog, trailofbits methodologies

## Review Approach

### Secret Detection
- API keys, tokens, passwords in source (gitleaks, trufflehog)
- Environment files committed: .env, .env.production, .env.local
- Configuration files with credentials: config.json, settings.py, app.config
- Hardcoded cryptographic material: private keys, certificates, seeds
- CI/CD configuration: GitHub Actions secrets, GitLab CI variables
- Docker files: ENV with secrets, build args with credentials
- Test fixtures with production credentials

### SAST Patterns (per-language)
**Python:**
- eval(), exec(), compile() with user input
- pickle.loads() / yaml.load() with untrusted data
- os.system(), subprocess with shell=True
- SQL queries with string formatting
- render_template_string() with user input (SSTI)
- xml.etree with external entities
- requests without timeout (DoS)

**JavaScript/TypeScript:**
- eval(), new Function(), setTimeout/setInterval with string
- innerHTML, document.write() with user data
- JSON.parse() without try/catch for untrusted data
- dangerouslySetInnerHTML in React
- NoSQL injection: user input in query operators
- require() with dynamic paths
- postMessage without origin check

**Go:**
- html/template vs text/template (XSS)
- SQL queries with fmt.Sprintf
- os/exec with user-controlled command
- filepath.Clean not enough for path traversal
- crypto/rand vs math/rand for tokens

**Java/Spring:**
- Runtime.exec() with user input
- Deserialization of untrusted Java objects
- XXE via DocumentBuilderFactory
- SpEL injection in @Value annotations
- Actuator endpoints exposed
- Thymeleaf template injection

### Architecture-Level Review
- Authorization logic: is it centralized or per-endpoint?
- Input validation: is it consistent across API, web, and mobile?
- Rate limiting: per-endpoint or global? Per-IP or per-user?
- Session management: token generation, storage, invalidation
- Error handling: what leaks to the user?
- Logging: are secrets, tokens, or PII logged?

## Tool-Based Scanning

### Semgrep
- Custom rules for project-specific patterns
- Framework-specific rules (Django, Express, Spring, Rails)
- Rule categories: injection, crypto, secrets, auth, config

### Dependency Scanning
- osv-scanner: known vulnerabilities in dependencies
- npm audit / pip-audit: language-specific vulnerability databases
- trivy: container image scanning
- Check for abandoned or unmaintained dependencies

## Manual Review Focus Areas

1. **Auth flow implementation** — does the code match the documented flow?
2. **Authorization checks** — are they at the handler layer, middleware, or both?
3. **Input validation chain** — validate → sanitize → use. Any gap?
4. **Secrets management** — where do production secrets come from?
5. **Error paths** — what happens when external services fail?
6. **Race conditions** — shared mutable state without locks
7. **Cryptographic decisions** — algorithm choice, key size, nonce handling
