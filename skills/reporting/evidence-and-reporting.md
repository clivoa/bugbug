# Evidence Hygiene & Reporting

**status:** active
**risk:** L0
**approval:** auto
**program_types:** [all]
**source:** reviewed from bug bounty platform documentation and best practices

## Evidence Collection

### What to Capture
- HTTP request/response pairs (raw, with headers)
- Timestamps (UTC) for every action
- Tool output with version and exact command
- Screenshots showing the vulnerability impact
- Scope verification (proving target is in-scope)
- Program rule that authorized each test

### What to Redact
- Session cookies and bearer tokens (use placeholder: REDACTED)
- API keys, passwords, credentials in any form
- PII: emails, names, addresses, phone numbers
- Customer data unrelated to the proof
- Internal identifiers not needed for reproduction
- IP addresses you tested from (unless required by program)

### Evidence per Vulnerability Class

**Injection (SQL, NoSQL, Command, SSTI, LDAP):**
- Request with payload
- Response showing error or time difference
- Exact payload used, no more than needed to prove injection
- Never: UNION SELECT data beyond a single harmless value

**IDOR / Broken Access Control:**
- Request from user A accessing user B's resource
- Response proving access
- Redact: user B's actual data, use minimal identifiable info

**XSS:**
- Request with payload
- Proof it executed: alert(document.domain) screenshot or equivalent
- Never: exploit other users, steal cookies, or chain with other attacks

**SSRF:**
- Request with internal URL/IP
- Proof of interaction (HTTP callback, DNS pingback, time difference)
- Never: scan internal network, access metadata beyond confirming reachability

**Authentication Bypass:**
- Normal auth flow for reference
- Bypassed auth flow with exact steps
- Proof of accessing protected resource without valid credentials

**Business Logic:**
- Expected behavior documentation
- Actual behavior with screenshots
- Steps to reproduce the logical flaw
- Impact: what could an attacker gain?

## Report Structure

### Title
`[Program] Vulnerability Class in Component — Brief Impact Description`

### Severity
Per CVSS 3.1 or platform-specific scale. Never inflate. Justify with:
- Attack vector (network/adjacent/local/physical)
- Attack complexity (low/high)
- Privileges required (none/low/high)
- User interaction (none/required)
- Scope (unchanged/changed)
- Confidentiality/Integrity/Availability impact

### Summary (2-3 sentences)
What is the vulnerability, where is it, what can an attacker do?

### Asset & Endpoint
Exact URL/endpoint/contract address/package ID. Must be demonstrably in-scope.

### Vulnerability Class
CWE number when applicable. Standard classification per program taxonomy.

### Preconditions
What must be true for this to be exploitable? Account required? Special configuration?

### Reproduction Steps
Numbered, precise steps. Another researcher should be able to reproduce with these alone.
1. ...
2. ...
3. ...

### Expected Result
What should happen per the intended security design.

### Actual Result
What actually happens, with evidence.

### Impact
- **Demonstrated impact:** what you proved
- **Plausible additional impact:** what could be possible (clearly separated)
- **Untested assumptions:** what you believe but haven't tested (clearly marked)

### Remediation
Specific, actionable fix. Not generic advice. Consider:
- Framework-specific fix
- Configuration change
- Architecture change
- Library upgrade

### Timeline (if applicable)
Dates of: discovery, attempted report, program response

### Attachments
List all evidence files with descriptions.

## Report Review Checklist

Before submitting:
- [ ] Asset is unquestionably in scope
- [ ] Vulnerability class is accepted by this program
- [ ] Behavior is reproducible from the steps provided
- [ ] Clear security boundary is violated
- [ ] Impact is demonstrated, not assumed
- [ ] Demonstrated vs additional vs untested impact are clearly separated
- [ ] All evidence is within scope
- [ ] No secrets, tokens, PII in the report or evidence
- [ ] No exaggeration of severity
- [ ] Reports only what was found, not speculation about other vulnerabilities
- [ ] Cleanup of test artifacts is confirmed
- [ ] Report language matches the program's accepted languages
