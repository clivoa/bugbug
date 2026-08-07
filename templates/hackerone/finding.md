# Finding: {{ title }}

**Finding ID:** {{ finding_id }}
**Status:** {{ status }}
**Engagement:** {{ engagement_id }}

---

## Asset
{{ asset }}

## Vulnerability Class
{{ vulnerability_class }}

## CWE
{{ cwe }}

## Severity
{{ severity }} | CVSS {{ cvss_score }}

---

## Summary
{{ summary }}

## Preconditions
{{ preconditions }}

## Reproduction Steps
{{ reproduction_steps }}

## Evidence

### Request
```http
{{ request }}
```

### Response
```http
{{ response }}
```

## Impact

### Demonstrated
{{ demonstrated_impact }}

### Plausible Additional
{{ plausible_impact }}

### Untested Assumptions
{{ untested_assumptions }}

---

## Validation

- [ ] Asset in scope
- [ ] Vulnerability class accepted
- [ ] Reproducible
- [ ] Security boundary violated
- [ ] Minimal data access
- [ ] Not expected functionality
- [ ] Sufficient evidence
- [ ] Artifacts cleaned
- [ ] Sensitive data redacted
- [ ] Severity matches impact

## Remediation
{{ remediation }}

## Timeline
- **Discovered:** {{ discovered_at }}
- **Validated:** {{ validated_at }}
- **Reported:** {{ reported_at }}
