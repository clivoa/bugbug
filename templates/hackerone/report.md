# {{ program_name }} — Vulnerability Report

**Report ID:** {{ finding_id }}
**Date:** {{ reported_at }}
**Researcher:** {{ researcher }}

---

## Summary

{{ summary }}

## Asset Information

- **Asset:** {{ asset }}
- **Endpoint / Component:** {{ endpoint }}
- **Scope Confirmation:** {{ scope_rule }}

## Vulnerability Details

- **Category:** {{ vulnerability_class }}
- **CWE:** {{ cwe }}
- **Severity:** {{ severity }} (CVSS {{ cvss_score }}: {{ cvss_vector }})

### Severity Justification

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector (AV) | {{ av }} | {{ av_rationale }} |
| Attack Complexity (AC) | {{ ac }} | {{ ac_rationale }} |
| Privileges Required (PR) | {{ pr }} | {{ pr_rationale }} |
| User Interaction (UI) | {{ ui }} | {{ ui_rationale }} |
| Scope (S) | {{ s }} | {{ s_rationale }} |
| Confidentiality (C) | {{ c }} | {{ c_rationale }} |
| Integrity (I) | {{ i }} | {{ i_rationale }} |
| Availability (A) | {{ a }} | {{ a_rationale }} |

---

## Preconditions

{{ preconditions }}

## Reproduction Steps

{{ reproduction_steps }}

## Expected Result

{{ expected_result }}

## Actual Result

{{ actual_result }}

## Impact

### Demonstrated Impact
{{ demonstrated_impact }}

### Plausible Additional Impact
{{ plausible_impact }}

### Untested Assumptions
{{ untested_assumptions }}

---

## Remediation

{{ remediation }}

## Attachments

{{ attachments }}

---

## Cleanup Confirmation

{{ cleanup }}

## Redaction Confirmation

- [ ] Session tokens redacted
- [ ] Personal information redacted
- [ ] Unnecessary data excluded
- [ ] Report contains only minimal proof
