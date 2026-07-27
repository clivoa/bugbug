## 1. Reviewed L3 catalog manifest

- [ ] 1.1 Add failing tests that the code-owned credential/L3 catalog validates against the P2 `validate_manifest`, yields the expected `operator.internal.*` L3 action ids, and rejects any shell/inline-eval/pipeline action.
- [ ] 1.2 Add failing tests that every catalog action is `L3` and that the catalog capability set excludes `denial-of-service`, `destructive-testing`, and `data-exfiltration`.
- [ ] 1.3 Implement the code-owned L3 catalog manifest (authenticated directory enumeration, credential access, validation/capture, exploit verification, post-exploitation, lateral movement, persistence) with absolute executables, whole-token argv, scope-checked target bindings, exact capability sets, and rate control, until 1.1–1.2 pass.

## 2. Capability gate and evidence

- [ ] 2.1 Add failing tests that an action requiring multiple capabilities denies with `DENY_CAPABILITY_NOT_ALLOWED` when any one flag is missing/false, and allows the gate only when all are exactly `true`.
- [ ] 2.2 Add failing tests that no credential/capture action declares `redacted-output` (it must be `metadata-only` or a closed `structured` schema), that a credential action requesting `redacted-output` denies `EVIDENCE_POLICY_DENIED`, and that structured evidence carries no raw secret bytes.

## 3. Capture-vs-analyze and provenance

- [ ] 3.1 Add failing tests that every capture-capable action is `L3` `credential-capture` and carries no passive/discovery label, and that analyze and capture are distinct actions with distinct capabilities.
- [ ] 3.2 Add failing tests that every action has a provenance record (source skill/category, classification, attribution) and that no action maps to an excluded (DoS/destruction/exfiltration/evasion) source.
- [ ] 3.3 Implement the provenance mapping and the reviewed `skills/internal-recon/**` L3 notes (argv subset + classification, no raw bundle pipeline) until 3.1–3.2 pass.

## 4. Disabled-by-default and isolated-lab fixtures

- [ ] 4.1 Add and pass a guard test proving the catalog loads only under an authorized internal profile with explicit confirmation, that presence in code never self-enables, and that CI invokes no live credential/exploit tool.
- [ ] 4.2 Add deterministic synthetic isolated-lab fixtures (example AD/Kerberos/LDAP lab data; no real target or credential material) with a regenerate/check tool.

## 5. Documentation and delivery

- [ ] 5.1 Document the P5b credential/L3 catalog: categories, exact capability sets, the all-capabilities-required rule, credential evidence (metadata-only/closed-structured), capture-vs-analyze, disabled-by-default, isolated-lab-only exercise, and the explicit DoS/destruction/exfiltration/evasion exclusions.
- [ ] 5.2 Run focused P5b tests, the full pytest suite, Ruff check/format, mypy, fixture drift, OpenSpec strict validation, the secret-scan regex over new paths, and `git diff --check`; record fresh outputs.
- [ ] 5.3 Request independent review, resolve findings, update Issue #10/Project fields, and archive the OpenSpec change only after implementation, verification, and merge.
