## 1. Reviewed catalog manifest

- [ ] 1.1 Add failing tests that the code-owned non-credential internal-recon catalog validates against the P2 `validate_manifest` and yields a registry with the expected `operator.internal.*` action ids.
- [ ] 1.2 Add failing tests that a shell/inline-eval or multi-tool-pipeline action is rejected by the manifest validator.
- [ ] 1.3 Implement the code-owned catalog manifest (local network state via `ip`/`ss` L1; host discovery and service enumeration via `nmap` L2; anonymous LDAP via `ldapsearch` L2), each with absolute executable, whole-token argv, typed parameters, rate control, and evidence mode, until 1.1–1.2 pass.

## 2. Classification and provenance

- [ ] 2.1 Add failing tests asserting every action's platform/architecture, exact risk level, and capabilities against the umbrella category table, and that the catalog capability set is disjoint from `credential-access`/`credential-capture`/`sensitive-data-access` and any L3 capability.
- [ ] 2.2 Add failing tests that every catalog action has a provenance record (source skill/category, classification, attribution) and that no action maps to a credential/L3 source.
- [ ] 2.3 Implement the provenance mapping and the reviewed `skills/internal-recon/**` notes (argv subset + classification, no raw bundle pipeline) until 2.1–2.2 pass.

## 3. Disabled-by-default guard and fixtures

- [ ] 3.1 Add and pass a guard test proving the catalog is not enabled without an authorized internal profile, that presence in a manifest never self-enables, and that discovered internal hostnames/RFC1918/LDAP endpoints never enable it.
- [ ] 3.2 Add deterministic synthetic lab fixtures (example subnets/hosts/endpoints and recorded output samples; no real target or credential material) under a disposable fixture root, with a regenerate/check tool, and prove no test invokes an external scanner.

## 4. Documentation and delivery

- [ ] 4.1 Document the P5a non-credential catalog: categories, classification, provenance/attribution, the disabled-by-default rule, and that P5b delivers the credential/L3 categories.
- [ ] 4.2 Run focused P5a tests, the full pytest suite, Ruff check/format, mypy, fixture drift, OpenSpec strict validation, the secret-scan regex over new paths, and `git diff --check`; record fresh outputs.
- [ ] 4.3 Request independent review, resolve findings, update Issue #6/Project fields, and archive the OpenSpec change only after implementation, verification, and merge.
