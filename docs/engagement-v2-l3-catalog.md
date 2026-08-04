# Engagement v2 credential/L3 catalog (P5b)

P5b is a code-owned catalog for explicitly authorized internal pentests and
operator-owned labs. It turns reviewed credential, capture, exploitation,
post-exploitation, lateral-movement, and persistence techniques into typed L3
actions. It does not loosen the gate and does not add a bypass or “unsafe mode.”

The catalog is inert in `src/hackbot/engagement_v2/l3_catalog.py`. Importing it
executes nothing, resolves no secret, and starts no network operation.

## Activation and decision contract

Presence in code never enables an action. `load_catalog` succeeds only when both
conditions are present:

1. the active profile is `private-pentest` or `local-lab`; and
2. internal recon was explicitly confirmed by the operator.

After loading, every request still passes the existing engagement v2 gate:
confirmed authority, a scope check for every target, all policy exclusions and
limits, evidence policy, and local/remote execution controls. A profile name
grants no capability. Every capability mapped from the action must be present in
`testing_rules` and be the Boolean value `true`; missing, `false`, or a non-Boolean
value returns `DENY_CAPABILITY_NOT_ALLOWED`. V2 returns ALLOW/DENY directly and
does not introduce per-action approval.

## Categories and exact capability sets

Every catalog entry is L3 and has an absolute executable, whole-token argv,
scope-bound targets, and a code-owned native rate adapter.

| Category / actions | Exact capabilities |
|---|---|
| Authenticated directory policies, SPNs, ADCS, graph | `authenticated-testing`, `sensitive-data-access` |
| AS-REP, Kerberoasting, LAPS, gMSA material access | `credential-access`, `sensitive-data-access` |
| Bounded password validation | `credential-capture`, `automated-scanning`, `state-changing` |
| Responder analyze-only | `authenticated-testing`, `sensitive-data-access` |
| Responder poison/capture | `credential-capture`, `state-changing` |
| Controlled exploit verification | `exploit-execution` |
| Payload/post-exploitation proof | `payload-execution`, `state-changing` |
| Lateral access verification | `lateral-movement`, `credential-access` |
| Controlled persistence marker | `persistence`, `state-changing` |

The manifest validator applies P2 first, then P5b-specific invariants: the
reviewed ID set is closed, every action is L3, shell/interpreter executables and
pipeline/control fragments are rejected, and excluded capabilities cannot enter.

## Credential evidence

Catalog actions default to `metadata-only`. Credential/sensitive actions never
declare `redacted-output`; requesting it fails with `EVIDENCE_POLICY_DENIED`.
Closed native structured evidence, when used by a native adapter, accepts only a
fixed field set for principal, ticket, or capture summaries. Counts and bounded
names/metadata are accepted; bytes and unknown fields are rejected. Raw output,
ticket material, reusable authentication material, and exit code as proof of
impact are not retained.

## Analyze versus capture

Responder analyze and poison/capture are distinct actions. Analyze does not
declare `credential-capture`. Capture is L3, declares `credential-capture` and
`state-changing`, records third-party characteristics, and carries capture/
poisoning labels — never passive or discovery.

## Provenance and exclusions

Every action maps to immutable provenance containing source skill/category,
classification, exact capabilities, and `@reeshasx` attribution. The reviewed
skill note is
[`skills/internal-recon/credential-l3-catalog.md`](../skills/internal-recon/credential-l3-catalog.md).
It records single-action argv subsets and never loads or copies raw bundle
pipelines.

The following remain outside the catalog and are rejected by tests:

- denial of service or resource exhaustion;
- destruction, wiping, or destructive testing;
- bulk exfiltration beyond minimal reproducible proof;
- detection evasion or anti-forensics.

## Isolated-lab verification

CI performs only manifest, policy, provenance, classification, and fixture tests.
It imports no scanner/exploit runtime and invokes no live credential or exploit
tool. Synthetic AD/Kerberos/LDAP metadata lives under
`tests/fixtures/engagement_v2_l3/`; it uses only `EXAMPLE.TEST` and the RFC 5737
documentation range `192.0.2.0/24`.

Regenerate or check fixture drift with:

```bash
.venv/bin/python scripts/generate_engagement_v2_l3_fixtures.py
.venv/bin/python scripts/generate_engagement_v2_l3_fixtures.py --check
```

Any real end-to-end exercise is operator-initiated only in an owned, isolated,
disposable lab, after explicit authority and cleanup requirements are confirmed.
