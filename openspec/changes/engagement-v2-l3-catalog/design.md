## Context

The engagement v2 engine (P0–P4) and the non-credential catalog (P5a) are shipped
and archived. Every action already passes confirmed authority, typed scope, an
exact sensitive-capability gate (P2), redacted conservative evidence (P3), and, if
remote, a pinned replay-resistant protocol (P4). P5b specifies the credential/L3
offensive catalog for **authorized internal-pentest and bug-bounty** work, where
offensive tooling is expected — but only under the operator's explicit,
capability-scoped authority.

This change is the safety/governance contract for that tooling: it makes
credential and exploitation techniques auditable, capability-gated, and
evidence-restricted rather than ad-hoc. It deliberately **excludes** denial of
service, destruction/wiping, bulk exfiltration beyond minimal proof, and detection
evasion.

## Goals / Non-Goals

**Goals:**

- Specify a reviewed L3 catalog (authenticated directory enumeration, credential
  access, validation/capture, exploit verification, post-exploitation, lateral
  movement, persistence) classified per the umbrella table.
- Require every declared capability to be exactly enabled; deny otherwise, with no
  per-action approval.
- Restrict credential evidence to metadata-only or a closed native structured
  schema; never raw dumps, never beyond minimal proof.
- Classify capture-capable modes distinctly from analyze modes; never label
  capture passive.
- Keep the catalog disabled by default and provenance-tagged; confine real
  end-to-end exercise to isolated disposable labs.

**Non-Goals:**

- No DoS/DDoS, destruction, bulk exfiltration, or evasion tooling.
- No engine-gate change, no per-action approval, no auto-enable.
- No execution wiring beyond P2/P3/P4; CI runs no live credential/exploit action.

## Decisions

### 1. The catalog is a code-owned v2 action manifest (as P5a)

Each L3 action is an `operator.internal.<category>.<tool>` entry with an absolute
executable, whole-token argv, typed parameters, scope-checked target bindings,
its exact `L3` risk, and its full capability set, validated by the P2
`validate_manifest`. Routing through the P2 validator guarantees no shell,
inline-eval, or pipeline, and that target-shaped inputs go through scope-checked
bindings.

### 2. Capability sets follow the umbrella table exactly

Credential access → `credential-access` + `sensitive-data-access`; capture →
`credential-capture` (+ `automated-scanning`/`state-changing`); exploit →
`exploit-execution`; payload → `payload-execution` + `state-changing`; lateral →
`lateral-movement` + `credential-access`; persistence → `persistence` +
`state-changing`; authenticated enumeration → `authenticated-testing` +
`sensitive-data-access`. The P2 policy gate requires **all** of an action's
capability flags to be `true`, so partial authorization denies.

### 3. Credential evidence is metadata-only or closed-structured

The evidence mode for credential actions is `metadata-only` by default, or
`structured` constrained to a closed native schema (counts, principal names,
ticket/hash metadata, not raw secret bytes). `redacted-output` is denied for
credential/sensitive capabilities (P3 already enforces `EVIDENCE_POLICY_DENIED`).
A validation test asserts no credential action declares `redacted-output` and that
structured schemas are closed-form.

### 4. Capture vs analyze are separate actions

A responder is split into an analyze/observe action (no capture capability) and a
poison/capture action (`credential-capture`, `state-changing`, third-party). No
capture-capable action may carry a passive/discovery label; a classification test
enforces the distinction and the "never passive" rule.

### 5. Provenance, disabled-by-default, and lab-only exercise

Every action carries a provenance record with attribution; the catalog loads only
through the gated loader (module-private manifest builder, as P5a). Any real
end-to-end exercise runs only in an isolated disposable lab (e.g. an operator's
own AD/Kerberos lab); fixtures are synthetic; CI executes no live action.

## Risks / Trade-offs

- A DoS/destruction/exfiltration action slips in → a disjointness test asserts the
  catalog capability set excludes `denial-of-service`/`destructive-testing`/
  `data-exfiltration`; adding one fails CI.
- A capture tool mislabeled passive → a classification test asserts every
  capture-capable action is `L3` `credential-capture` and carries no passive label.
- Raw credential material persisted → evidence tests assert metadata-only/closed
  structured and that credential actions cannot use `redacted-output`.
- Partial authorization runs an L3 action → a policy test asserts a single missing
  capability flag denies `DENY_CAPABILITY_NOT_ALLOWED`.
- Accidental live exercise in CI → tests import no scanner/exploit tool and run
  only against synthetic fixtures.

## Migration Plan

1. Add the code-owned L3 catalog manifest and provenance, reviewed
   `skills/internal-recon/**` L3 notes, and isolated-lab synthetic fixtures.
2. Add classification, disjointness (excluded impacts), all-capabilities-required,
   evidence-mode, capture-vs-analyze, and disabled-by-default tests; keep CI
   scanner/exploit-free.
3. Verify, request independent review, merge, and archive.

Rollback removes the catalog, provenance, notes, fixtures, and tests. P5b adds no
engine behavior and no persisted state; rollback migrates no data.

## Open Questions

None blocking. Categories, levels, and capabilities are fixed by the umbrella
table; the manifest/policy/evidence contracts are fixed by P2/P3; the
disabled-by-default rule by CLAUDE.md/SECURITY.md. DoS, destruction, bulk
exfiltration, and evasion are out of scope for this catalog by decision.
