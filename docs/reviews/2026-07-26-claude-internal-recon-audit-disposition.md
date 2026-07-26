# Claude internal-recon audit — disposition

**Date:** 2026-07-26

**Source:** `/Users/clivoa/Desktop/auditoria-internal-recon-bugbug.txt`

**Source SHA-256:**
`3e2a807a2f8dbd68cfc5d1a83e29da2562ab63a29d610745e03e006e64d6289b`

**Scope:** Technical evaluation of the external read-only audit against the
current codebase and the proposed engagement v2 design. No implementation
changes were made during this review.

## Summary

The audit accurately describes the current v1 implementation: internal-recon
has no executable catalog, caller-supplied profile plumbing is not wired through
the CLI, L3 is absolutely denied, L2 grants are required, the runner has no
secret input channel, the SSH runner renders remote command text, and evidence
redaction does not cover common internal credential material.

Most Critical/Important findings are therefore confirmed implementation gaps
already targeted by the v2 design. Three proposed remedies are intentionally
not adopted because they conflict with operator-approved v2 decisions:

- no `internal_testing_allowed` profile/capability gate;
- no `required_profile` restriction for v2 actions;
- no per-action or L3 approval after engagement confirmation.

The authoritative amended design is
`docs/superpowers/specs/2026-07-26-engagement-v2-internal-pentest-design.md`.

## Finding disposition

| ID | Technical disposition | Design consequence |
|---|---|---|
| C1 | Confirmed for v1. `active_profile` is caller-supplied and the CLI loads no profile. The audit's proposed profile segregation is rejected for v2. | v2 loads an immutable profile from `program.yaml`, removes caller override, and does not use `required_profile` as a capability gate. |
| C2 | Confirmed description of current L3 denial. Treating it as an invariant for v2 or adding an L3 grant conflicts with the approved policy. | v1 retains the absolute denial. Confirmed v2 returns direct `ALLOW`/`DENY` from scope and explicit capabilities, with no grant. |
| C3 | Confirmed. Current runner closes stdin and offers no protected file binding. | Secrets resolve only after `ALLOW` and use declared stdin or opaque `0600` temporary files; never argv or environment. |
| I1 | Confirmed and not fully solved by exact input-secret redaction alone. Kerberos, NTLM, LAPS, gMSA, password attributes, and directory data can be newly discovered output. | Credential-producing operator actions require `metadata-only` evidence. Reviewed native parsers may persist only allowlisted structured facts. Format redaction remains defense in depth. |
| I2 | Partially confirmed. Current CIDR classification can treat slash-bearing input as URL-like and checking only the network address would be insufficient. A sweep of an explicitly authorized CIDR is nevertheless intended behavior. | v2 uses a typed CIDR and subnet containment. Any overlap with an excluded host/network denies the whole sweep. Discovered hosts are rechecked before later actions. |
| I3 | Confirmed. v1 lacks internal exact-host and non-HTTP endpoint types. | scope v2 adds exact `hosts` and typed `network_endpoints`, plus `in-scope-target` runner identity. |
| I4 | Confirmed. Current runners do not model root/capabilities. | Actions declare OS/architecture and required privileges. Any privilege requires explicit policy and runner attestation; action argv cannot invoke `sudo`, `su`, or `doas`. |
| M1 | Confirmed. Internal skill directories are placeholders; normalized material lives in generated notes/docs and classification tables. | The implementation plan must create reviewed skill/catalog artifacts and keep normalized source data inert. |
| M2 | Confirmed. Several referenced commands are Linux-specific. | Every action declares OS/architecture; remote helper preflight denies a mismatch. |
| M3 | Confirmed. “Responder analyze” cannot inherit a generic passive label safely because it can collect authentication material. | Responder modes are distinct; any credential-capable mode is L3 with `credential-capture`, with poisoning characteristics declared separately. |

## Catalog evaluation

The audit's decomposition of host discovery, LDAP, Active Directory, and Linux
enumeration is useful and is incorporated into the v2 catalog taxonomy.

The proposed current-gate MVP is not adopted as the target architecture because
it would build temporary dependencies on:

- `required_profile`;
- bare remote tool names and PATH lookup;
- the legacy SSH command-string runner;
- L2 approval grants.

All four are explicitly superseded by the v2 design. The catalog will instead
be implemented after the shared v2 schema, policy, typed binder, evidence modes,
secret transport, and remote helper substrate exist.

## Additional requirements introduced by the review

1. Credential-producing output cannot rely on regex redaction as its primary
   persistence control.
2. CIDR requests use true network containment and excluded-overlap denial.
3. Privileged actions require typed privilege declarations and attestation;
   privilege acquisition cannot occur inside action argv.
4. Action availability is conditional on declared OS and architecture.
5. Responder credential-capable modes are always L3.

## Remaining status

This review was followed by a broader specification re-audit and a dedicated
remote threat model. Their additional Critical/Important findings supersede the
earlier statement that no material review item remained:

- `docs/reviews/2026-07-26-engagement-v2-spec-reaudit-disposition.md`
- `docs/reviews/2026-07-26-claude-remote-threat-model-disposition.md`

The umbrella specification incorporates the accepted dispositions and still
requires final operator review before the first OpenSpec implementation plan is
written.
