# Engagement v2 P0 contract boundary

P0 publishes isolated, dependency-free contract definitions for later
engagement v2 phases. **P0 does not enable engagement v2 execution.** The
current runtime remains schema v1 and continues to use its existing CLI,
program, risk, scope, and tool paths. P0 has no loader, migration, action
binder, policy decision, secret resolution, subprocess execution, SSH transport,
internal-recon adapter, or autonomous workflow execution.

The source boundary is `src/hackbot/engagement_v2/`. Its package root exports
only `ContractError` and `ReasonCode`; consumers import the remaining narrow
interfaces from their named modules:

| Module | Contract interface |
| --- | --- |
| `errors` | Closed `ReasonCode` values and secret-free `ContractError`. |
| `constants` | Immutable artifact versions, bounds, enums, identifier/digest syntax, protocol values, and P4-oriented trust constants. |
| `canonical` | `canonical_bytes`, `digest_value`, `authority_digest`, and `execution_digest`. |
| `patterns` | Immutable `SafePattern`, `compile_safe_pattern`, and `safe_fullmatch`. |
| `schemas` | `schema_documents` and deterministic `render_schema_files`. |
| `protocol` | Immutable `FrameType`, `Frame`, `FramedMessage`, `RunBinding`, plus `write_message`, `read_message`, and `response_chain`. |

## Canonical values and digest domains

`hackbot-canonical-json-v1` accepts only mappings, lists/tuples, NFC strings,
signed 64-bit integers, exact booleans, and null, at a maximum nesting depth of
32. Mapping keys are ASCII snake case matching `[a-z][a-z0-9_]{0,63}`. Floats,
bytes, surrogates, non-NFC strings, and C0/C1 controls are rejected. Encoding is
sorted-key, compact UTF-8 JSON; ordered lists, including argv, remain ordered.
Callers in later phases normalize set-like collections before canonicalization;
P0 deliberately does not provide a loader or semantic normalizer.

Binding names—parameter names and request keys, secret and target bindings, and
placeholder IDs—use `[a-z][a-z0-9_]{0,63}`. The broader 128-byte
`[a-z0-9]+(?:[._-][a-z0-9]+)*` grammar remains limited to value identifiers
such as action/node IDs and secret reference values.

`digest_value` returns lowercase `sha256:<64 hex>`. `authority_digest` hashes
`{"contract":"hackbot-authority-v1","value":...}` and
`execution_digest` hashes
`{"contract":"hackbot-execution-v1","value":...}`. The fixed wrapper is
the domain separation: callers must not supply their own digest prefix.

## Safe full-match grammar

`hackbot-safe-fullmatch-v1` is implicitly anchored and at most 256 ASCII bytes.
It accepts unescaped ASCII letters, digits, space, `_`, `.`, `:`, `/`, and `@`;
escaped `-`, `[`, `]`, `{`, `}`, and `\\`; character classes of 1–64 literals or
ascending `A-Z`, `a-z`, or `0-9` ranges with optional leading `^`; and bounded
`{m}` or `{m,n}` quantifiers where `0 <= m <= n <= 1024`. It rejects grouping,
alternation, wildcards, anchors, lookaround, backreferences, Unicode classes,
unbounded quantifiers, and nested quantifiers. Matching is full-match and uses
the bounded parser/matcher rather than Python `re`. Printable ASCII match input
is capped at 8,192 bytes and processed in deterministic
`O(input_length * atom_count)` transitions.

## Generated schemas and fixtures

The code-owned Draft 2020-12 schemas are committed under
`schemas/engagement-v2/`: program v2, scope v2, authorization v2, actions v1,
action request v2, runner v2, remote header v1, and `manifest.json`. Check
exact-byte schema drift without writing:

Every schema root declares
`"x-hackbot-canonical-format": "hackbot-canonical-json-v1"`. Standard Draft
2020-12 validation is necessary but not sufficient: P1/P2/P4 must also enforce
strict exact primitive validation and the code-owned custom annotations
(`x-hackbot-max-utf8-bytes`, `x-hackbot-unique-by`) and safe-pattern format.
P0 adds no runtime JSON Schema dependency.

```bash
.venv/bin/python scripts/export_engagement_v2_schemas.py --check
```

Regenerate schemas only when an approved contract definition changes:

```bash
.venv/bin/python scripts/export_engagement_v2_schemas.py
```

The deterministic synthetic fixture corpus is under
`tests/fixtures/engagement_v2/`. Check or regenerate it with:

```bash
.venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py --check
.venv/bin/python scripts/generate_engagement_v2_contract_fixtures.py
```

## Protocol values and P0 non-activation

The protocol contract fixes magic `b"HBV2RUN\x00"`, protocol version 1, a
1,048,576-byte header cap, at most 256 frames, a 67,108,864-byte per-frame cap,
a 75,497,472-byte request cap, and a 41,943,040-byte response cap. A run binding
uses a lowercase UUIDv4, a 32-byte/43-character unpadded-base64url nonce, a
1–300 second lifetime, and at most 30 seconds of clock skew. The specifications
also reserve a P4 replay reservation retained for 600 seconds after expiry, or
until a longer in-progress run finalizes. The egress-observation age is 60
seconds.

These are validation and framing primitives only. **No SSH, helper, or replay
cache exists in P0.** P0 neither opens a socket nor reserves a replay tuple nor
spawns a child. P4 is responsible for any pinned SSH transport, helper identity
verification, replay storage, privilege permits, and trusted preflight.

The code-owned runner-security projection registry binds the runner role and
node identity; SSH endpoint, identity, host-key pin, known-hosts path, and fixed
security options; helper path/protocol plus configured digest and/or
code-signing selector; OS, architecture, permitted privileges; source mode and
address; complete egress-attestation trust tuple; and privilege-signer
fingerprint. Only local private-key path/content and connection timeout are
operational runner exclusions. A deterministic golden vector proves that every
registered field changes the authority digest; P0 does not implement the P1
loader.

## Phase consumers and status

| Consumer | P0 contract it must consume | P0 does not provide |
| --- | --- | --- |
| P1 loader and scope v2 | Artifact versions, strict primitives, canonical authority projection, and authority digest. | A v2 loader, snapshot, migration, or scope runtime. |
| P2 action manifest, binder, and policy | Action enums/bounds, safe placeholders/patterns, execution projection, lifecycle, and denial reasons. | Binding, policy decisions, secret retrieval, or subprocess execution. |
| P4 remote helper and trust protocol | Framing, run binding, protocol caps, response chain, trust/permit constants, and schemas. | SSH, helper process, replay cache, host/helper verification, or privilege broker. |

P0 is merged and archived; its current normative contracts live in
[`openspec/specs/`](../openspec/specs/). The proposal, design, tasks, and delta
specs remain in
[`openspec/changes/archive/2026-07-27-engagement-v2-security-contracts/`](../openspec/changes/archive/2026-07-27-engagement-v2-security-contracts/).
P1 is Ready, while P2–P7 remain dependent and must not treat these contracts as
an activated execution surface. Delivery history is tracked by closed
[GitHub Issue #1](https://github.com/clivoa/bugbug/issues/1).
