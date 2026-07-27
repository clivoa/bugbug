# Engagement v2 actions manifest, binder, and policy (P2)

**Status:** implemented on `feat/engagement-v2-actions-policy`.

P2 turns an operator action manifest into a bound, policy-decided command. It is
the last safety gate before P3 executes anything. **P2 decides and binds but
executes nothing:** it opens no socket, spawns no child, and resolves no secret.

## Public interfaces

`hackbot.engagement_v2.manifest`

- `load_manifest(path) -> Mapping[str, ActionDefinition]` / `validate_manifest(document)`
  — hardened decode plus strict validation of `actions.yaml` against the P0
  action-execution contracts, returning an immutable registry. Any violation
  fails closed with the exact P0 reason (`INVALID_ACTION_MANIFEST`,
  `INVALID_PLACEHOLDER`, `INVALID_SCHEMA_VERSION`, …).
- `CAPABILITY_TO_FIELD` — the canonical action-capability → `testing_rules` field
  map.

`hackbot.engagement_v2.binder`

- `bind(action, request, resolved_targets, *, platform) -> BoundCommand` — renders
  argv purely from the action's code-owned template. `argv[0]` is always the
  selected absolute executable (P0 review forward-carry N2); a request can never
  supply argv, override the executable, or introduce a shell. `{secret_file:id}`
  becomes a `SecretReference` (resolved only by P3) and `{targets_file:id}` /
  `{artifact_file:id}` become a `FileReference`.

`hackbot.engagement_v2.policy`

- `decide(request, snapshot, registry, *, platform) -> PolicyDecision` — a pure,
  deterministic, deny-wins `ALLOW`/`DENY` decision. `REQUIRES_APPROVAL` is never
  returned. On `ALLOW` the decision carries the `BoundCommand`.

## Decision order (deny-wins)

1. resolve the action from the registry (unknown action is an invalid request);
2. require confirmed authorization (`DENY_AUTHORIZATION_UNCONFIRMED`);
3. sensitive-capability gate — each required capability's `testing_rules` field
   must be exactly `true`, else `DENY_CAPABILITY_NOT_ALLOWED`;
4. all-target scope — every target is checked against the P1 scope before any
   binding output; one out-of-scope, excluded, or duplicate target denies the
   whole action with that target's scope reason (no silent subset);
5. numeric limits — target count over `max_targets_per_action` denies
   `DENY_POLICY_LIMIT`;
6. rate enforceability — a network-rated capability with a `not-applicable` rate
   control under a finite `max_requests_per_second` denies
   `DENY_RATE_UNENFORCEABLE`;
7. otherwise bind and `ALLOW`.

The effective risk level is `max(declared, requested)`; a request can only raise,
never lower, it. Levels `L0`–`L3` are classification, not approval.

Determinism: `decide` reads only the materialized snapshot (scope,
`testing_rules`, authorization) and the request, so identical materialized rules
yield identical decisions regardless of profile name.

## Manifest contract highlights

Operator action IDs are prefixed `operator.`; executables are absolute paths;
shell/interpreter basenames are accepted only for a declared `L3` action and
elevation basenames (`sudo`, `su`, …) are never `argv[0]`; capabilities must be
in the canonical set; `argv-placeholder` rate control requires a rate and a
concurrency parameter; and every argv token is a literal or a single whole-token
placeholder referencing a declared parameter, target, artifact, or secret.

## Integration boundary

P2's modules live inside `hackbot.engagement_v2` and import only the P0 package,
the P1 loader/scope, and the standard library. Guard tests assert the P2 modules
import nothing executing (`subprocess`, `socket`, `keyring`, networking) and make
no `exec`/`spawn`/`system` call — P2 executes nothing.
