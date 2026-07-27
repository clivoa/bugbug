# policy-v2 Specification

## Purpose
TBD - created by archiving change engagement-v2-actions-policy. Update Purpose after archive.
## Requirements
### Requirement: Deterministic deny-wins decision order
Policy v2 SHALL evaluate a request against a confirmed snapshot and action
registry in a fixed, deny-wins order: validate the frozen engagement and
registry; require confirmed authorization; bind and type-check non-secret
parameters; infer the effective risk level and required capabilities; validate
every individual target against scope; apply prohibited tools, vulnerability
types, and excluded impacts; apply capability, rate, concurrency, target-count,
timeout, header, source-identity, and restricted-hour rules; then return `ALLOW`
or a stable `DENY_*`. The engine SHALL NOT return `REQUIRES_APPROVAL` for schema
v2 and SHALL resolve no secret and create no resource as part of the decision.

#### Scenario: Fully permitted request is allowed
- **WHEN** a request passes every ordered check
- **THEN** the decision is `ALLOW` and no secret is resolved and no resource is created

#### Scenario: Unconfirmed authorization denies before parameter work
- **WHEN** the snapshot's authorization is not confirmed
- **THEN** the decision denies with `DENY_AUTHORIZATION_UNCONFIRMED` before any target or capability check

#### Scenario: Approval is never requested
- **WHEN** any schema v2 request is evaluated
- **THEN** the decision is only `ALLOW` or a `DENY_*`; `REQUIRES_APPROVAL` is never returned

### Requirement: Sensitive-capability gate
An action's required capabilities SHALL each map to a `testing_rules` boolean
that MUST be exactly `true`. A capability whose field is absent, `false`, or a
non-boolean SHALL deny with `DENY_CAPABILITY_NOT_ALLOWED`. A profile name SHALL
grant no capability by itself.

#### Scenario: Missing capability field denies
- **WHEN** an action requires a capability whose `testing_rules` field is absent
- **THEN** the decision denies with `DENY_CAPABILITY_NOT_ALLOWED`

#### Scenario: Capability set to false denies
- **WHEN** an action requires a capability whose field is exactly `false`
- **THEN** the decision denies with `DENY_CAPABILITY_NOT_ALLOWED`

#### Scenario: All required capabilities true allows the gate
- **WHEN** every required capability field is exactly `true` and all other checks pass
- **THEN** the capability gate does not deny

### Requirement: All-target scope decision
Every member of a request's target list SHALL be validated against scope before
any binding output or resource is produced. One malformed, duplicate-conflicting,
excluded, or out-of-scope target SHALL deny the whole action with that target's
stable scope reason; the engine SHALL NOT silently filter and run a permitted
subset.

#### Scenario: One out-of-scope target denies the action
- **WHEN** a target list contains one out-of-scope target among otherwise in-scope targets
- **THEN** the decision denies with the offending target's scope reason and no partial execution is prepared

#### Scenario: All in-scope targets pass the scope stage
- **WHEN** every target is in scope and not excluded
- **THEN** the scope stage does not deny

### Requirement: Prohibited tools, vulnerability types, and excluded impacts
The engine SHALL deny with `DENY_POLICY_LIMIT` when the selected executable's
basename appears in `prohibited_tools`, when the action's declared vulnerability
types intersect `prohibited_vulnerability_types`, or when its declared impacts
intersect `excluded_impacts`.

#### Scenario: Prohibited tool denies
- **WHEN** the selected executable's basename is listed in `prohibited_tools`
- **THEN** the decision denies with `DENY_POLICY_LIMIT`

#### Scenario: Excluded impact denies
- **WHEN** an action declares an impact listed in `excluded_impacts`
- **THEN** the decision denies with `DENY_POLICY_LIMIT`

### Requirement: Rate enforceability and effective risk level
A request declaring a finite rate for an action whose rate control cannot enforce
it SHALL deny with `DENY_RATE_UNENFORCEABLE`. Other numeric-limit violations
(concurrency, target count, timeout) SHALL deny with `DENY_POLICY_LIMIT`. The
effective risk level SHALL be the maximum of the action's declared minimum,
inferred characteristics, and any higher operator-requested level; a request
SHALL NOT lower the inferred level. Levels `L0`–`L3` are classification and audit
levels, not approval levels.

#### Scenario: Unenforceable finite rate denies
- **WHEN** a request sets a finite rate for an action whose rate control is unenforceable
- **THEN** the decision denies with `DENY_RATE_UNENFORCEABLE`

#### Scenario: Request cannot lower the inferred level
- **WHEN** a request declares a level lower than the inferred effective level
- **THEN** the effective level remains the inferred maximum and is used for classification

### Requirement: Profile-independent determinism
Given identical materialized authority (scope, policy, runner) and an identical
request, policy v2 SHALL return an identical decision regardless of the profile
name. The decision SHALL be a pure function of the materialized inputs.

#### Scenario: Identical materialized rules yield identical decisions
- **WHEN** two engagements differ only by profile name but have identical materialized rules and receive the identical request
- **THEN** both evaluations return the identical decision and reason

