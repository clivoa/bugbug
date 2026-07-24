# Risk and Approval Engine Design

## Purpose

Build the local, deterministic policy gate that every future tool adapter must
pass before execution. The engine enforces Hackbot's four risk levels:

- **L0 — passive:** allowed only after the applicable engagement, authorization,
  scope, and program-policy checks pass.
- **L1 — low-impact active:** allowed only when explicitly supported by a
  code-owned action definition, in scope, permitted by the program, allowlisted,
  and within configured rate and concurrency limits.
- **L2 — intrusive, high-volume, or state-changing:** never auto-runs. It produces
  an action-bound approval challenge that a human operator must approve
  immediately before one execution.
- **L3 — prohibited:** always denied. Neither a program file, model request,
  operator approval, profile, nor configuration flag can enable it.

This phase is local policy code only. It does not implement or execute network
tools, provider calls, scanners, or MCP operations.

## Non-negotiable properties

1. **Fail closed.** Missing, malformed, unknown, stale, or contradictory input
   yields `DENY`, never an allow-with-warning fallback.
2. **Risk cannot be lowered by untrusted input.** A code-owned action definition
   supplies the minimum risk. Requests and program policy may elevate risk or
   impose additional restrictions, but may not reduce it.
3. **Program restrictions cannot be overridden by approval.** An L2 grant
   confirms operator intent for an otherwise-authorized action; it does not
   override scope, authorization, prohibited tools, program rules, or L3.
4. **Discovery is not authorization.** Evidence from ASN, certificates, Shodan,
   DNS history, branding, repositories, or tool output never expands scope.
5. **Target-controlled content is data only.** It cannot define actions, change
   risk, grant approval, alter limits, or modify the policy context.
6. **Every L2 approval is single-use and exact-action-bound.** It expires after
   five minutes, is consumed atomically once, and becomes invalid if any covered
   field changes.
7. **No secrets in policy artifacts.** Action arguments are structured and must
   already be secret-free. Challenges, grants, decisions, errors, and audit
   events contain no secret values.

## Trust boundaries

### Trusted inputs

- `ActionDefinition` instances registered by code-owned, reviewed adapters.
- A `Scope` produced by the strict program loader.
- A validated program-policy snapshot derived from `program.yaml`,
  `scope.yaml`, and `authorization.json`.
- The operator's interactive confirmation through the approval CLI.
- The engine's injected clock and approval store.

### Untrusted inputs

- Model-generated requests and rationales.
- Target, tool, scanner, MCP, Burp, repository, and provider output.
- Discovered assets and redirects.
- Files that have not passed the program/authorization schema validators.
- Handwritten approval files or altered pending/granted artifacts.

Untrusted inputs may populate descriptive request fields only after validation.
They never select an action's minimum risk or grant execution authority.

## Architecture

Create a focused `src/hackbot/risk/` package:

- `models.py` — frozen enums and dataclasses for action definitions, requests,
  policy contexts, decisions, challenges, and grants.
- `registry.py` — immutable registry of code-owned `ActionDefinition` objects;
  duplicate or unknown action IDs fail closed.
- `policy.py` — pure deterministic evaluation; no filesystem, prompting,
  subprocess, or network operations.
- `approvals.py` — canonical challenge hashing, five-minute expiry, atomic
  persistence and consumption, interactive grant validation, and approval audit.
- `context.py` — validates and converts the already-loaded engagement documents
  into a frozen `PolicyContext`.

The CLI wires these units together but contains no policy logic. Future adapters
will call the same engine API immediately before process or network execution.

## Core models

### `RiskLevel`

An ordered integer enum: `L0 = 0`, `L1 = 1`, `L2 = 2`, `L3 = 3`.

### `ActionDefinition`

A frozen, code-owned definition containing:

- `action_id`: stable adapter/action identifier.
- `minimum_risk`: immutable risk floor.
- `network_access`: whether the action can contact any network endpoint.
- `low_impact_allowlisted`: whether the definition may auto-run at L1.
- `state_changing`, `high_volume`, and `touches_third_party`: conservative
  characteristics used to elevate risk.
- `required_profile`: optional profile restriction.

An action is elevated to at least L2 when it is state-changing, high-volume, or
touches a third party. Definitions marked L3 remain L3 permanently.

### `ActionRequest`

A frozen request containing:

- engagement identifier and path;
- action ID and target;
- structured `argv` tuple;
- hypothesis ID and rationale;
- requested rate and concurrency;
- data touched and expected impact;
- stop condition and cleanup plan;
- the program rule claimed to authorize the action;
- required headers represented by names only;
- optional caller-requested risk elevation.

All text fields have explicit size limits. `argv` is a tuple of individual
arguments, never a shell command string. Empty hypotheses, stop conditions, or
cleanup plans are invalid for active actions. The request may raise its risk but
cannot lower the registered floor.

The exact limits are: 128 characters for identifiers, 2,048 for target and
program-rule text, 4,096 per argv item, 128 argv items, and 8,192 for each
descriptive field. Rate is an integer from 1 through 1,000 requests per second;
concurrency is an integer from 1 through 100. Local-only L0 actions may omit rate
and concurrency; network or active actions may not.

### `PolicyContext`

A frozen snapshot containing:

- engagement and program identity;
- authorization confirmation and timestamp;
- frozen `Scope`;
- testing rules: rate, concurrency, automated-scanning permission,
  restricted hours, prohibited tools and vulnerability types, required headers,
  and excluded impacts;
- active profile;
- a deterministic `policy_digest`.

The existing program schema will be extended to validate the types and ranges of
all testing-rule values rather than validating their keys only. Contradictory
flags such as enabling denial of service are rejected or treated as an absolute
L3 prohibition; they never authorize the action.

Program rate and concurrency use the same integer ranges as requests. Lists of
prohibited tools, vulnerability types, excluded impacts, and required header
names contain unique, normalized, non-empty strings. Restricted hours use the
strict mapping `{"timezone": "<IANA name>", "windows": ["HH:MM-HH:MM"]}` and
Python's standard-library `zoneinfo`; malformed or ambiguous windows deny the
action. Project-level L3 flags such as denial of service or social engineering
must be absent or `false`.

### `PolicyDecision`

A frozen result with one of:

- `ALLOW`;
- `REQUIRES_APPROVAL`;
- `DENY`.

It contains the effective risk, stable reason code, safe human explanation,
scope rule, program rule, policy digest, and optional approval challenge. It
does not contain an executable callable or a secret.

## Evaluation order

`RiskEngine.evaluate(definition, request, context, grant=None)` performs the
following checks in order:

1. Validate every model and reject missing or oversized fields.
2. Require the request's engagement identity to match the policy context.
3. Require engagement authorization with `confirmed: true`, a valid UTC
   confirmation timestamp, and a non-empty `confirmed_by` value for every
   governed action. This phase imposes no arbitrary age expiry on a program's
   authorization; revocation is represented by changing `confirmed` to `false`.
4. Resolve the action from the immutable registry. Unknown or duplicate actions
   are denied.
5. Compute effective risk as the maximum of the registered floor,
   conservative action characteristics, and any caller elevation.
6. Deny L3 and all absolute project prohibitions.
7. For network actions, require an independently allowed scope decision for the
   exact target. Redirects must be evaluated as new requests.
8. Apply program denials: prohibited tool/type/impact, profile mismatch,
   restricted hours, required-header mismatch, and explicit program
   restrictions.
9. Enforce positive rate and concurrency values no greater than program limits.
10. For L1, additionally require the code-owned low-impact allowlist and the
    applicable automated-testing permission.
11. Return `ALLOW` for a fully valid L0/L1 request.
12. For L2 without a grant, return `REQUIRES_APPROVAL` plus a challenge.
13. For L2 with a grant, validate exact binding, expiry, policy digest, and
    single-use state; consume it atomically, then return `ALLOW`.

Any exception at a trust boundary is converted into a stable `DENY` decision.
Programming defects are not silently swallowed by internal helpers; tests and
the CLI surface them without weakening the gate.

## L2 challenge and approval lifecycle

### Canonical challenge

The challenge contains every field the operator must review:

- program and engagement;
- exact target;
- action and exact structured argv;
- effective risk and rationale;
- hypothesis;
- expected impact;
- rate and concurrency;
- data touched;
- stop condition;
- authorizing program rule;
- cleanup plan;
- scope and policy digests;
- creation and expiry timestamps;
- a random nonce.

Canonical JSON uses sorted keys, UTF-8, fixed separators, and no non-finite
numbers. `challenge_digest` is SHA-256 over those canonical bytes.

### Grant

`hackbot approval grant <challenge.json>`:

1. Reloads the current engagement and policy.
2. Recomputes and displays the complete challenge.
3. Refuses non-interactive input.
4. Requires the operator to type an exact short confirmation code derived from
   the challenge digest.
5. Writes a grant bound to the full digest, operator label, timestamp, and
   five-minute expiry.

Approval is not accepted through a command argument, environment variable,
model response, target content, or piped stdin.

### Atomic single-use consumption

Approval state lives under the ignored engagement directory:

```text
approvals/
  pending/
  granted/
  consumed/
  expired/
  events.jsonl
```

Files are created with exclusive-create semantics and restrictive permissions.
Grant consumption atomically renames the exact grant from `granted/` to
`consumed/` on the same filesystem. Concurrent or repeated consumers therefore
find no usable grant. Expired grants move to `expired/`. Altered artifacts fail
digest validation and are denied.

Application code exposes no API to unconsume, extend, or broaden a grant.

## Audit

The approval store appends secret-free JSONL events for:

- challenge creation;
- grant or rejection;
- expiry;
- successful consumption;
- attempted replay;
- digest or policy mismatch.

Each event includes UTC timestamp, engagement, action ID, challenge digest,
effective risk, result, and reason code. Events are written with one `O_APPEND`
write under an engagement-local file lock, mode `0600`, followed by `fsync`.
There is no event deletion or rewrite API. Broader tool/scope/egress audit
integration remains a later phase.

## CLI

Initial commands:

```text
hackbot risk evaluate REQUEST.json --engagement ENGAGEMENT_DIR [--json]
hackbot approval grant CHALLENGE.json --engagement ENGAGEMENT_DIR
hackbot approval status CHALLENGE_ID --engagement ENGAGEMENT_DIR [--json]
```

`risk evaluate` performs policy evaluation only and never executes the action.
L0/L1 exit successfully only when allowed; L2 writes a pending challenge and
uses a distinct exit code; L3 and invalid requests are denied. JSON output uses
stable reason codes so future adapters do not parse prose.

The CLI will initially use a small code-owned registry of non-executing fixture
actions solely to exercise the gate end to end. Real action definitions arrive
with reviewed tool adapters; arbitrary CLI input cannot register an action.

## Error handling

- Invalid request, program, scope, authorization, or approval: `DENY`.
- Missing action definition: `DENY_UNKNOWN_ACTION`.
- Scope rejection: `DENY_SCOPE`.
- Program restriction: a specific `DENY_PROGRAM_*` reason.
- L3: `DENY_PROHIBITED`.
- Missing L2 approval: `REQUIRES_APPROVAL`.
- Expired, altered, mismatched, or consumed approval: a specific deny reason.
- Filesystem write failure: deny and leave no partial grant or misleading
  success record.

Errors disclose names, reason codes, and safe paths only. They never include
secret values, cookies, request bodies, or environment contents.

## Testing strategy

All production behavior is developed test-first. Tests cover:

- ordered risk levels and immutable models;
- duplicate/unknown action definitions;
- registered risk floors that requests cannot lower;
- conservative elevation to L2;
- authorization mismatch and default-deny failures;
- exact scope checks and deny-wins;
- L1 allowlist, automated-testing, rate, concurrency, header, time, profile,
  prohibited-tool/type, and excluded-impact gates;
- L2 challenge completeness and deterministic canonical hashing;
- one successful single-use grant;
- replay, expiry, mutation, target/argv/policy mismatch, and concurrent consume;
- L3 denial regardless of program or supplied grant;
- untrusted content attempting to set risk, scope, or approval;
- atomic write failures and absence of partial state;
- CLI exit codes and JSON reason codes;
- full regression suite, Ruff, mypy, offline wheel build, and installed-package
  smoke tests.

No test uses real engagement data, real targets, provider calls, network access,
or operator secrets.

## Deferred work

- Actual subprocess or network execution.
- Tool adapters and their production action definitions.
- Provider gateway and model routing.
- Burp MCP and Shodan integration.
- Full evidence/finding/reporting workflows.
- Cryptographic audit signing or protection against a malicious local operator.

The threat model for this phase protects against target/model/tool-controlled
content and accidental operator mistakes. A local operator with arbitrary
filesystem and process control is outside this phase's enforcement boundary.
