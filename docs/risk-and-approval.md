# Risk and approval engine

`src/hackbot/risk/` is the deterministic, fail-closed policy gate that every
future Hackbot tool adapter must pass before any action runs. It answers one
question — *may this exact action run right now against this exact target under
this engagement's authorization?* — and, for intrusive (L2) actions, manages a
single-use, five-minute human approval.

Today the gate is wired only to **inert fixture actions** that name no tool,
executable, or shell and can never execute anything. The CLI exists so the gate
can be exercised end to end. Real tool execution arrives in a later, separately
reviewed phase and must pass this same gate.

- Core package is standard-library only. Reading a YAML engagement needs the
  `config` extra (`pip install 'hackbot[config]'`).
- No command here performs a provider call, subprocess, socket, or
  target-network request.

## Risk levels

| Level | Meaning | Gate behavior |
|-------|---------|---------------|
| **L0** | Passive | Allowed after scope + program checks pass. |
| **L1** | Low-impact active | Allowed only when in-scope, program-permitted, rate-limited, and on the code-owned allowlist (`low_impact_allowlisted`). |
| **L2** | Intrusive / high-volume / state-changing | `requires-approval`: a pending challenge is written; a human must grant it at the TTY before the action is allowed once. |
| **L3** | Prohibited | Always denied. No program, profile, request, grant, or operator override can enable it. |

A **code-owned action definition** sets a minimum risk and characteristics
(`state_changing`, `high_volume`, `touches_third_party`, `creates_account`,
`uses_multiple_accounts`, `out_of_band`, `shell_execution`, …). Those
characteristics can only **raise** the floor (e.g. any `shell_execution` action
is L3). A request's `requested_risk` can raise risk but can never lower a
code-owned floor.

## Evaluation order

`RiskEngine.evaluate(request, context, grant=None, now=...)` runs a pure,
filesystem-free preflight in this fixed order; the first failing check wins and
returns a stable `reason_code`:

1. `request` / `context` well-formed → `DENY_INVALID_REQUEST` / `DENY_INVALID_CONTEXT`
2. request engagement matches context engagement → `DENY_ENGAGEMENT_MISMATCH`
3. authorization confirmed → `DENY_AUTHORIZATION`
4. program testing policy valid and not L3-enabling → `DENY_PROGRAM_INVALID_POLICY` / `DENY_PROHIBITED`
5. action is in the registry → `DENY_UNKNOWN_ACTION`
6. action definition valid → `DENY_INVALID_ACTION_DEFINITION`
7. effective risk is not L3 → `DENY_PROHIBITED`
8. scope check on the exact target (for network actions) → `DENY_SCOPE`
9. program restrictions (see below) → a specific `DENY_PROGRAM_*`
10. rate / concurrency within program limits → `DENY_RATE` / `DENY_CONCURRENCY`
11. L1 must be allowlisted → `DENY_L1_NOT_ALLOWLISTED`
12. below L2 → **allow**; at L2 → **requires-approval** (or grant consumption)

### Program restrictions approval cannot override

These come from the engagement's `testing_rules` and deny before any approval is
even offered — an operator cannot approve past them:

`DENY_PROGRAM_AUTOMATED_NOT_ALLOWED`, `DENY_PROGRAM_AUTHENTICATED_NOT_ALLOWED`,
`DENY_PROGRAM_ACCOUNT_CREATION_NOT_ALLOWED`,
`DENY_PROGRAM_MULTIPLE_ACCOUNTS_NOT_ALLOWED`,
`DENY_PROGRAM_OUT_OF_BAND_NOT_ALLOWED`, `DENY_PROGRAM_PROHIBITED_TOOL`,
`DENY_PROGRAM_PROHIBITED_VULNERABILITY_TYPE`, `DENY_PROGRAM_EXCLUDED_IMPACT`,
`DENY_PROGRAM_PROFILE`, `DENY_PROGRAM_RESTRICTED_HOURS`,
`DENY_PROGRAM_SOURCE_IP_UNVERIFIED`,
`DENY_PROGRAM_REQUIRED_HEADERS_UNSUPPORTED`.

Denial-of-service and social-engineering are hard-false in the program schema and
collapse to `DENY_PROHIBITED`.

## L2 approval lifecycle

An L2 action produces a **challenge**: a canonical snapshot of the code-owned
definition, the reviewed request (target, argv, rate, concurrency, rationale,
hypothesis, expected impact, data touched, stop condition, cleanup plan,
authorizing rule), the scope snapshot, and the policy digest. Its SHA-256 is the
64-hex **challenge id**.

- **Exactly five minutes.** `expires_at = created_at + 5min`, enforced on grant
  and consume against an injected UTC clock. There is no extend/unexpire API.
- **Single use.** A grant is consumed atomically once (a same-filesystem
  `rename` from `granted/` to `consumed/`). Replay → `DENY_APPROVAL_CONSUMED`.
- **Action-bound.** The grant covers the *exact* action. Any change to target,
  argv, rate, or policy re-derives a different digest → `DENY_APPROVAL_MISMATCH`
  (or `DENY_APPROVAL_POLICY_MISMATCH` when only policy changed).
- **Secret-free.** Challenge and audit data are scanned; secret-bearing input is
  refused (`APPROVAL_SECRET`) and no artifact is written.

### On-disk layout

Under `<engagement>/approvals/` (directories mode `0700`, artifacts `0600`):

```
approvals/
  pending/    <digest>.json   # awaiting human grant
  granted/    <digest>.json   # granted, not yet consumed
  consumed/   <digest>.json   # used once; terminal
  expired/    <digest>.json   # expired before use; terminal
  locks/                      # per-digest fcntl locks
  transactions/               # crash-safe transition journal
```

An append-only, secret-free audit line records each transition.

## Confirmation is TTY-only

`hackbot approval grant` opens `/dev/tty` directly, prints every operator-review
field (never the internal binding), and requires the operator to type the exact
short code `APPROVE-<first 12 hex of the digest>`. There is **no** argv, env,
stdin, pipe, or model-output path to confirmation. After input, the context is
reloaded and the challenge reconstructed from its digest again; if anything
changed, the grant is refused and the challenge stays pending. The `approved_by`
recorded is the engagement's confirmed authorization actor.

## CLI

```text
hackbot risk evaluate REQUEST.json --engagement DIR [--json]
hackbot approval grant  CHALLENGE_ID --engagement DIR [--json]   # interactive TTY
hackbot approval status CHALLENGE_ID --engagement DIR [--json]
```

`risk evaluate` reads a strict request file (≤ 64 KiB, UTF-8, no duplicate keys,
no non-finite constants, object root, known keys only, no bool-as-int). The
engagement id and path come from the loaded context — never from the request
file, which may not carry them. `approval grant`/`status` accept **only** a
canonical 64-hex challenge id; no artifact path is ever opened by name.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | allow, successful grant, or a reported status |
| `1` | policy/approval deny, or a persistence failure |
| `2` | invalid local request/context/digest, or missing `config` extra |
| `3` | interactive TTY unavailable or confirmation mismatch |
| `4` | valid L2 action persisted as pending |

JSON output carries stable `reason_code`s so future adapters never parse prose.

### Fixture actions (execute nothing)

The CLI resolves actions only from a small immutable registry
(`src/hackbot/risk/fixtures.py`): `fixture.passive` (L0), `fixture.low-impact`
(L1), `fixture.intrusive` (L2), `fixture.prohibited` (L3). None names a tool,
executable, shell, or argv template, so none can run anything, and CLI input can
never register or mutate an action.

## Example

Against the sanitized sample engagement (scope: `acme-corp.example` and
`https://acme-corp.example/app`; `example.com` stands in for any target):

```bash
# L0 passive request → allow, exit 0
hackbot risk evaluate l0-request.json --engagement engagements/sample --json

# L2 intrusive request → requires-approval, exit 4, writes pending/<id>.json
hackbot risk evaluate l2-request.json --engagement engagements/sample --json

# Inspect the stored state (no temporal validity implied)
hackbot approval status <challenge-id> --engagement engagements/sample --json

# Grant it at the terminal (type APPROVE-<first 12 hex>) → exit 0
hackbot approval grant <challenge-id> --engagement engagements/sample
```

A request file lists only the reviewed fields, e.g.:

```json
{
  "action_id": "fixture.intrusive",
  "target": "https://acme-corp.example/app",
  "argv": [],
  "hypothesis_id": "hyp-1",
  "rationale": "Validate one authorized hypothesis with a single low-rate probe.",
  "rate": 1,
  "concurrency": 1,
  "data_touched": "Public response headers only.",
  "expected_impact": "One low-rate intrusive probe against an in-scope asset.",
  "stop_condition": "Stop on any rate limit, block, or unexpected scope change.",
  "cleanup_plan": "No state is created; nothing to clean up.",
  "program_rule": "Authorized intrusive testing rule.",
  "required_headers": [],
  "requested_risk": null
}
```
