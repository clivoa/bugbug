# Risk and Approval Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the deterministic, fail-closed L0–L3 policy gate and single-use,
five-minute L2 approval lifecycle that every future Hackbot tool adapter must
pass.

**Architecture:** Add a focused `hackbot.risk` package with frozen models, an
immutable code-owned action registry, pure policy evaluation, strict engagement
context loading, and an atomic filesystem approval store. Extend the program
schema with typed testing policy, then expose evaluation and human approval
through non-executing CLI commands.

**Tech Stack:** Python 3.11+ standard library (`dataclasses`, `enum`, `hashlib`,
`json`, `os`, `pathlib`, `secrets`, `zoneinfo`), existing PyYAML config extra,
pytest, Ruff, mypy.

## Global Constraints

- Core package remains standard-library-only; YAML remains behind the `config`
  extra.
- No provider call, subprocess execution, target-network activity, or real tool
  adapter is added in this plan.
- L3 is absolute and cannot be enabled by a program, profile, request, grant, or
  operator override.
- Program and request inputs may elevate risk but never lower a code-owned risk
  floor.
- Every network action requires confirmed engagement authorization and an exact
  allowed scope decision.
- L2 grants bind every reviewed field, expire after exactly five minutes, and are
  consumed atomically once.
- Approval input is interactive TTY-only; no argv, environment, model response,
  or piped-stdin approval.
- Policy artifacts and audit events contain no secrets.
- Production behavior is written test-first and each test is observed failing for
  the intended reason before implementation.

---

### Task 1: Frozen risk models and immutable action registry

**Files:**
- Create: `src/hackbot/risk/__init__.py`
- Create: `src/hackbot/risk/models.py`
- Create: `src/hackbot/risk/registry.py`
- Create: `tests/risk/__init__.py`
- Create: `tests/risk/test_models_registry.py`

**Interfaces:**
- Produces: `RiskLevel`, `DecisionKind`, `ActionDefinition`, `ActionRequest`,
  `TestingPolicy`, `AuthorizationState`, `PolicyContext`, `ApprovalChallenge`,
  `ApprovalGrant`, `PolicyDecision`, and `ActionRegistry`.
- Consumes: existing frozen `hackbot.scope.Scope`.

- [ ] **Step 1: Write failing model and registry tests**

```python
from dataclasses import FrozenInstanceError

import pytest

from hackbot.risk.models import ActionDefinition, ActionRequest, RiskLevel
from hackbot.risk.registry import ActionRegistry, RegistryError


def test_risk_levels_are_ordered():
    assert RiskLevel.L0 < RiskLevel.L1 < RiskLevel.L2 < RiskLevel.L3


def test_action_definition_is_frozen_and_characteristics_raise_floor():
    action = ActionDefinition("fixture.write", RiskLevel.L1, state_changing=True)
    assert action.effective_floor == RiskLevel.L2
    with pytest.raises(FrozenInstanceError):
        action.action_id = "changed"


def test_request_cannot_lower_registered_floor():
    action = ActionDefinition("fixture.scan", RiskLevel.L2)
    request = ActionRequest(
        engagement_id="sample",
        engagement_path="/tmp/sample",
        action_id="fixture.scan",
        target="https://example.com",
        argv=("fixture", "scan"),
        hypothesis_id="hyp-1",
        rationale="Validate one authorized hypothesis.",
        rate=1,
        concurrency=1,
        data_touched="Public response headers.",
        expected_impact="One low-rate request.",
        stop_condition="Stop on any rate limit.",
        cleanup_plan="No state is created.",
        program_rule="Automated testing rule.",
        requested_risk=RiskLevel.L0,
    )
    assert request.effective_risk(action) == RiskLevel.L2


def test_registry_rejects_duplicate_and_unknown_actions():
    action = ActionDefinition("fixture.passive", RiskLevel.L0)
    with pytest.raises(RegistryError):
        ActionRegistry([action, action])
    registry = ActionRegistry([action])
    with pytest.raises(RegistryError):
        registry.require("missing")
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
.venv/bin/python -m pytest tests/risk/test_models_registry.py -q
```

Expected: collection fails because `hackbot.risk` does not exist.

- [ ] **Step 3: Implement the minimal frozen models**

Create models with these public signatures:

```python
class RiskLevel(IntEnum):
    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3


class DecisionKind(str, Enum):
    ALLOW = "allow"
    REQUIRES_APPROVAL = "requires-approval"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    action_id: str
    minimum_risk: RiskLevel
    network_access: bool = False
    low_impact_allowlisted: bool = False
    state_changing: bool = False
    high_volume: bool = False
    touches_third_party: bool = False
    required_profile: str | None = None

    @property
    def effective_floor(self) -> RiskLevel:
        elevated = self.state_changing or self.high_volume or self.touches_third_party
        return max(self.minimum_risk, RiskLevel.L2 if elevated else self.minimum_risk)
```

`ActionRequest` must validate the exact limits from the design in
`__post_init__`, store `argv` and header names as tuples, and implement:

```python
def effective_risk(self, definition: ActionDefinition) -> RiskLevel:
    return max(definition.effective_floor, self.requested_risk or RiskLevel.L0)
```

The remaining dataclasses use frozen, slotted fields only. `PolicyDecision.deny`
and `PolicyDecision.allow` classmethods construct stable results without
callables or secret-bearing fields.

- [ ] **Step 4: Implement the immutable registry**

```python
class ActionRegistry:
    def __init__(self, definitions: Iterable[ActionDefinition]) -> None:
        items: dict[str, ActionDefinition] = {}
        for definition in definitions:
            if definition.action_id in items:
                raise RegistryError(f"duplicate action id: {definition.action_id}")
            items[definition.action_id] = definition
        self._items = MappingProxyType(items)

    def require(self, action_id: str) -> ActionDefinition:
        try:
            return self._items[action_id]
        except KeyError as exc:
            raise RegistryError(f"unknown action id: {action_id}") from exc
```

- [ ] **Step 5: Run focused tests and verify GREEN**

```bash
.venv/bin/python -m pytest tests/risk/test_models_registry.py -q
```

Expected: all Task 1 tests pass.

- [ ] **Step 6: Commit Task 1**

```bash
git add src/hackbot/risk tests/risk
git commit -m "feat: add frozen risk models and registry"
```

---

### Task 2: Strict testing-policy and authorization context

**Files:**
- Modify: `src/hackbot/programs/schema.py`
- Modify: `src/hackbot/programs/loader.py`
- Create: `src/hackbot/risk/context.py`
- Modify: `tests/programs/test_schema.py`
- Create: `tests/risk/conftest.py`
- Create: `tests/risk/test_context.py`
- Create: `tests/risk/fixtures/authorization-confirmed.json`
- Create: `tests/risk/fixtures/authorization-denied.json`

**Interfaces:**
- Consumes: `TestingPolicy`, `AuthorizationState`, `PolicyContext`, existing
  `load_program_file`, and existing frozen `Scope`.
- Produces: `validate_testing_policy(value: object) -> TestingPolicy`,
  `load_authorization(path) -> AuthorizationState`, and
  `load_policy_context(engagement_dir, profile, now) -> PolicyContext`.

- [ ] **Step 1: Write failing strict-policy tests**

Create `tests/risk/conftest.py` with a `sample_engagement(tmp_path)` fixture that
copies the committed sanitized program and scope files, writes a confirmed
authorization document using `2000-01-01T00:00:00Z` and `test-operator`, and
returns the temporary engagement path. All later risk tests reuse this fixture;
production classes receive no test-only helper methods.

```python
def test_testing_policy_rejects_invalid_ranges():
    with pytest.raises(ValidationError):
        validate_testing_policy({"max_requests_per_second": 0, "concurrency": 101})


@pytest.mark.parametrize(
    "field",
    ["denial_of_service_allowed", "social_engineering_allowed"],
)
def test_project_level_l3_flags_cannot_be_true(field):
    with pytest.raises(ValidationError):
        validate_testing_policy({field: True})


def test_policy_rejects_duplicate_normalized_tool_names():
    with pytest.raises(ValidationError):
        validate_testing_policy({"prohibited_tools": ["NMAP", "nmap"]})
```

Add context tests:

```python
def test_context_requires_confirmed_authorization(sample_engagement):
    (sample_engagement / "authorization.json").write_text(
        '{"confirmed": false, "confirmation_timestamp": null, "confirmed_by": null}'
    )
    with pytest.raises(ContextError):
        load_policy_context(sample_engagement, profile="bug-bounty")


def test_policy_digest_changes_when_program_policy_changes(sample_engagement):
    first = load_policy_context(sample_engagement, profile="bug-bounty")
    text = (sample_engagement / "program.yaml").read_text()
    (sample_engagement / "program.yaml").write_text(
        text.replace("max_requests_per_second: 2", "max_requests_per_second: 1")
    )
    second = load_policy_context(sample_engagement, profile="bug-bounty")
    assert first.policy_digest != second.policy_digest
```

- [ ] **Step 2: Run focused tests and verify RED**

```bash
.venv/bin/python -m pytest tests/programs/test_schema.py tests/risk/test_context.py -q
```

Expected: failures for missing typed policy/context APIs.

- [ ] **Step 3: Add exact program-policy validation**

Implement `validate_testing_policy` in `programs/schema.py` with:

```python
def _bounded_int(value: object, *, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValidationError([f"{name}: expected integer {low}..{high}"])
    return value


def _normalized_unique_strings(value: object, *, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValidationError([f"{name}: must be a list"])
    normalized = tuple(str(item).strip().lower() for item in value)
    if any(not item for item in normalized) or len(set(normalized)) != len(normalized):
        raise ValidationError([f"{name}: values must be non-empty and unique"])
    return normalized
```

Parse restricted hours as an IANA timezone plus `HH:MM-HH:MM` windows. Reject
bad timezones, equal start/end times, and malformed values. Return the frozen
`TestingPolicy` model and call this validator from `validate_program`.

- [ ] **Step 4: Implement context loading and deterministic digest**

`load_policy_context` must:

1. load and validate `program.yaml` and `scope.yaml`;
2. parse `authorization.json` with strict keys;
3. require `confirmed is True`, an aware UTC timestamp, and non-empty
   `confirmed_by`;
4. canonicalize safe policy data with sorted-key compact JSON;
5. SHA-256 the canonical bytes into `policy_digest`;
6. return a frozen `PolicyContext`.

Use dependency-injected `now` only for restricted-hours evaluation tests; do not
invent authorization age expiry.

- [ ] **Step 5: Run focused and program regression tests**

```bash
.venv/bin/python -m pytest tests/programs tests/risk/test_context.py -q
```

Expected: all tests pass and existing program ingestion stays default-deny.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/hackbot/programs src/hackbot/risk/context.py tests/programs tests/risk
git commit -m "feat: validate risk policy and authorization context"
```

---

### Task 3: Pure L0/L1/L3 policy evaluation

**Files:**
- Create: `src/hackbot/risk/policy.py`
- Create: `tests/risk/test_policy.py`

**Interfaces:**
- Consumes: `ActionRegistry`, `ActionRequest`, `PolicyContext`, `RiskLevel`, and
  `Scope.check`.
- Produces:
  `RiskEngine.evaluate(request, context, grant=None, now=None) -> PolicyDecision`.

- [ ] **Step 1: Write failing fail-closed policy tests**

```python
def test_unknown_action_is_denied(engine, context, request):
    decision = engine.evaluate(replace(request, action_id="unknown"), context)
    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_UNKNOWN_ACTION"


def test_l0_network_action_requires_exact_scope(engine, context, request):
    decision = engine.evaluate(replace(request, target="https://evil.example"), context)
    assert decision.reason_code == "DENY_SCOPE"


def test_l1_requires_allowlist_and_program_permission(engine, context, request):
    denied = engine.evaluate(replace(request, action_id="fixture.l1-unlisted"), context)
    assert denied.reason_code == "DENY_L1_NOT_ALLOWLISTED"


def test_rate_and_concurrency_cannot_exceed_program(engine, context, request):
    assert engine.evaluate(replace(request, rate=3), context).reason_code == "DENY_RATE"
    assert (
        engine.evaluate(replace(request, concurrency=3), context).reason_code == "DENY_CONCURRENCY"
    )


def test_l3_is_denied_even_with_caller_elevation_or_grant(engine, context, request):
    decision = engine.evaluate(replace(request, action_id="fixture.prohibited"), context)
    assert decision.kind is DecisionKind.DENY
    assert decision.reason_code == "DENY_PROHIBITED"
```

Also test profile mismatch, prohibited tools/types, excluded impacts, required
headers, restricted hours, authorization mismatch, engagement mismatch, and
request attempts to lower risk.

- [ ] **Step 2: Run policy tests and verify RED**

```bash
.venv/bin/python -m pytest tests/risk/test_policy.py -q
```

Expected: failure because `RiskEngine` is missing.

- [ ] **Step 3: Implement ordered evaluation**

Implement this order without filesystem access:

```python
def evaluate(self, request, context, grant=None, now=None):
    if request.engagement_id != context.engagement_id:
        return deny("DENY_ENGAGEMENT_MISMATCH")
    try:
        definition = self.registry.require(request.action_id)
    except RegistryError:
        return deny("DENY_UNKNOWN_ACTION")
    risk = request.effective_risk(definition)
    if risk is RiskLevel.L3:
        return deny("DENY_PROHIBITED", risk)
    if definition.network_access:
        scope_decision = context.scope.check(request.target)
        if not scope_decision.allowed:
            return deny("DENY_SCOPE", risk, scope_decision)
    program_denial = self._program_denial(definition, request, context, now)
    if program_denial is not None:
        return program_denial
    if risk is RiskLevel.L1 and not definition.low_impact_allowlisted:
        return deny("DENY_L1_NOT_ALLOWLISTED", risk)
    if risk < RiskLevel.L2:
        return allow(risk, context.policy_digest)
    return self._require_approval(definition, request, context, now)
```

Each denial branch gets its own stable reason code. At this stage, L2 returns
`REQUIRES_APPROVAL` without accepting a grant; Task 5 supplies grant consumption.

- [ ] **Step 4: Run policy tests and verify GREEN**

```bash
.venv/bin/python -m pytest tests/risk/test_policy.py -q
```

Expected: all Task 3 tests pass.

- [ ] **Step 5: Run scope and program regressions**

```bash
.venv/bin/python -m pytest tests/scope tests/programs tests/risk -q
```

Expected: all selected tests pass.

- [ ] **Step 6: Commit Task 3**

```bash
git add src/hackbot/risk/policy.py tests/risk/test_policy.py
git commit -m "feat: enforce L0 L1 and L3 policy decisions"
```

---

### Task 4: Canonical L2 challenges and atomic approval store

**Files:**
- Create: `src/hackbot/risk/approvals.py`
- Create: `tests/risk/test_approvals.py`

**Interfaces:**
- Consumes: `ActionDefinition`, `ActionRequest`, `PolicyContext`,
  `ApprovalChallenge`, `ApprovalGrant`.
- Produces: `build_challenge`, `canonical_bytes`, `ApprovalStore.create_pending`,
  `ApprovalStore.grant`, `ApprovalStore.status`, `ApprovalStore.consume`, and
  `ApprovalStore.append_event`.

- [ ] **Step 1: Write failing challenge and lifecycle tests**

```python
def test_challenge_hash_is_deterministic(definition, request, context, fixed_now):
    first = build_challenge(definition, request, context, now=fixed_now, nonce="abc")
    second = build_challenge(definition, request, context, now=fixed_now, nonce="abc")
    assert first.challenge_digest == second.challenge_digest
    assert first.expires_at - first.created_at == timedelta(minutes=5)


def test_challenge_binds_argv_target_and_policy(definition, request, context, fixed_now):
    base = build_challenge(definition, request, context, now=fixed_now, nonce="abc")
    argv_changed = build_challenge(
        definition,
        replace(request, argv=("tool", "--different")),
        context,
        now=fixed_now,
        nonce="abc",
    )
    assert base.challenge_digest != argv_changed.challenge_digest


def test_grant_is_single_use(tmp_path, challenge, fixed_now):
    store = ApprovalStore(tmp_path)
    store.create_pending(challenge)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    assert store.consume(grant, challenge, now=fixed_now).status == "consumed"
    with pytest.raises(ApprovalError, match="already consumed"):
        store.consume(grant, challenge, now=fixed_now)


def test_expired_or_altered_grant_is_denied(tmp_path, challenge, fixed_now):
    store = ApprovalStore(tmp_path)
    store.create_pending(challenge)
    grant = store.grant(challenge, approved_by="operator", now=fixed_now)
    with pytest.raises(ApprovalError, match="expired"):
        store.consume(grant, challenge, now=fixed_now + timedelta(minutes=6))
```

Add tests for exclusive create, atomic rename race, digest mismatch, policy
mismatch, file mode `0600`, append-only event fields, and simulated write failure
leaving no partial success record.

- [ ] **Step 2: Run approval tests and verify RED**

```bash
.venv/bin/python -m pytest tests/risk/test_approvals.py -q
```

Expected: failure because approval APIs are missing.

- [ ] **Step 3: Implement canonical hashing and exact five-minute expiry**

```python
def canonical_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def challenge_digest(fields: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_bytes(fields)).hexdigest()
```

`build_challenge` must copy every reviewed field listed in the design, use an
injected nonce in tests and `secrets.token_hex(16)` in production, and compute
`expires_at = created_at + timedelta(minutes=5)`.

- [ ] **Step 4: Implement atomic store and secret-free audit**

Use:

```python
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, payload)
os.fsync(fd)
os.close(fd)
```

Create `pending`, `granted`, `consumed`, and `expired` directories at mode
`0700`. Consume with one same-filesystem `os.rename(granted_path, consumed_path)`.
Append one compact JSON line under an engagement-local `fcntl.flock` lock, then
`fsync`. Expose no unconsume or expiry-extension API.

- [ ] **Step 5: Run approval tests and verify GREEN**

```bash
.venv/bin/python -m pytest tests/risk/test_approvals.py -q
```

Expected: all Task 4 tests pass, including replay and atomicity.

- [ ] **Step 6: Commit Task 4**

```bash
git add src/hackbot/risk/approvals.py tests/risk/test_approvals.py
git commit -m "feat: add single-use L2 approval store"
```

---

### Task 5: Integrate L2 grants into the policy engine

**Files:**
- Modify: `src/hackbot/risk/policy.py`
- Modify: `src/hackbot/risk/approvals.py`
- Create: `tests/risk/test_l2_integration.py`

**Interfaces:**
- Consumes: `ApprovalStore`, `build_challenge`, and existing `RiskEngine`.
- Produces: L2 `REQUIRES_APPROVAL`, exact-grant `ALLOW`, and stable denial codes
  for missing, expired, altered, mismatched, or consumed grants.

- [ ] **Step 1: Write failing end-to-end L2 tests**

```python
def test_l2_without_grant_returns_complete_challenge(engine, context, l2_request):
    decision = engine.evaluate(l2_request, context)
    assert decision.kind is DecisionKind.REQUIRES_APPROVAL
    assert decision.challenge.argv == l2_request.argv
    assert decision.challenge.cleanup_plan == l2_request.cleanup_plan


def test_exact_grant_allows_once(engine, store, context, l2_request, fixed_now):
    pending = engine.evaluate(l2_request, context, now=fixed_now)
    store.create_pending(pending.challenge)
    grant = store.grant(pending.challenge, approved_by="operator", now=fixed_now)
    allowed = engine.evaluate(l2_request, context, grant=grant, now=fixed_now)
    assert allowed.kind is DecisionKind.ALLOW
    replay = engine.evaluate(l2_request, context, grant=grant, now=fixed_now)
    assert replay.reason_code == "DENY_APPROVAL_CONSUMED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("target", "https://other.example"),
        ("argv", ("fixture", "--changed")),
        ("rate", 1),
    ],
)
def test_grant_does_not_cover_changed_action(
    field, value, engine, granted_l2, context, l2_request, fixed_now
):
    changed = replace(l2_request, **{field: value})
    decision = engine.evaluate(changed, context, grant=granted_l2, now=fixed_now)
    assert decision.reason_code == "DENY_APPROVAL_MISMATCH"
```

- [ ] **Step 2: Run integration tests and verify RED**

```bash
.venv/bin/python -m pytest tests/risk/test_l2_integration.py -q
```

Expected: L2 grants are not yet consumed by the evaluator.

- [ ] **Step 3: Bind the engine to the approval store**

Add `approval_store: ApprovalStore` to `RiskEngine`. For L2:

1. deterministically rebuild the challenge from the current definition, request,
   context, and stored pending nonce;
2. return `REQUIRES_APPROVAL` when no grant is supplied;
3. compare grant digest, policy digest, engagement, and expiry;
4. call `ApprovalStore.consume`;
5. translate each `ApprovalError.code` to a stable deny reason;
6. return `ALLOW` only after atomic consumption succeeds.

- [ ] **Step 4: Run L2 and full risk tests**

```bash
.venv/bin/python -m pytest tests/risk -q
```

Expected: all risk tests pass.

- [ ] **Step 5: Commit Task 5**

```bash
git add src/hackbot/risk tests/risk
git commit -m "feat: enforce action-bound L2 approvals"
```

---

### Task 6: Non-executing risk and approval CLI

**Files:**
- Create: `src/hackbot/risk/fixtures.py`
- Modify: `src/hackbot/cli/main.py`
- Create: `tests/risk/test_cli.py`
- Modify: `tests/packaging/test_offline_install.py`
- Create: `tests/risk/fixtures/l0-request.json`
- Create: `tests/risk/fixtures/l2-request.json`
- Create: `tests/risk/fixtures/l3-request.json`

**Interfaces:**
- Consumes: context loader, immutable fixture registry, `RiskEngine`, and
  `ApprovalStore`.
- Produces:
  `hackbot risk evaluate`, `hackbot approval grant`, and
  `hackbot approval status`.

- [ ] **Step 1: Write failing CLI behavior tests**

```python
def test_risk_evaluate_l0_json(sample_engagement, capsys):
    code = app(
        [
            "risk",
            "evaluate",
            str(FIX / "l0-request.json"),
            "--engagement",
            str(sample_engagement),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["decision"] == "allow"


def test_risk_evaluate_l2_writes_pending_challenge(sample_engagement, capsys):
    code = app(
        [
            "risk",
            "evaluate",
            str(FIX / "l2-request.json"),
            "--engagement",
            str(sample_engagement),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 4
    assert payload["decision"] == "requires-approval"
    assert Path(payload["challenge_file"]).exists()


def test_approval_grant_refuses_non_tty(sample_engagement, monkeypatch, capsys):
    monkeypatch.setattr(
        "hackbot.cli.main._read_approval_from_tty",
        lambda _challenge: (_ for _ in ()).throw(OSError("interactive TTY required")),
    )
    code = app(
        [
            "approval",
            "grant",
            "pending/challenge.json",
            "--engagement",
            str(sample_engagement),
        ]
    )
    assert code == 3
    assert "interactive TTY required" in capsys.readouterr().err


def test_l3_cli_is_always_denied(sample_engagement, capsys):
    code = app(
        [
            "risk",
            "evaluate",
            str(FIX / "l3-request.json"),
            "--engagement",
            str(sample_engagement),
            "--json",
        ]
    )
    assert code == 1
    assert json.loads(capsys.readouterr().out)["reason_code"] == "DENY_PROHIBITED"
```

Extend `tests/packaging/test_offline_install.py` to build and install the core
wheel in a throwaway no-dependency venv, then assert that `hackbot risk --help`
lists `evaluate`. Also assert that evaluating a request without the config extra
fails cleanly with installation guidance and no traceback.

- [ ] **Step 2: Run CLI and installed-package tests and verify RED**

```bash
.venv/bin/python -m pytest tests/risk/test_cli.py \
  tests/packaging/test_offline_install.py -q
```

Expected: the source and freshly installed CLIs both lack the risk/approval
commands.

- [ ] **Step 3: Add a non-executing code-owned fixture registry**

Create only:

```python
FIXTURE_ACTIONS = ActionRegistry(
    [
        ActionDefinition("fixture.passive", RiskLevel.L0, network_access=True),
        ActionDefinition(
            "fixture.low-impact",
            RiskLevel.L1,
            network_access=True,
            low_impact_allowlisted=True,
        ),
        ActionDefinition(
            "fixture.intrusive",
            RiskLevel.L2,
            network_access=True,
            high_volume=True,
        ),
        ActionDefinition("fixture.prohibited", RiskLevel.L3, network_access=True),
    ]
)
```

These definitions never invoke anything and cannot be extended from CLI input.

- [ ] **Step 4: Wire parsers and stable exit codes**

Implement:

- allow: exit `0`;
- deny: exit `1`;
- invalid local input: exit `2`;
- interactive approval unavailable/failure: exit `3`;
- requires approval: exit `4`.

Load request JSON with strict known keys and construct `ActionRequest`. Implement
`_read_approval_from_tty(challenge)` to open `/dev/tty`, display every challenge
field, and require the exact short code derived from the digest. Convert missing
TTY or mismatch into exit `3`. Do not accept a confirmation value through argv,
env, or stdin. `approval grant` accepts the pending challenge file path;
`approval status` accepts the challenge ID.

- [ ] **Step 5: Run CLI and installed-package tests and verify GREEN**

```bash
.venv/bin/python -m pytest tests/risk/test_cli.py tests/cli \
  tests/packaging/test_offline_install.py -q
```

Expected: new, existing, and freshly installed CLI tests pass.

- [ ] **Step 6: Commit Task 6**

```bash
git add src/hackbot/cli/main.py src/hackbot/risk/fixtures.py tests/risk \
  tests/packaging/test_offline_install.py
git commit -m "feat: expose non-executing risk approval CLI"
```

---

### Task 7: Documentation, package verification, and final safety regression

**Files:**
- Modify: `conftest.py`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `scripts/smoke_test.sh`
- Create: `docs/risk-and-approval.md`

**Interfaces:**
- Consumes: completed risk CLI and packaging scripts.
- Produces: operator documentation and installed-wheel regression coverage.

- [ ] **Step 1: Document exact policy and CLI behavior**

`docs/risk-and-approval.md` must document:

- evaluation order and reason codes;
- L0/L1/L2/L3 semantics;
- program restrictions that approval cannot override;
- five-minute exact-action grant lifecycle;
- exit codes;
- approval directory layout;
- TTY-only confirmation;
- the fact that fixture actions execute nothing;
- examples using only `example.com` and the sanitized sample engagement.

Update README status/test count from the fresh final test collection, and update
SECURITY.md to distinguish implemented approval enforcement from future tool
execution.

- [ ] **Step 2: Extend the offline smoke test**

Add commands that run from `/tmp` against the installed wheel:

```bash
"$HACKBOT" risk --help >/dev/null
"$HACKBOT" approval --help >/dev/null
```

No smoke step may perform a target or provider network request.

- [ ] **Step 3: Normalize the existing root pytest bootstrap**

Run the configured formatter on the existing root `conftest.py`; this adds the
required blank line after its module docstring without changing behavior:

```bash
.venv/bin/ruff format conftest.py
```

- [ ] **Step 4: Run all verification gates**

```bash
uv sync --locked --extra dev --extra config --extra secrets
.venv/bin/python -m pytest -q -ra
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
scripts/smoke_test.sh
git diff --check
```

Expected: zero test failures, zero unexpected skips, Ruff clean, formatting clean,
mypy clean, offline smoke pass, and no whitespace errors.

- [ ] **Step 5: Commit Task 7**

```bash
git add README.md SECURITY.md docs/risk-and-approval.md scripts/smoke_test.sh \
  conftest.py
git commit -m "docs: verify risk and approval safety gate"
```

---

## Plan self-review

- Spec coverage: models, immutable registry, strict policy context, ordered
  L0/L1/L3 evaluation, canonical L2 challenges, single-use storage, audit, CLI,
  packaging, documentation, and verification each have a task.
- Scope: no tool execution, provider integration, or attack methodology is mixed
  into this plan.
- Type consistency: all later tasks consume the model, registry, engine, context,
  and approval-store names introduced in earlier tasks.
- Safety boundary: attack-skill work remains a separate spec and cannot begin
  execution work until this gate is implemented and verified.
