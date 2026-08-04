# P5b Authority Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver OpenSpec tasks 1.1–2.5: exact complete P5b catalog contracts, snapshot-bound activation/decision/binding, a signed single-use `ExecutionPermitV2`, P4 framing integration, and the fixed forced-command deployment contract, without enabling a live L3 adapter.

**Architecture:** Keep the current generic P2 manifest and P4 privilege permit backward-compatible. Add P5b-specific immutable contract records and an activation object bound to one `EngagementSnapshot`; extend `remote_permit.py` with a separate v2 domain and exact claims; transport the signed permit in one dedicated request frame; and expose a validation-only L3 gate whose injected replay reservation always runs before its injected resource factory. Actual SQLite durability, OCI execution, networking, adapters, and remote E2E remain later P5b milestones.

**Tech Stack:** Python 3.11+ standard library, frozen dataclasses, canonical JSON/SHA-256, existing pure-Python Ed25519 verifier, pytest, Ruff, mypy, OpenSpec 1.6.

## Global Constraints

- Schema v1 behavior and fixture bytes remain unchanged.
- Public CI performs no live credential, capture, exploit, payload, lateral, persistence, Docker, nftables, or remote-host action.
- No shell text, arbitrary argv, script, payload bytes, unreviewed module, generic command, or raw credential material enters any new interface.
- `ExecutionPermitV2` lifetime is 1–300 seconds inclusive and uses replay key `(authority_digest, run_id, nonce)`.
- Every failure uses an existing `ReasonCode`; public errors remain secret-free and path-free.
- The existing privilege permit v1 domain, field set, and tests remain unchanged.
- P5b remains non-executable until later OCI/adapters/lab work creates valid promotion receipts.

---

## File Structure

- Create `src/hackbot/engagement_v2/l3_contracts.py`: immutable complete action contracts, canonical definition digests, snapshot binding, and activation/decision entry points.
- Modify `src/hackbot/engagement_v2/l3_catalog.py`: supply the exact 15 raw complete definitions and delegate activation to `l3_contracts`; retain structured-evidence helpers.
- Create `tests/fixtures/engagement_v2_l3/catalog-v1.json`: manually reviewed exact golden document for every complete definition.
- Create `tests/engagement_v2/test_l3_contracts.py`: complete-definition, mutation, provenance, snapshot, policy, binding, and v1 isolation tests.
- Modify `src/hackbot/engagement_v2/remote_permit.py`: add v2 claim construction, signing callback integration, and verification while preserving v1.
- Create `tests/engagement_v2/test_l3_permit.py`: exact field/domain/time/signature/binding tests.
- Modify `src/hackbot/engagement_v2/constants.py` and `src/hackbot/engagement_v2/protocol.py`: add one dedicated `EXECUTION_PERMIT` request frame and enforce its envelope shape.
- Create `src/hackbot/engagement_v2/l3_gate.py`: validation-only pre-resource gate with injected replay reservation and resource factory.
- Create `tests/engagement_v2/test_l3_gate.py`: invalid-before-reservation/resource and valid-reservation-before-resource order tests.
- Create `src/hackbot/engagement_v2/l3_deployment.py`: closed deployment-contract validation for a root-owned broker and forced-command SSH identity.
- Create `tests/engagement_v2/test_l3_deployment.py`: fixed-path/digest/user/SSH restriction tests.
- Modify `openspec/changes/engagement-v2-l3-catalog/tasks.md`: check only tasks 1.1–2.5 after their exact gates pass.

### Task 1: Exact complete catalog definitions

**Files:**
- Create: `src/hackbot/engagement_v2/l3_contracts.py`
- Modify: `src/hackbot/engagement_v2/l3_catalog.py`
- Create: `tests/fixtures/engagement_v2_l3/catalog-v1.json`
- Create: `tests/engagement_v2/test_l3_contracts.py`

**Interfaces:**
- Produces: `L3ActionContract`, `complete_catalog_document()`, `validate_complete_catalog(document, project_root)`, and `definition_digest(document)`.
- Consumes: existing `ActionDefinition`, `validate_manifest()`, `digest_value()`, `ContractError`, and `ReasonCode`.

- [ ] **Step 1: Add the independent golden and failing exactness test**

  Add a manually reviewed JSON fixture whose `actions` array is ordered exactly as the 15 IDs in the approved design. Each action record must contain these exact top-level keys: `manifest`, `adapter_id`, `image_key`, `input_schema`, `network_policy`, `rate_policy`, `evidence_schema`, `cleanup_contract`, and `provenance`. Use adapter/image groups `openldap`, `certipy`, `bloodhound`, `impacket`, `netexec`, `responder`, `lab_exploit`, `payload_proof`, `lateral_ssh`, and `persistence_proof`; use the real provenance path `skills/internal-recon/credential-l3-catalog.md` for all locally reviewed behavior.

  ```python
  def test_complete_catalog_matches_independent_golden() -> None:
      expected = json.loads(_GOLDEN.read_text(encoding="utf-8"))
      assert complete_catalog_document() == expected
      contracts = validate_complete_catalog(expected, project_root=Path.cwd())
      assert tuple(contracts) == tuple(_EXPECTED_IDS)
  ```

- [ ] **Step 2: Run the golden test and verify it fails**

  Run: `/Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_l3_contracts.py::test_complete_catalog_matches_independent_golden -q`

  Expected: FAIL because `l3_contracts` and the complete document do not exist.

- [ ] **Step 3: Add mutation tests for the full definition surface**

  Parametrize mutations for every complete-definition section, plus excluded capabilities, shell/interpreter executable, raw `argv`/`command`/`script`/`payload`/`module` input fields, nonexistent provenance path, duplicate/missing/extra action, and reordered action IDs. Every mutation must raise `ContractError(ReasonCode.INVALID_ACTION_MANIFEST)`.

  ```python
  @pytest.mark.parametrize(
      ("section", "replacement"),
      [
          ("adapter_id", "operator-controlled"),
          ("image_key", "latest"),
          ("network_policy", {"mode": "unrestricted"}),
          ("rate_policy", {"kind": "none"}),
          ("evidence_schema", {"mode": "redacted-output"}),
          ("cleanup_contract", {"target": "optional"}),
          ("provenance", {"local_path": "skills/missing.md"}),
      ],
  )
  def test_complete_definition_mutation_denies(section: str, replacement: object) -> None:
      document = copy.deepcopy(complete_catalog_document())
      document["actions"][0][section] = replacement
      with pytest.raises(ContractError) as excinfo:
          validate_complete_catalog(document, project_root=Path.cwd())
      assert excinfo.value.reason_code is ReasonCode.INVALID_ACTION_MANIFEST
  ```

- [ ] **Step 4: Implement immutable contracts and exact validation**

  Define frozen records and return mapping proxies. The definition digest domain is `hackbot-l3-action-definition-v1`.

  ```python
  @dataclass(frozen=True)
  class L3ActionContract:
      action: ActionDefinition
      adapter_id: str
      image_key: str
      input_schema: Mapping[str, object]
      network_policy: Mapping[str, object]
      rate_policy: Mapping[str, object]
      evidence_schema: Mapping[str, object]
      cleanup_contract: Mapping[str, object]
      provenance: Mapping[str, object]
      definition_digest: str

  def definition_digest(raw: Mapping[str, object]) -> str:
      return digest_value({"contract": "hackbot-l3-action-definition-v1", "value": dict(raw)})
  ```

  Validation must first compare the complete canonical document to the code-owned complete document, then pass each nested `manifest` through `validate_manifest()`, then verify that the local provenance path resolves under the repository root and is a regular file. The password-spray capabilities must include `multiple-accounts`; Responder analyze must require only `sensitive-data-access`; all other exact capability sets follow the delta spec verbatim.

- [ ] **Step 5: Run catalog tests and commit**

  Run:

  ```bash
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_l3_catalog.py tests/engagement_v2/test_l3_contracts.py -q
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m ruff check src/hackbot/engagement_v2/l3_catalog.py src/hackbot/engagement_v2/l3_contracts.py tests/engagement_v2/test_l3_contracts.py
  ```

  Commit: `feat(p5b): define exact L3 catalog contracts`

### Task 2: Snapshot-bound activation, decision, and binding

**Files:**
- Modify: `src/hackbot/engagement_v2/l3_contracts.py`
- Modify: `src/hackbot/engagement_v2/l3_catalog.py`
- Modify: `tests/engagement_v2/test_l3_contracts.py`
- Modify: `tests/engagement_v2/test_l3_catalog.py`
- Modify: `tests/engagement_v2/test_v1_isolation.py`

**Interfaces:**
- Produces: `SnapshotBinding`, `ActivatedL3Catalog`, `activate_catalog(snapshot, internal_recon_confirmed, project_root)`, and `decide_l3(request, snapshot, activation, platform)`.
- Consumes: `EngagementSnapshot.identity/profile/authority_digest`, `policy.decide()`, and `BoundCommand` from the existing binder.

- [ ] **Step 1: Add failing same-snapshot and mismatch tests**

  ```python
  activation = activate_catalog(snapshot, internal_recon_confirmed=True, project_root=Path.cwd())
  allowed = decide_l3(_request(action_id), snapshot, activation, platform="linux")
  assert allowed.kind is DecisionKind.ALLOW

  changed = replace(snapshot, authority_digest="sha256:" + "f" * 64)
  with pytest.raises(ContractError) as excinfo:
      decide_l3(_request(action_id), changed, activation, platform="linux")
  assert excinfo.value.reason_code is ReasonCode.DENY_AUTHORIZATION_STALE
  ```

  Cover mismatched `identity`, `profile`, and `authority_digest`; absent/false/non-boolean capabilities; unauthorized profiles; missing internal confirmation; request executable/argv overrides; and activation created from a non-`EngagementSnapshot` object.

- [ ] **Step 2: Run focused tests and confirm the stale-binding failures**

  Run: `/Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_l3_contracts.py -q`

  Expected: FAIL because activation currently accepts only a profile string and has no immutable binding.

- [ ] **Step 3: Implement the activation boundary**

  ```python
  @dataclass(frozen=True)
  class SnapshotBinding:
      snapshot_identity: str
      profile: str
      authority_digest: str

  @dataclass(frozen=True)
  class ActivatedL3Catalog:
      binding: SnapshotBinding
      actions: Mapping[str, L3ActionContract]

  def decide_l3(request, snapshot, activation, *, platform):
      if SnapshotBinding(snapshot.identity, snapshot.profile, snapshot.authority_digest) != activation.binding:
          raise ContractError(ReasonCode.DENY_AUTHORIZATION_STALE)
      return decide(request, snapshot, {key: value.action for key, value in activation.actions.items()}, platform=platform)
  ```

  `activate_catalog` must reject unauthorized/unconfirmed input with `DENY_AUTHORIZATION_UNCONFIRMED`. Remove the profile-string loader as an execution-capable entry point; retain only a clearly named private fixture helper if existing catalog unit tests need raw definitions.

- [ ] **Step 4: Prove v1 isolation and commit**

  Extend the AST/runtime test so importing, activating, rejecting, and discarding P5b changes neither v1 module globals nor the exact bytes of existing v1 fixtures.

  Run:

  ```bash
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_l3_contracts.py tests/engagement_v2/test_v1_isolation.py -q
  ```

  Commit: `feat(p5b): bind catalog decisions to one snapshot`

### Task 3: Canonical signed ExecutionPermitV2

**Files:**
- Modify: `src/hackbot/engagement_v2/remote_permit.py`
- Create: `tests/engagement_v2/test_l3_permit.py`

**Interfaces:**
- Produces: `ExecutionPermitContext`, `build_execution_permit_v2()`, `sign_execution_permit_v2(permit, signer)`, and `verify_execution_permit_v2()`.
- Consumes: `ActivatedL3Catalog`, an `ALLOW` `PolicyDecision`, canonical JSON, an injected `Callable[[bytes], bytes]` signer, and the existing Ed25519 verifier.

- [ ] **Step 1: Add failing exact-field/domain/lifetime tests**

  The permit body must contain exactly the 21 fields from the approved design, including `schema_version`. Use domain `hackbot-execution-permit-v2`. Test 1-second and 300-second validity, and reject 0/301 seconds, expired/not-yet-valid timestamps, unknown/missing fields, bad signer fingerprint, tampered signature, and each mismatched claim group.

  ```python
  def _signed(permit: dict[str, object]) -> bytes:
      body = canonical_bytes({"contract": "hackbot-execution-permit-v2", "permit": permit})
      return sign(_SEED, body)

  @pytest.mark.parametrize("field", sorted(_EXPECTED_FIELDS))
  def test_each_permit_binding_mismatch_denies(field: str) -> None:
      permit = _permit()
      permit[field] = _different_value(field)
      with pytest.raises(ContractError):
          verify_execution_permit_v2(permit, _signed(permit), public_key(_SEED), context=_context(), pinned_signer_fingerprint=_fingerprint(public_key(_SEED)), now=_NOW)
  ```

- [ ] **Step 2: Run tests and confirm v2 is absent**

  Run: `/Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_l3_permit.py -q`

  Expected: FAIL on missing v2 imports.

- [ ] **Step 3: Implement build/sign/verify without weakening v1**

  `ExecutionPermitContext` must type every exact claim. Store list-like claims as tuples and map-like claims as immutable mappings, thawing them only for canonical serialization. `build_execution_permit_v2` must require an `ALLOW` decision bound through the same activation and snapshot; it must never accept a caller-supplied action-definition digest. `sign_execution_permit_v2` calls only the injected signer and rejects any signature not exactly 64 bytes.

  Map failures as follows: bad field set/canonical form/general binding -> `EXEC_PROTOCOL_INVALID`; bad privilege set -> `EXEC_PRIVILEGE_MISMATCH`; bad signer/helper/runner/image/definition digest -> `EXEC_TRUST_MISMATCH`; invalid time -> `EXEC_PROTOCOL_EXPIRED`.

- [ ] **Step 4: Run v1 and v2 permit suites and commit**

  Run:

  ```bash
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_remote_permit.py tests/engagement_v2/test_l3_permit.py -q
  ```

  Commit: `feat(p5b): add snapshot-bound execution permit v2`

### Task 4: P4 permit frame and pre-resource validation gate

**Files:**
- Modify: `src/hackbot/engagement_v2/constants.py`
- Modify: `src/hackbot/engagement_v2/protocol.py`
- Create: `src/hackbot/engagement_v2/l3_gate.py`
- Modify: `tests/engagement_v2/test_protocol.py`
- Create: `tests/engagement_v2/test_l3_gate.py`

**Interfaces:**
- Produces: `FrameType.EXECUTION_PERMIT`, `SignedExecutionPermit`, `decode_execution_permit_frame(frame)`, and `validate_l3_request(request, verification_context, replay_reserver, resource_factory)`.
- Consumes: `verify_execution_permit_v2`, the existing framed message reader, and injectable callbacks `reserve(authority_digest, run_id, nonce, now)` and `create(validated_request)`.

- [ ] **Step 1: Add failing protocol and ordering tests**

  Require exactly one `EXECUTION_PERMIT` frame for an L3 action and zero for a legacy request. Its canonical JSON payload has exact keys `permit` and `signature`, with the signature base64url encoded. Reject duplicate frames, missing permit, malformed/noncanonical JSON, unknown envelope fields, and a permit frame on a response.

  Use ordered spies to prove invalid permits call neither callback and valid permits call `reserve` before `create`:

  ```python
  events: list[str] = []
  validate_l3_request(
      request,
      context,
      replay_reserver=lambda *_args: events.append("reserve"),
      resource_factory=lambda _validated: events.append("resource"),
  )
  assert events == ["reserve", "resource"]
  ```

- [ ] **Step 2: Run protocol/gate tests and verify they fail**

  Run: `/Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_protocol.py tests/engagement_v2/test_l3_gate.py -q`

  Expected: FAIL because frame type 8 and the L3 gate do not exist.

- [ ] **Step 3: Implement the frame and gate**

  Add enum value `EXECUTION_PERMIT = 8`, include it only in request frame types, and keep existing request frames valid. The gate validates the P4 run binding, decodes/verifies the permit, confirms the request header echoes permit authority/action/run/nonce, calls replay reservation, and only then calls the injected resource factory. This milestone's factory returns an inert validation token; it must not spawn a process, container, namespace, or mount.

- [ ] **Step 4: Run protocol, helper, permit, and gate suites and commit**

  Run:

  ```bash
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_protocol.py tests/engagement_v2/test_remote_runner_helper.py tests/engagement_v2/test_l3_permit.py tests/engagement_v2/test_l3_gate.py -q
  ```

  Commit: `feat(p5b): gate L3 frames before resource creation`

### Task 5: Fixed broker deployment contract

**Files:**
- Create: `src/hackbot/engagement_v2/l3_deployment.py`
- Create: `tests/engagement_v2/test_l3_deployment.py`

**Interfaces:**
- Produces: `L3DeploymentContract` and `validate_l3_deployment(document)`.
- Consumes: only canonical primitives and existing digest/identifier validation patterns.

- [ ] **Step 1: Add failing deployment-contract tests**

  The exact document fields are `schema_version`, `broker_path`, `broker_sha256`, `ssh_user`, `forced_command`, `interactive_shell`, `tty`, `port_forwarding`, `agent_forwarding`, `x11_forwarding`, and `permitted_signer_sha256`. The valid broker path and forced command are exactly `/usr/local/libexec/hackbot-l3-runner`; all five interactive/forwarding booleans are exactly `false`; user is exactly `hackbot-l3`; digests are lowercase `sha256:<64 hex>`.

  Test unknown/missing fields, relative/different command paths, non-boolean values, any enabled interactive feature, wrong user, tag/self-report fields, and malformed digests.

- [ ] **Step 2: Run tests and confirm the validator is absent**

  Run: `/Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_l3_deployment.py -q`

  Expected: FAIL on missing module.

- [ ] **Step 3: Implement the closed validator**

  ```python
  @dataclass(frozen=True)
  class L3DeploymentContract:
      broker_path: str
      broker_sha256: str
      ssh_user: str
      forced_command: str
      permitted_signer_sha256: str

  def validate_l3_deployment(document: Mapping[str, object]) -> L3DeploymentContract:
      if set(document) != _FIELDS or document.get("schema_version") != 1:
          raise ContractError(ReasonCode.INVALID_RUNNER)
      if any(document[name] is not False for name in _DISABLED_BOOLEAN_FIELDS):
          raise ContractError(ReasonCode.INVALID_RUNNER)
      # Validate exact path/user/digest values, then return the frozen record.
  ```

- [ ] **Step 4: Run focused tests and commit**

  Run:

  ```bash
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_l3_deployment.py tests/engagement_v2/test_remote_transport.py tests/engagement_v2/test_remote_helper.py -q
  ```

  Commit: `feat(p5b): validate fixed L3 broker deployment`

### Task 6: Milestone verification and OpenSpec progress

**Files:**
- Modify: `openspec/changes/engagement-v2-l3-catalog/tasks.md`

**Interfaces:**
- Consumes: completed Tasks 1–5 and fresh gate output.
- Produces: OpenSpec tasks 1.1–2.5 marked complete; tasks 3.1 onward unchanged.

- [ ] **Step 1: Run the complete milestone gate**

  ```bash
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/engagement_v2/test_l3_catalog.py tests/engagement_v2/test_l3_contracts.py tests/engagement_v2/test_l3_permit.py tests/engagement_v2/test_l3_gate.py tests/engagement_v2/test_l3_deployment.py tests/engagement_v2/test_v1_isolation.py -q
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest -q
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m ruff check .
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m ruff format --check .
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m mypy src/hackbot
  openspec validate engagement-v2-l3-catalog --strict --json
  /Users/clivoa/Documents/Github/bugbug/.venv/bin/python -m pytest tests/publication_guard -q
  git diff --check origin/main..HEAD
  ```

- [ ] **Step 2: Mark only proven tasks complete**

  Change checkboxes 1.1–1.5 and 2.1–2.5 from `[ ]` to `[x]`. Do not mark durable SQLite replay/rate work, OCI, broker execution, networking, adapters, remote lab, review, or delivery complete.

- [ ] **Step 3: Validate progress and commit**

  Run:

  ```bash
  openspec instructions apply --change engagement-v2-l3-catalog --json
  openspec validate engagement-v2-l3-catalog --strict --json
  git diff --check
  ```

  Expected OpenSpec progress: `10/90` tasks complete.

  Commit: `docs(p5b): record authority foundation milestone`

## Plan Self-Review

- Spec coverage: this plan covers only approved milestone 1 and OpenSpec tasks 1.1–2.5; tasks 3.1–13.7 remain explicitly outside this plan and unchecked.
- Placeholder scan: no placeholder marker, deferred code stub, generic error-handling instruction, or unspecified test step remains.
- Type consistency: `SnapshotBinding` is consumed by activation, decision, and permit issuance; `ExecutionPermitContext` is consumed by the frame gate; the frame gate's replay callback matches the later durable ledger key.
- Safety boundary: the milestone returns only inert validated tokens and adds no process/container/network execution path.
