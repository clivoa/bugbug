## ADDED Requirements

### Requirement: Secrets resolve only after ALLOW
Secret references SHALL be resolved only after policy returned `ALLOW`, never
during validation, binding, or a denied decision. A failure to resolve a required
secret SHALL fail closed before `spawned`, so no child runs without its declared
material.

#### Scenario: No resolution before ALLOW
- **WHEN** a request is validated, bound, or denied
- **THEN** no secret is read or resolved

#### Scenario: Missing secret fails closed before spawn
- **WHEN** a required secret cannot be resolved after `ALLOW`
- **THEN** the run fails before `spawned`, `executed` is false, and the audit records a secret-free failure reason

### Requirement: Engagement-namespaced resolution
A secret SHALL be resolved only within the active engagement's namespace identity.
The executor SHALL NOT look up or accept a secret belonging to a different
engagement, and a reference that resolves only under another engagement SHALL fail
closed.

#### Scenario: No cross-engagement lookup
- **WHEN** a secret reference exists only under a different engagement identity
- **THEN** resolution fails closed and no secret is delivered to the child

### Requirement: Protected delivery only
Resolved secret material SHALL reach the child only through `stdin` or a
protected, exclusively-created file with mode `0600` (memory-backed when
available), matching the action's declared transport. Secret names and values
SHALL NOT enter argv, the environment, the audit record, evidence, or error
messages, and secret files SHALL be removed as part of resource cleanup.

#### Scenario: File transport is protected and cleaned up
- **WHEN** an action declares the `file` secret transport
- **THEN** the secret is written to a mode-`0600` exclusive file inside the private run directory and removed during resource cleanup

#### Scenario: Secrets never enter argv or audit
- **WHEN** a run uses a resolved secret
- **THEN** no secret name or value appears in argv, the environment, the audit record, evidence, or any error
