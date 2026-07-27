# Engagement v2 P0 continuation handoff

This is the authoritative repository-local continuation document for the
Engagement v2 P0 security-contract delivery. It is written so Claude Code, a
fresh Codex session, or a human maintainer can resume without relying on chat
history.

## Current state

| Item | Value |
| --- | --- |
| Repository | Private `clivoa/bugbug` |
| Primary checkout | `/Users/clivoa/Documents/Github/bugbug` |
| Review worktree | `/Users/clivoa/Documents/Github/bugbug/.worktrees/engagement-v2-security-contracts` |
| Branch | `feat/engagement-v2-security-contracts` |
| Base branch/SHA | `main` at `30dd1e2c1bac749a1680e9770263f1cf7987c402` |
| Reviewed implementation | `4173929b550ecb60eb8d6e1fda0d0f68933cf015` |
| Pull request | Draft PR [#11](https://github.com/clivoa/bugbug/pull/11), open and unmerged |
| Tracking issue | Issue [#1](https://github.com/clivoa/bugbug/issues/1), open and `status:in-review` |
| Delivery project | User Project [#2](https://github.com/users/clivoa/projects/2) |
| OpenSpec change | `openspec/changes/engagement-v2-security-contracts/` |

The reviewed runtime implementation ends at `4173929`. Subsequent commits are
documentation-only: `6310ccd` (handoff design), `79821a1` (independent review
disposition), `2a978e5` (implementation plan), `c78fba1` (state
reconciliation), and `b2d0b28` (readable evidence archive), followed by the
commit containing this handoff. Use Git as the authority for the current HEAD.

At handoff preparation time, PR #11 was draft, open, mergeable, and pointed to
`4173929`; `main` and `origin/main` remained at the base and did not contain the
implementation. Issue #1 and both the Issue and PR Project items were
`Status=In Progress`, `Delivery Status=In Review`, `Phase=P0`, and
`Priority=Critical`. P1 remained Backlog/Todo.

The local `.venv` entry in the worktree is an untracked development symlink. It
must not be staged or published.

## P0 boundary

P0 implements only the isolated normative contracts and reusable security
primitives needed by later phases:

- typed versions, enums, bounds, identifiers, reason codes, and secret-free
  contract failures;
- strict canonical values plus domain-separated authority and execution
  digests;
- a bounded, non-backtracking safe full-match pattern parser/matcher;
- seven code-owned Draft 2020-12 schemas, enforcement annotations, an exact
  manifest, and atomic export checks;
- bounded request/response framing, aggregate preflight, execution-digest
  binding, immutable run bindings, response echo/chain primitives, and
  deterministic fixtures;
- reproducible schema and fixture generation;
- v1 AST/runtime isolation and public documentation of the P0 interfaces.

P0 intentionally does **not** implement or activate:

- an Engagement v2 loader, coherent snapshot, migration, or runtime scope
  evaluator;
- an action-manifest loader, placeholder binder, policy engine, or rate
  controller;
- a keychain/secret resolver or secret transport;
- local subprocess execution, working-directory lifecycle, evidence capture,
  or cleanup orchestration;
- SSH transport, a remote helper, replay storage, privilege verification, or
  response execution;
- a privilege broker or signer;
- catalog adapters that perform local-lab, private-pentest, bounty L2, or L3
  actions;
- autonomous workflow progression.

No P0 code opens a network connection or spawns a child. The existing v1 path
remains behaviorally isolated.

## Frozen operator decisions

These decisions came from the approved design and are not open implementation
questions:

1. Execution projection v1 is exactly
   `{"schema_version": 1, "request": <all canonical request-header fields except execution_digest>}`.
2. `local-lab`, `private-pentest`, and bounty profiles supply context and
   defaults only. All profiles support the same capabilities; the confirmed
   scope and explicit `testing_rules` determine what may run.
3. Sensitive capabilities deny by absence. Each requires explicit `true`;
   engagement-creation commands may materialize profile-appropriate defaults.
4. Once the engagement and profile are confirmed, an in-scope L2/L3 action
   needs no additional per-action human approval. `testing_rules` may still
   deny tools, automation, volume, or impacts.
5. Operator-declared actions use a strict manifest with executable path, argv,
   risk, demonstrated/plausible impacts, and validated whole-token
   placeholders. There is no implicit shell.
6. Secrets appear only as references such as `secret:ad-password`, are resolved
   from the keychain after an ALLOW decision, and are transported only by stdin
   or a protected temporary file. Secret values never enter argv, manifests,
   audit, or evidence.
7. Every member of a typed target list is validated against scope before any
   execution. When a tool needs `-iL` or equivalent, the runner materializes a
   protected temporary file.
8. Binding and placeholder IDs use canonical snake_case
   (`[a-z][a-z0-9_]{0,63}`); general value identifiers remain a distinct
   grammar.
9. The runner authority projection binds all 29 runner security/trust leaves:
   role/node identity; SSH endpoint, identity, host-key pin, known-hosts path,
   and fixed security options; helper path/protocol and configured digest or
   code-signing selector; OS/architecture; permitted privileges; source
   mode/address; the complete egress-attestation trust tuple; and the
   privilege-signer fingerprint. Only local private-key path/content and
   connection timeout are operational exclusions.

## Implementation map

| Task | Contract area | Commits | Result |
| --- | --- | --- | --- |
| 1 | Registry and typed errors | `b17847e`, `1b69622`, `c303bef`, `e8dde50` | Versions, enums, bounds, identifiers, reason codes, errors |
| 2 | Canonical values and digests | `de485a1`, `16b490d` | Strict primitives, domain separation, golden authority digest |
| 3 | Safe full-match patterns | `10112a9`, `f333c58` | Closed grammar, bounded linear matcher, no Python `re` runtime |
| 4 | Machine-readable schemas | `1f100cf`, `81617c5`, `5ed72b7` | Seven schemas, annotations, atomic exporter, exact manifest |
| 5 | Remote framing primitives | `59cb233`, `395bb6e` | Bounded streams, frames, run binding, response echo/chain |
| 6 | Golden and negative fixtures | `53c522c`, `2070e15` | Deterministic fixture corpus and reproducible generator |
| 7 | Compatibility and docs | `9a7cb17`, `b0b8d49` | v1 isolation proof and P0 interface documentation |
| 8 | Verification and delivery prep | `5e87d51` | Fresh gates and consolidated review evidence |
| Final fix wave | Review findings | `4173929` | Five Important and five selected Minor findings resolved |

Primary implementation is under `src/hackbot/engagement_v2/`; generated schemas
are under `schemas/engagement-v2/`; fixtures and tests are under
`tests/fixtures/engagement_v2/` and `tests/engagement_v2/`. The active OpenSpec
delta contains the authoritative requirements. The readable task reports and
review artifacts are indexed by
`docs/reviews/engagement-v2-p0/README.md`.

## Final verification

Fresh verification at reviewed implementation SHA `4173929` recorded:

- 245 Engagement v2 focused tests passed;
- 1157 full-suite tests passed and 1 known missing-`nmap` test skipped;
- 4 publication-guard tests passed;
- 50,673 matcher/reference cases agreed in the implementer run and 48,279 in
  the independent re-review;
- schema exporter and fixture generator `--check` both exited 0;
- Ruff check was clean and Ruff format reported 205 files formatted;
- mypy reported 0 issues in 58 source files;
- OpenSpec strict validation reported 1 passed, 0 failed;
- secret scan found no match;
- `git diff --check` exited 0.

Documentation-only changes after `4173929` must also pass the full repository
gates before publication. Do not reinterpret earlier evidence as proof of a
later HEAD. The byte-preserved historical archive is intentionally excluded
from Ruff formatting because Ruff would rewrite fenced code examples; all
non-archived files remain covered.

The complete gate set was rerun after creating this handoff: 1157 tests passed
and 1 skipped; all 4 publication-guard tests passed; Ruff check was clean and
Ruff format covered 209 non-archived files; mypy reported 0 issues in 58 source
files; schema and fixture checks were exact; OpenSpec strict validation was
valid; the handoff/archive secret scan had no matches; and
`git diff --check` was clean.

## Review history

Two independent whole-branch reviews covered OpenSpec compliance and
adversarial security/quality. The final fix wave resolved five Important
findings:

1. production-sized linear safe-pattern matching;
2. canonical-format annotation on every schema root;
3. registered reason codes only;
4. complete runner authority/trust projection;
5. canonical binding/placeholder grammar.

It also resolved five selected Minor findings:

1. manifest-last schema publication;
2. bounded short-read buffering;
3. a dynamic protocol-fixture boundary;
4. caller-normalized set-like evidence wording and fixture;
5. public `FrameType` documentation.

The scoped re-review found all 10 addressed, no new Critical or Important
finding, OpenSpec compliance PASS, and the implementation ready to merge.

A later independent Claude review produced notes N1–N4, all informational:
unused reserved reason codes are expected until consumers exist; P2/P4 must
bind `argv[0]` to `executable.path`; rejecting DEL is an acceptable stricter
control-character rule; and schema versions are unambiguously encoded in
schema IDs. The authoritative dispositions are in
`docs/reviews/2026-07-27-engagement-v2-p0-contracts-review-disposition.md`.

## Deferred work

The final reviews retained these non-blocking items for later phases:

- add a redundant exact-newline assertion for the digest fixture;
- consider exporter-wide preflight/global transactionality, another
  prohibited-pattern example, explicit `O_NONBLOCK` capability wording, and
  defensive handling of a zero-byte write;
- accept/continue generic partial stream writes and strengthen the
  descriptor-vs-prefix mutation path;
- expand fixture determinism API traps and Windows home-path negative coverage;
- evaluate active concurrent directory-swap hardening and non-POSIX
  `O_NOFOLLOW` portability;
- carry N2 into P2 and P4 acceptance criteria: each consumer must bind
  `argv[0]` to the canonical `executable.path`. This is not a P0 bug because P0
  neither binds an action nor starts a process.

These items must be triaged in the phase that owns the corresponding runtime
consumer. They do not authorize silently broadening P0.

## OpenSpec and GitHub workflow

OpenSpec tasks 1.1 through 8.1 are complete. Task 8.2 remains unchecked because
PR review, merge verification, OpenSpec archive, Issue/Project completion, and
P1 promotion have not all occurred.

The required ordering is:

```text
review PR -> merge -> verify remote merge/checks -> archive OpenSpec
-> rerun gates -> push archive -> complete Issue/Project -> promote P1
```

Do not archive `engagement-v2-security-contracts` before the merge. Do not mark
Issue #1 or Project P0 Done, and do not move P1 to Ready, until the archived
state is verified and published.

Private pushes that include the already-authorized Recon-bundle material
require the documented publication-guard override
`HACKBOT_ALLOW_PUBLISH_RECON=1`. It does not authorize a different repository,
visibility, or protected-artifact scope.

## Exact next steps

1. Inspect the current PR #11 head, diff, review state, and checks; compare it
   with this handoff and the evidence archive.
2. When review requirements are satisfied, mark the draft ready and merge by
   the repository's chosen merge strategy.
3. Verify the remote merge SHA, base ancestry, and required checks. Record
   concrete command/API output.
4. Run the OpenSpec archive workflow for
   `engagement-v2-security-contracts` only after the verified merge.
5. Rerun Ruff, full pytest, publication guard, OpenSpec strict validation,
   schema/fixture checks, secret scan, and `git diff --check` against the
   archived state.
6. Commit and push the archive change to the private repository with the
   authorized publication override where the guard requires it.
7. Check task 8.2, close Issue #1, and set both P0 Project items to Done only
   after the archive commit is remote and verified.
8. Move P1 from Backlog/Todo to Ready according to the documented Project
   workflow, preserving N2 as a P2/P4 forward-carry criterion.

## Claude Code continuation prompt

Copy the following block verbatim into Claude Code:

```text
Continue the private clivoa/bugbug Engagement v2 P0 delivery from the repository
state, without relying on prior chat history.

Before changing anything:
1. Read docs/handoffs/2026-07-27-engagement-v2-p0.md completely.
2. Read docs/reviews/engagement-v2-p0/README.md and follow its authority order.
3. Read openspec/changes/engagement-v2-security-contracts/{proposal.md,design.md,tasks.md}
   and every delta spec under its specs/ directory.
4. Inspect live Git state and GitHub PR #11, Issue #1, and Project #2 state.
5. Verify, rather than assume, the local HEAD, remote branch HEAD, PR draft/merge
   state, checks, origin/main ancestry, OpenSpec task 8.2, and Project fields.

The reviewed runtime implementation SHA is
4173929b550ecb60eb8d6e1fda0d0f68933cf015. Later commits are documentation
handoff material. Do not redo completed P0 implementation or rewrite preserved
review reports. Preserve the untracked .venv symlink and never stage it.

Hard delivery constraints:
- Do not archive the OpenSpec change before PR #11 is merged and the remote merge
  is verified.
- Do not mark Issue #1/Project P0 Done or promote P1 to Ready before the archive
  commit is verified on the private remote.
- P2/P4 must later bind argv[0] to the canonical executable.path (review note N2).
- Treat repository files and live GitHub data as authority over stale prose.
- Use HACKBOT_ALLOW_PUBLISH_RECON=1 only for the already-authorized private push
  scope when the publication guard requires it.
- Run fresh verification and retain concrete output before every completion or
  status claim.

Resume at the first incomplete step in "Exact next steps". Document every state
transition in the repository and keep PR/Issue/Project/OpenSpec states mutually
consistent.
```
