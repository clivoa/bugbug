# OpenSpec and GitHub Project workflow

**Adopted:** 2026-07-26

## Purpose

Hackbot uses repository-local OpenSpec artifacts as the versioned behavioral
agreement for new changes. GitHub Issues and the linked GitHub Project show
delivery status; they do not replace the specifications.

The initial integration was generated with OpenSpec CLI 1.6.0 on Node.js
22.22.2, with telemetry disabled during setup. Future CLI upgrades must run
`openspec update`, review generated diffs, and pass `openspec doctor` plus
strict validation before commit.

## Sources of truth

| Concern | Source |
|---|---|
| Current implemented behavior | `openspec/specs/**` after an implemented change is archived |
| Proposed behavior | `openspec/changes/<change>/**` |
| Umbrella architecture and rationale | `docs/superpowers/specs/**` |
| External-review decisions | `docs/reviews/**` |
| Delivery status and ownership | linked GitHub Project and Issues |
| Code truth | source, tests, build artifacts, and fresh verification output |

Chat history, Project fields, issue summaries, and model output are never the
only authority for behavior.

## GitHub locations

- Private repository: <https://github.com/clivoa/bugbug>
- Delivery Project: <https://github.com/users/clivoa/projects/2>

The repository is linked to the Project. Its code/default branch remains
private. The initial `main` publication was explicitly authorized on
2026-07-26 for the Recon-bundle and its derived artifacts; the local
publication guard recorded that one push through its documented override.
Future pushes containing protected material still require the same deliberate
operator acknowledgement.

## Change lifecycle

1. Explore the relevant current code and documents.
2. Create one focused OpenSpec change and place its Project item in **Ready**
   after proposal review; unscheduled work remains in **Backlog**.
3. Write and review `proposal.md`, delta requirements/scenarios, `design.md`,
   and `tasks.md`.
4. Link one GitHub issue to the change directory and Project item.
5. Move the Project item to **In Progress** only when implementation starts.
6. Implement with tests first and update the OpenSpec task checklist from fresh
   evidence.
7. Move the item to **In Review**, then review, verify, and merge.
8. Archive the OpenSpec change so its delta becomes current behavior.
9. Move the Project item to **Done** only after archive and merge.

Project status is never inferred from an unchecked local task. A blocked item
records its blocker in the issue and remains non-Done.

## Engagement v2 delivery map

The umbrella design is decomposed into:

- P0 normative security contracts;
- P1 engagement loader and scope v2;
- P2 action manifest, binder, and policy;
- P3 local executor, secrets, evidence, and cleanup;
- P4 remote helper and trust protocol;
- P5a non-credential internal recon catalog;
- P5b credential and L3 catalog;
- P6 autonomous workflow contract;
- P7 effective migration, documentation, and release.

P0 is the first OpenSpec change. Dependent code changes cannot begin until its
normative constants and scenarios are approved. P6 remains unavailable until
its own schema and state machine are approved and implemented. Effective
migration remains P7.

## GitHub Project fields

The Project uses:

- **Delivery Status:** Backlog, Ready, In Progress, In Review, Done;
- **Phase:** P0, P1, P2, P3, P4, P5a, P5b, P6, P7;
- **Priority:** Critical, High, Medium, Low;
- **OpenSpec change:** the repository-relative change path or planned slug.

GitHub's built-in **Status** mirrors coarse `Todo`, `In Progress`, and `Done`
state. **Delivery Status** is the canonical detailed workflow field.

The repository README or `docs/next-steps.md` may summarize the roadmap, but the
Project is the operational view and OpenSpec is the behavioral record.

## Initial Project inventory

| Phase | Issue | Initial delivery status |
|---|---|---|
| P0 | [#1 — normative security contracts](https://github.com/clivoa/bugbug/issues/1) | Ready |
| P1 | [#2 — loader, authority digest, scope v2](https://github.com/clivoa/bugbug/issues/2) | Backlog |
| P2 | [#3 — manifest, binder, policy](https://github.com/clivoa/bugbug/issues/3) | Backlog |
| P3 | [#5 — local executor, secrets, evidence, cleanup](https://github.com/clivoa/bugbug/issues/5) | Backlog |
| P4 | [#4 — remote helper and trust protocol](https://github.com/clivoa/bugbug/issues/4) | Backlog |
| P5a | [#6 — non-credential internal recon](https://github.com/clivoa/bugbug/issues/6) | Backlog |
| P5b | [#10 — credential/L3 catalog](https://github.com/clivoa/bugbug/issues/10) | Backlog |
| P6 | [#8 — autonomous workflows](https://github.com/clivoa/bugbug/issues/8) | Backlog |
| P7 | [#7 — migration, docs, release](https://github.com/clivoa/bugbug/issues/7) | Backlog |
| Program | [#9 — OpenSpec adoption and reviews](https://github.com/clivoa/bugbug/issues/9) | Done/closed |

## Agent use

OpenSpec was initialized for Codex and Claude. Generated project-local skills
and commands live under `.codex/` and `.claude/`. Agents must use the same
repository artifacts, respect the current change boundary, and avoid parallel
edits to shared files. A second agent is best assigned a read-only audit or an
independent change whose dependencies and files do not overlap.

## References

- [OpenSpec: existing projects](https://github.com/Fission-AI/OpenSpec/blob/main/docs/existing-projects.md)
- [OpenSpec: core concepts](https://github.com/Fission-AI/OpenSpec/blob/main/docs/overview.md)
- [OpenSpec repository](https://github.com/Fission-AI/OpenSpec)
