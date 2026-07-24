# Reference Review

Review of every reference project the Hackbot design was asked to inspect. Each
was **cloned** into `references/external/` (git-ignored, not vendored) and read at
the architecture level. For each: what it is, reusable concepts, weak security
assumptions, license, duplicated functionality, macOS/portability concerns,
hardcoded model/provider assumptions, autonomous actions that should require
approval, and the disposition — **adopt / rewrite / exclude / isolate**.

> Disposition legend
> - **Adopt (pattern)** — reuse the *idea/structure* (not copyrightable) in clean-room code.
> - **Adopt (attributed)** — adapt substantial licensed text/code; keep the attribution + license.
> - **Rewrite** — take methodology only; discard the implementation.
> - **Isolate** — reference-only; do not copy code or link against it.
> - **Exclude** — not used.

Licenses are summarized here and tracked authoritatively in
[`licenses-and-attribution.md`](./licenses-and-attribution.md).

---

## Skill-format & methodology references

### cloudflare/security-audit-skill — MIT
- **What**: A single `security-audit` Agent-Skill: `SKILL.md` + on-demand topic files
  (`RECONNAISSANCE.md`, `ATTACK-CLASSES.md`, `VALIDATION-AND-REPORTING.md`, …), a
  `report-schema.json`, and a `validate-findings.cjs` verifier. Deliberately
  "agent-neutral" (abstracts the Task/subagent mechanism).
- **Reusable**: The exact skill packaging we want — a thin router `SKILL.md` that
  loads deep content on demand; a JSON report schema; a **code** validator that
  checks findings rather than trusting the model. Phased pipeline (recon → hunt →
  validate → report) with subagents that return data instead of writing files.
- **Weak assumptions**: Writes run artifacts under `~/security-audit-skill/…`
  (outside the project); we keep everything inside the engagement dir. It is a
  source-audit skill, so it has no network scope engine (not its job).
- **Disposition**: **Adopt (pattern)** for the skill format, report schema shape,
  and on-demand loading. Our `skills/` follow this layout.

### trailofbits/skills — CC BY-SA 4.0  ⚠️ copyleft on adapted text
- **What**: A large `plugins/*/skills/*/SKILL.md` collection (e.g.
  `burpsuite-project-parser` with `allowed-tools: Bash Read`). Clean frontmatter
  with `name`, `description`, `allowed-tools`.
- **Reusable**: The `allowed-tools` frontmatter field (per-skill tool allowlisting)
  and the Burp-project-parsing idea.
- **License caveat**: **BY-SA 4.0** means if we adapt their *prose* substantially,
  our derivative text inherits ShareAlike. To avoid relicensing our whole skill
  tree, we learn the **structure** (not copyrightable) and write original text.
- **Disposition**: **Adopt (pattern)** only — frontmatter shape + tool-allowlist
  idea. **No prose copied.** Any future direct adaptation goes in an isolated,
  BY-SA-labeled directory.

### yaklang/hack-skills — MIT
- **What**: ~40 vulnerability-class skill folders (SSTI, XXE, prototype-pollution,
  SAML, GraphQL, sandbox-escape, defi-attack-patterns, …), each a methodology
  `.md` with an "AI LOAD INSTRUCTION" header for on-demand loading.
- **Reusable**: Breadth of vuln-class methodology; the load-instruction convention;
  good source of *detection indicators* per class (rewritten in our words).
- **Weak assumptions**: Pure prose skills that assume the agent will run arbitrary
  commands; no scope/risk gating; some content (browser/V8, process-injection) is
  exploit-dev oriented and out of scope for bug-bounty recon.
- **Disposition**: **Rewrite** — mine for vuln-class detection indicators and safe
  test procedures; every executable step goes through our tool adapters + risk gate.

### 0xN0RMXL/BugBountySkills — MIT
- **What**: Knowledge-base heavy (CHECKLISTS, KNOWLEDGE_BASE, MASTER_SYSTEM_PROMPTS,
  SKILL_FILES, SAMPLES). Prompt/checklist library, not an engine.
- **Reusable**: Checklists for evidence hygiene and per-class coverage; sample
  report structures.
- **Weak assumptions**: "Master system prompts" encourage broad autonomy; no code
  enforcement. 61 MB of mixed material.
- **Disposition**: **Rewrite** — cherry-pick checklists into our `skills/reporting`
  and `evidence-hygiene`, re-authored.

---

## Agentic bug-bounty / harness references

### elementalsouls/Claude-BugHunter — MIT
- **What**: The closest sibling. A Python `engine/` with `scope.py`, `recon.py`,
  `osint.py`, `state.py`, `skill_map.py`, `agent.py`; a `skills/hunt-*` tree; a
  `burp-mcp.json.example`; `engagement.example.json`.
- **Reusable (high value)**: `scope.py` is a **deterministic, code-enforced** scope
  checker — "scope is enforced in CODE, not by trusting an LLM. Deny wins.
  Default deny." Pattern forms: apex+subdomain, `*.`, exact host, CIDR, `re:`.
  This is exactly our required model. `skill_map.py` (skill routing) and the
  engagement state layout are directly informative.
- **Weak assumptions**: Engine "may run unattended" — we keep a hard human gate at
  Level 2. Burp config is by example file (fine); provider layer is Claude-centric.
- **Disposition**: **Adopt (attributed)** — our `src/hackbot/scope/` adapts the
  `scope.py` deny-wins/default-deny logic with attribution + MIT notice. Everything
  else: **Rewrite**.

### gadievron/raptor — MIT
- **What**: Large (82 MB) agentic security platform: `raptor_agentic.py`,
  `raptor_codeql.py`, `raptor_fuzzing.py`, `core/`, `engine/`, `plugins/`,
  `tiers/`, `libexec/`. CITATION.cff (academic).
- **Reusable**: The **tiered execution** concept (capability tiers), plugin
  architecture, and separation of agentic/codeql/fuzzing entry points inform our
  profile + risk-tier design.
- **Weak assumptions**: Heavyweight; CodeQL/fuzzing pull large deps; broad autonomy
  in the agentic path.
- **Disposition**: **Rewrite** — borrow the tier/plugin *concepts*; do not vendor.

### capitalone/vulnhunter — Apache-2.0
- **What**: SAST-oriented harness (`harness/`, `vulnhunt`, `vulnhunt-fix-verify`,
  `vulnhunter-agent`) with `install.sh`/`uninstall.sh`, CODEOWNERS, SECURITY.md.
- **Reusable**: The **fix→verify** loop (validate a finding, then verify a
  remediation) informs our validation-gate + report remediation section. Clean
  install/uninstall discipline.
- **Disposition**: **Rewrite** — validation/verify loop concept; source-review skill.

### cisco-open/ai-deep-sast — Apache-2.0
- **What**: Deep SAST with an LLM: `detector.py`, `rule_matcher.py`, `indexer.py`,
  `redactor.py`, `finding_store.py`, `llm_client.py`, `deepscan_reporter.py`,
  ASVS/CodeGuard loaders, a local `foundation-sec-model`.
- **Reusable (high value)**: **`redactor.py`** (redact before sending to the model)
  and **`finding_store.py`** (structured finding persistence) map directly to our
  evidence redaction + findings store. ASVS mapping for report rigor. Provider is
  behind `llm_client.py` (swappable) — good.
- **Disposition**: **Adopt (pattern)** — redaction-before-LLM and finding-store
  shapes; **Rewrite** the SAST engine into our `source-review` skill.

### google/mantis — Apache-2.0
- **What**: A multi-agent methodology expressed as `mantis-*` agent folders
  (architecture, threat-model, plan, reproduce, critic, dedupe, report, review,
  reflect, calibrate…) + a top-level `schema.json`, `AGENTS.md`.
- **Reusable (high value)**: The **agent decomposition** for a security workflow —
  especially `threat-model`, `reproduce`, `dedupe` (duplicate-risk!), `critic`
  (second-opinion review), `calibrate` (severity). Directly informs our
  hypothesis → validate (second model) → dedupe → report pipeline and the
  `schema.json` for structured hand-offs.
- **Disposition**: **Adopt (pattern)** — workflow decomposition + schema-driven
  hand-offs; agent names inform our workflow stages.

### anthropics/defending-code-reference-harness — Apache-2.0
- **What**: A reference harness (`dnr_harness/`, `harness/`, `targets/`, `tests/`,
  `CLAUDE.md`) for evaluating code defensively against untrusted targets.
- **Reusable (high value)**: The **untrusted-target boundary** discipline and test
  `targets/` pattern — a template for our prompt-injection test corpus (Phase 19)
  and for structuring "target content is data, never instructions."
- **Disposition**: **Adopt (pattern)** — untrusted-content boundaries + test-target
  structure for our injection tests.

### visa/visa-vulnerability-agentic-harness — Apache-2.0 (+ NOTICE, THIRD_PARTY_LICENSES)
- **What**: Python harness `vvaharness/` with a **backend abstraction**
  (`backends/agent_sdk.py`, `backends/sdk.py`, `backends/claude_cli.py`), a
  pipeline, `util/prompts.py`, `util/redact` (tested via `tests/test_redact.py`),
  and checkpoint/resume tests (`test_checkpoints.py`, `test_validate_resume.py`).
- **Reusable (high value)**: **Provider/back-end abstraction** (CLI vs SDK) is our
  gateway/provider-interface blueprint; **redaction with dedicated tests**;
  **checkpointed, resumable validation**. Ships NOTICE + THIRD_PARTY_LICENSES —
  the compliance discipline we mirror.
- **Disposition**: **Adopt (pattern)** — backend abstraction, redaction test
  discipline, checkpoint/resume; **Rewrite** implementation.

---

## MCP references

### PortSwigger/mcp-server — GPL-3.0  ⚠️ strong copyleft
- **What**: Official Burp MCP as a Burp extension (Kotlin/Gradle). Modules:
  `tools/Tools.kt`, `config/TargetValidation.kt`, `security/CredentialFilter.kt`,
  `security/HttpRequestSecurity.kt`, `security/DataAccessSecurity.kt`,
  `config/components/AutoApproveTargetsPanel.kt`. SSE server + packaged stdio proxy.
- **Reusable (interface only)**: Confirms our defaults — **loopback `127.0.0.1:9876`**,
  SSE **or** stdio proxy, **target validation/approval**, **credential filtering**
  before data leaves Burp, **auto-approve targets empty by default**, and a
  read-only vs state-changing tool split.
- **License caveat**: GPL-3.0. We **run** it as an installed extension and talk to
  it over MCP (mere use/aggregation — fine). We **copy no Kotlin source** into
  Hackbot and do not link against it.
- **Disposition**: **Adopt (interface)** + **Isolate (code)** — integrate via the
  MCP protocol; mirror its security defaults in our own config; never vendor code.

### shuvonsec/claude-bug-bounty — MIT
- **What**: Claude-Code-centric toolkit: `agent.py`, `brain.py`, `engine.py`,
  `hooks/hooks.json`, `rules/`, `mcp/` (burp-mcp-client, caido-mcp-client,
  hackerone-mcp), `install.sh`.
- **Reusable**: The idea of enforcing scope via **Claude Code hooks** (pre-tool-use
  safety checks) is valuable; multi-MCP client set (Burp/Caido/H1).
- **⚠️ Weak assumption (important)**: `install.sh` places hooks in **`~/.claude/hooks/`
  (global)** and loads them from the user profile — this **violates our strict
  isolation requirement**. We implement the same guard as **project-local** hooks
  under `bugbug/.claude/` only.
- **Disposition**: **Rewrite** — adopt the pre-tool-use scope-hook *concept*, but
  project-scoped; never touch `~/.claude`.

### shuvonsec/web3-bug-bounty-hunting-ai-skills — MIT
- **What**: Web3 skill set: `web3-solidity-audit-mcp`, `web3-hunt-foundation`,
  `web3-poc-foundry`, `web3-grep-arsenal`, `web3-triage-report`, zkSync/zkEra hunts.
- **Reusable**: Structure for our `skills/web3` pack — Slither/Aderyn + Foundry
  fork-PoC workflow, grep arsenal for Solidity, triage/report format.
- **Disposition**: **Rewrite** — re-author web3 skills in our format; Foundry stays
  behind an explicit feature flag and PoCs run only against local forks.

---

## Rewrite-only / isolate references

### yashab-cyber/hackbot — MIT
- **What**: A pip-installable AI security CLI named `hackbot` (Docker, `hackbot/`
  package, website). Namesake of the *command* we build, but a different design.
- **Reusable**: CLI ergonomics and packaging ideas only. Naming: our command is
  also `hackbot`; we note the unrelated MIT project for attribution/avoidance of
  confusion. No code shared.
- **Disposition**: **Rewrite** — independent implementation; acknowledge namesake.

### elder-plinius/T3MP3ST — AGPL-3.0  ⚠️⚠️ network copyleft
- **What**: Large TypeScript multi-tenant agent platform (bench, ctf, tools, src),
  WHITEPAPER/VISION. Offensive-leaning autonomy.
- **License caveat**: **AGPL-3.0** — strong copyleft with a network-use clause.
  Copying/linking would impose AGPL on our project.
- **Disposition**: **Isolate** — strictly reference-only. **No code, no prose
  adapted.** Any autonomous-multi-target patterns here are explicitly *out of
  scope* for Hackbot's safety model.

### DevCop95/bugbounty-lab101 — MIT
- **What**: Lab/practice repo (`auto-scanner`, `bugbounty`, `programs`,
  `legacy-vm-practice`, `start-server.sh`).
- **Reusable**: Local-lab layout ideas; sample program files.
- **Disposition**: **Rewrite** — informs `labs/` and sample program fixtures; the
  `auto-scanner` is the anti-pattern we avoid (no unattended scanning).

---

## Cross-cutting conclusions

**Adopted patterns (clean-room or attributed):**
1. Agent-Skills packaging (Cloudflare / ToB) → `skills/**` + on-demand loading.
2. Deny-wins/default-deny **code** scope engine (elementalsouls, attributed) → `src/hackbot/scope/`.
3. Redaction-before-LLM + structured finding store (cisco, visa) → `evidence/`, `findings/`.
4. Provider/back-end abstraction (visa) → `src/hackbot/providers/` + gateway.
5. Workflow decomposition + schema hand-offs, incl. dedupe/critic/calibrate (mantis) → `workflows/`.
6. Untrusted-target boundaries + test corpus (anthropics harness) → Phase-19 injection tests.
7. Burp MCP security defaults & loopback (PortSwigger, interface only) → `mcp/burp`.

**Weak assumptions we explicitly reject:**
- Models building raw shell strings → we use validated `argv` arrays only.
- Scope left to the prompt → enforced in code, deny-wins.
- Global config/hook installation (`~/.claude`, `~/.zshrc`) → project-local only.
- Secrets in env/argv/examples → Keychain/secret-service backend, stdin entry.
- Unattended progression recon→exploit → hard Level-2 human gate.
- Trusting MCP/tool/target output as instructions → treated as untrusted data.

**Portability note (per operator request):** design is OS-agnostic with a
Darwin/Linux focus. GNU-only assumptions in references are replaced by a platform
shim; the optional Linux SSH runner is modeled explicitly (see `architecture.md`).

**License compliance:** GPL (PortSwigger) integrated via protocol only; AGPL
(T3MP3ST) isolated; BY-SA (ToB) used as pattern only. All adopted MIT/Apache
material carries attribution in [`licenses-and-attribution.md`](./licenses-and-attribution.md).
