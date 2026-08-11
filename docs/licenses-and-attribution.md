# Licenses & Attribution

Authoritative ledger of third-party material the Hackbot (`bugbug`) project was
inspected against or derives patterns from.

**Principles**
- Presence of content is **not** permission to reuse. When no license exists, the
  material is **reference-only** unless the operator explicitly authorizes reuse.
- GPL/AGPL code is never vendored or linked; it is used only via protocol/process
  boundaries (mere use / aggregation).
- CC BY-SA text is not copied into our permissively-structured skill tree; only
  non-copyrightable structure is reused.
- Every adopted MIT/Apache file that materially influences our code keeps a
  header attribution and appears here.

---

## 1. Reference repositories

Cloned to `references/external/` (git-ignored). Dispositions detailed in
[`reference-review.md`](./reference-review.md).

| Project | License | Reuse in Hackbot | Obligation |
|---|---|---|---|
| cloudflare/security-audit-skill | **MIT** | Skill-format pattern | Keep MIT notice if any file adapted |
| trailofbits/skills | **CC BY-SA 4.0** | Structure/idea only (no prose) | ShareAlike **avoided** by not copying text |
| yaklang/hack-skills | **MIT** | Vuln-class methodology (rewritten) | Attribution if text adapted |
| 0xN0RMXL/BugBountySkills | **MIT** | Checklists (rewritten) | Attribution if text adapted |
| elementalsouls/Claude-BugHunter | **MIT** | **scope.py logic adapted (attributed)** | MIT notice in `src/hackbot/scope/` |
| gadievron/raptor | **MIT** | Tier/plugin concepts | Attribution if code adapted |
| capitalone/vulnhunter | **Apache-2.0** | fix->verify concept | NOTICE if code adapted |
| cisco-open/ai-deep-sast | **Apache-2.0** | redaction + finding-store patterns | NOTICE if code adapted |
| google/mantis | **Apache-2.0** | Workflow decomposition + schema | NOTICE if code adapted |
| anthropics/defending-code-reference-harness | **Apache-2.0** | Untrusted-content boundaries + test targets | NOTICE if code adapted |
| visa/visa-vulnerability-agentic-harness | **Apache-2.0** | Backend abstraction, redaction tests, checkpoint/resume | NOTICE + THIRD_PARTY passthrough |
| PortSwigger/mcp-server | **GPL-3.0** | **Interface/defaults only — no code vendored** | Integrate via MCP protocol; not linked |
| shuvonsec/claude-bug-bounty | **MIT** | Pre-tool-use scope-hook concept (project-local) | Attribution if code adapted |
| shuvonsec/web3-...-ai-skills | **MIT** | Web3 skill structure (rewritten) | Attribution if text adapted |
| yashab-cyber/hackbot | **MIT** | Namesake only; no code shared | Note namesake |
| DevCop95/bugbounty-lab101 | **MIT** | Lab layout ideas | Attribution if code adapted |
| elder-plinius/T3MP3ST | **AGPL-3.0** | **Isolated — reference-only, nothing copied** | Not vendored/linked |

### Currently adopted (attributed) code
| Hackbot path | Source | License | Note |
|---|---|---|---|
| `src/hackbot/scope/` (planned) | elementalsouls/Claude-BugHunter `engine/scope.py` | MIT (c) 2026 Sachin Sharma | deny-wins/default-deny matcher logic adapted |

As additional files are adapted, add a row here and a header comment in the file:
`# Adapted from <project> (<license>, (c) <holder>). See docs/licenses-and-attribution.md`.

---

## 2. Hackbot's own license

**MIT** (see [`LICENSE`](../LICENSE)). Given the AGPL/GPL/BY-SA constraints above,
Hackbot's own code stays clean-room or attributed-MIT/Apache. **No AGPL/GPL/BY-SA
code is incorporated**, so those obligations do not attach to Hackbot's source.

---

## 3. Tool & data dependencies (runtime)

Security tools (subfinder, httpx, nuclei, ffuf, semgrep, gitleaks, nmap, etc.) are
installed as external binaries under their own licenses and invoked as separate
processes — not linked. Their licenses are recorded in the generated install
manifest (`scripts/install-tools.sh` output) and SBOM when produced.
