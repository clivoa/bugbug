# Licenses & Attribution

Authoritative ledger of third-party material the Hackbot (`bugbug`) project was
inspected against or derives patterns from, plus the local recon bundle.

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

## 1. Local reconnaissance bundle

| Field | Value |
|---|---|
| File | `references/recon/Recon-bundle.html` (immutable reference) |
| Title | "Recon — CyberNeon Bundle" |
| Contents | 19 reconnaissance notes (pt-BR) |
| License | **NONE found** in the file (no MIT/GPL/Apache/CC/copyright string) |
| Operator authorization | **Granted for LOCAL, PRIVATE use** — content was already circulating publicly (operator decision, 2026-08-07, revising the 2026-07-24 attribution-retained decision). **Redistribution NOT authorized.** |

**Handling.** Per operator authorization we normalize the bundle's *methodology*
into Hackbot skills for local use. The original HTML is never modified. Every
skill or adapter materially derived from a note carries
`attribution: "CyberNeon Recon Bundle (public source; no formal license)"` and
a back-reference in `generated/recon-bundle/manifest.yaml`. Because no license
grants redistribution, **derived skills must not be published or shared**
outside this machine without further authorization. The derived skills remain
local-only artifacts.

External resources merely *linked* by the bundle (crt.sh, dnsdumpster,
hackertarget, censys, securitytrails, viewdns, Google Transparency Report,
exploit-db) are third-party services governed by their own terms.

---

## 2. Reference repositories

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
| capitalone/vulnhunter | **Apache-2.0** | fix→verify concept | NOTICE if code adapted |
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

## 3. Hackbot's own license

**MIT** (see [`LICENSE`](../LICENSE)). Given the AGPL/GPL/BY-SA constraints above,
Hackbot's own code stays clean-room or attributed-MIT/Apache, so MIT applies
without conflict. **No AGPL/GPL/BY-SA code is incorporated**, so those
obligations do not attach to Hackbot's source. The MIT grant does not extend to
the local reconnaissance bundle (`references/recon/Recon-bundle.html`), which
remains unlicensed upstream material authorized for local, private use only.

---

## 4. Tool & data dependencies (runtime)

Security tools (subfinder, httpx, nuclei, ffuf, semgrep, gitleaks, nmap, etc.) are
installed as external binaries under their own licenses and invoked as separate
processes — not linked. Their licenses are recorded in the generated install
manifest (`scripts/install-tools.sh` output) and SBOM when produced.
