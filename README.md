# bugbug

A bug bounty workstation that runs on your machine. It's built to be auditable,
puts safety checks in code (not prompts), and works through Claude Code. If
you're doing pentests, bug bounties, CTFs, or security research on stuff you're
allowed to test, this is for you.

**Only test what you own or have permission to test.** Never use this for
anything unauthorized. The [`SECURITY.md`](./SECURITY.md) and
[`CLAUDE.md`](./CLAUDE.md) spell out the rules in detail.

## What it does

- Keeps your engagements organized under `engagements/<platform>/<program>/`
- Checks scope in code before any network action leaves your box
- Runs real security tools (nmap, ffuf, nuclei, sqlmap, subfinder, etc.) through a risk gate that can block, allow, or ask for approval
- Records evidence and generates reports for HackerOne, Intigriti, Bugcrowd, and others
- Connects to Burp Suite via MCP for proxy history, repeater, scanner, and spider
- L3 actions (AD attacks, exploitation, lateral movement) are available when you confirm you're authorized. Your call, your responsibility

## Quick start

```bash
# Check your setup
scripts/doctor.sh

# Build and install
python3 -m venv .venv
.venv/bin/python scripts/build_wheel.py
.venv/bin/python -m pip install --no-index --no-deps dist/hackbot-*.whl

# See what's available
.venv/bin/hackbot doctor
.venv/bin/hackbot skills list

# Create an engagement from a program file
.venv/bin/hackbot program import program.yaml --engagements-dir engagements

# Check if a target is in scope
.venv/bin/hackbot scope check https://target.com --scope-file scope.yaml
```

## How it works

Every action goes through the same pipeline:

```
hackbot tool run → scope check → risk gate → run command → audit + evidence
```

The risk gate has four levels:

| Level | What it means | Runs when |
|-------|---------------|-----------|
| L0 | Passive, no touching the target | Always, after scope init |
| L1 | Low impact, looks like normal traffic | In scope, rate limited, on the allowlist |
| L2 | Intrusive or state-changing | You approve it first (TTY, single-use) |
| L3 | Exploitation, cred access, AD attacks | You confirm authorization + capability flags |

L3 used to be locked to `private-pentest` profiles. Now it's available under any
profile as long as authorization is confirmed, the target is in scope, and the
relevant capability flags are on. You're responsible for what you run.

## Tools included

The code knows about these tools and where to find them. If a tool isn't installed
it's silently skipped when the action registry loads.

```
curl, dig, nmap, openssl, whois          # usually already on your system
subfinder, httpx, katana, gau, dnsx      # recon: go install
waybackurls, alterx, naabu               # more recon
ffuf, feroxbuster                        # fuzzing
nuclei, dalfox, sqlmap, wafw00f          # vuln scanning
arjun, graphw00f                         # param / graphql discovery
semgrep, gitleaks, trufflehog            # source analysis
hydra, john, masscan, metasploit         # L3: exploitation (remote)
impacket, crackmapexec, bloodhound       # L3: AD attacks (remote)
```

Tool paths live in `src/hackbot/tools/actions.py`. If you install via `go install`,
the `~/go/bin/` paths are already in the allowlist.

## What's where

```
config/         YAML configs (providers, tools, risk policy, reporting)
src/hackbot/    the engine: CLI, scope, risk gate, tool adapters, MCP, engagement v2
skills/         methodology guides organized by domain with YAML frontmatter
skills/skills.yaml  master registry — maps every skill to code-owned actions
docs/           architecture, threat model, how-tos, reviews
templates/      report templates per platform (hackerone, intigriti, etc.)
engagements/    your engagements live here (gitignored, except samples)
scripts/        build, doctor, bootstrap
schemas/        JSON schemas for engagement v2 contracts
```

### Skills & actions

Every skill in `skills/` links to code-owned actions in `src/hackbot/tools/actions.py`
through the master registry `skills/skills.yaml`. Use `hackbot skills list` to see
what's available.

14 recon categories, 4 internal-recon (disabled by default), plus web, api, auth,
cloud, mobile, source-review, ai-security, web3, and reporting skills — all with
proper YAML frontmatter and cross-references.

## Burp Suite + MCP

If you use Burp, install the MCP Server extension from the BApp Store. It listens on
`127.0.0.1:9876` and exposes proxy history, repeater, scanner, and spider as MCP
tools. The project ships with a `.mcp.json` that connects Claude Code to it.

Full setup guide: [`docs/burp-mcp-integration.md`](docs/burp-mcp-integration.md)

## Engagement structure

```
engagements/<platform>/<program>/<date>/
  program.yaml       what program, what platform, testing rules
  scope.yaml         what's in and out of scope
  authorization.json confirmed or not, by whom, when
  rules.md           program-specific rules (optional)
  recon/             raw recon output
  hypotheses/        what you think might be vulnerable
  findings/          confirmed issues
  evidence/          redacted proof
  reports/           generated markdown reports
```

## Documentation

- [`docs/risk-and-approval.md`](docs/risk-and-approval.md) — risk levels and the approval workflow
- [`docs/tool-execution.md`](docs/tool-execution.md) — how tools get executed safely
- [`docs/burp-mcp-integration.md`](docs/burp-mcp-integration.md) — Burp Suite MCP setup
- [`docs/remote-runner.md`](docs/remote-runner.md) — running actions on a remote box
- [`docs/findings-and-reporting.md`](docs/findings-and-reporting.md) — findings and report generation
- [`docs/engagement-v2-contracts.md`](docs/engagement-v2-contracts.md) — engagement v2 contracts
- [`docs/next-steps.md`](docs/next-steps.md) — what's next

## Requirements

Python 3.11 or newer. macOS or Linux. The core CLI has no third-party runtime
dependencies and works offline. Optional dependencies (keyring, yaml) are pulled
in when you install the full package.

## License

MIT for the project's own code. Some referenced material has its own license
terms — see [`docs/licenses-and-attribution.md`](docs/licenses-and-attribution.md).
