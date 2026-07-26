# Web directory enumeration (ffuf) — design

**Status:** approved (2026-07-26)

**Goal:** Promote the reviewed directory-enumeration recon skill into a code-owned,
gated `web.dir-enum` action (ffuf), delivering real active fuzzing for bug-bounty
scenarios, tested end to end against a local lab.

**Safety boundary:** L2 (intrusive/high-volume) → explicit TTY approval; runs only
against in-scope targets; recon (discovery), not exploitation; nothing L3; the
raw bundle HTML is never read; attributed to `@reeshasx`.

## Context

`REAL_ACTIONS` holds gated recon actions across curl/dig/openssl/nmap. Directory
enumeration needs a wordlist. Putting the `FUZZ` keyword in the operator-supplied
`{target}` URL (e.g. `http://host/FUZZ`) means the **existing** whole-token
`{target}` placeholder suffices — no reviewed risk-model change. The wordlist is a
small **code-owned bundled** file (custom operator wordlists via a `{wordlist}`
placeholder remain a later increment). ffuf is installed locally on the Mac for
this increment; the Kali SSH runner is the next increment.

## Architecture

### 1. Bundled wordlist + ffuf resolution — `src/hackbot/tools/`

- `src/hackbot/tools/wordlists/web-content.txt` — a small (~30 entries) code-owned
  common-paths wordlist.
- `ffuf_path()` beside the other resolvers; `web_content_wordlist()` returns the
  packaged wordlist path (`Path(__file__).parent / "wordlists" / "web-content.txt"`).
- `scripts/build_wheel.py` also packages `*.txt` under the package (currently only
  `*.py` ship), so the wordlist is present in an installed wheel.

### 2. Action — `web.dir-enum`

Registered only when ffuf resolves and the wordlist exists:

```python
ActionDefinition(
    "web.dir-enum",
    RiskLevel.L0,
    network_access=True,
    uses_external_tool=True,
    high_volume=True,          # -> effective floor L2
    executable=ffuf,
    argv_template=(ffuf, "-s", "-u", "{target}", "-w", "<wordlist path>"),
)
```

`{target}` is the full ffuf URL including `FUZZ` (e.g. `http://host/FUZZ`);
`scope.check` matches the host. `high_volume` → L2 → requires approval. `-s` keeps
output to found paths only.

### 3. Provenance

Add `web.dir-enum` → `recon/parameter-discovery` (note `note-enumeracao-diretorios`,
bundle risk `2`, approval `explicit`) to `PROMOTED_ACTIONS`, with attribution.

## Error handling

Unchanged gate: no `ALLOW` → no execution; L2 → TTY approval; out-of-scope →
`DENY_SCOPE`. ffuf absent → the action is not registered. A missing wordlist at
run time makes ffuf exit non-zero (CLI exit 1); no traceback.

## Testing strategy (test-first)

- **shape**: `web.dir-enum` registered (when ffuf resolves), L2 effective floor,
  `high_volume`, ffuf-backed, argv contains `-u {target}` and the wordlist path.
- **gate**: `run_action(grant=None)` on `web.dir-enum` → `REQUIRES_APPROVAL`, not
  executed.
- **end-to-end (ffuf present)**: `hackbot tool run web.dir-enum REQUEST.json
  --engagement DIR --approve` (monkeypatched TTY) against the loopback lab
  (`http://127.0.0.1:<port>/FUZZ`) executes ffuf, exits `0`, finds a known path,
  and captures redacted evidence; the grant is consumed. Skips when ffuf is absent.
- **provenance**: the new entry validates against the manifest (parameter-discovery,
  not internal-pack).
- **packaging**: the offline-installed wheel contains
  `hackbot/tools/wordlists/web-content.txt`.
- **Regression**: full suite, Ruff, format, mypy, offline smoke.

## Boundary

`web.dir-enum` is a recon-only, code-owned, gated (scope + risk + approval),
attributed active-fuzzing action using a bundled code-owned wordlist. Custom
operator wordlists (a `{wordlist}` placeholder) and a Kali SSH runner are separate
later increments.
