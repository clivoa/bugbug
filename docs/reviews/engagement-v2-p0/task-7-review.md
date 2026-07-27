# Task 7 independent review

Review scope: commit range `2070e15..9a7cb17` only.

Spec compliance: FAIL

Task quality: WITH FIXES

## Summary

The change is correctly limited to the four Task 7 deliverables. It does not
change a production runtime file, and it does not modify the OpenSpec change or
any OpenSpec task checkbox. `hackbot.programs.schema.SCHEMA_VERSION` is `1` at
both ends of the reviewed range. The contract document contains the exact
sentence `P0 does not enable engagement v2 execution`, accurately denies a P0
SSH/helper/replay implementation, and does not claim that v2 execution exists.

The numerical protocol caps, schema and fixture commands, safe-pattern summary,
digest wrappers, P1/P2/P4 dependencies, local OpenSpec link, Issue #1 URL,
P0-Ready/P1–P7-dependent roadmap text, and workflow inventory path are otherwise
consistent with the implemented contracts and OpenSpec materials inspected.

The binding isolation requirement is nevertheless not satisfied. The AST guard
has false negatives for ordinary absolute `ImportFrom` statements, and the
runtime subprocess does not invoke the repository's configured CLI entrypoint.
The operator document also contains an incorrect representation of the exact
wire magic and an incomplete replay-retention statement.

## Findings

### Critical

None.

### Important

1. `tests/engagement_v2/test_v1_isolation.py:37` — Absolute `ImportFrom` nodes
   are resolved relative to the importing package.

   Impact: `base` starts as `package` even when `node.level == 0`. Consequently,
   an import such as `from hackbot.engagement_v2 import ContractError` in
   `src/hackbot/cli/probe.py` is recorded as
   `hackbot.cli.hackbot.engagement_v2`, and
   `from hackbot import engagement_v2` is also missed. These are common direct
   imports of the forbidden package, so the guard can pass after accidental v2
   activation. This contradicts the binding ruling that both `Import` and
   `ImportFrom`, including relevant relative forms, be analyzed correctly.

   Concrete correction: use an empty base for absolute imports, for example
   `base = ()` when `node.level == 0`, and resolve from `package` only when
   `node.level > 0`. Add focused cases proving detection of at least
   `import hackbot.engagement_v2`,
   `from hackbot.engagement_v2 import ContractError`,
   `from hackbot import engagement_v2`, and
   `from ..engagement_v2 import ReasonCode` from both normal modules and
   `__init__.py` files.

   Independent probe evidence: the current helper returned
   `hackbot.cli.hackbot.engagement_v2` for the first absolute form and
   `hackbot.cli.hackbot.engagement_v2` for the imported alias in the second
   absolute form; it correctly resolved the relative form to
   `hackbot.engagement_v2`.

2. `tests/engagement_v2/test_v1_isolation.py:62` — The runtime proof does not
   exercise the configured v1 CLI entrypoint, and its risk exercise is
   tautological.

   Impact: `pyproject.toml:29` registers `hackbot.cli.main:app`, but the child
   only calls `build_parser().parse_args(...)`. It never dispatches `app`, so a
   dynamic v2 import introduced in the real entrypoint would not be observed.
   Likewise, `isinstance(RiskEngine(ActionRegistry(())), RiskEngine)` can only
   assert the type of the object just constructed; it does not exercise a risk
   decision path where a dynamic import could occur. The subprocess itself is a
   fresh interpreter and the final `sys.modules` check is non-tautological, but
   the claimed entrypoint coverage is incomplete.

   Concrete correction: in the child, call the registered entrypoint with a
   harmless path such as `cli_main.app(["version"])` and explicitly check its
   return value. Exercise a deterministic risk decision method rather than an
   `isinstance` of a freshly constructed object. Retain the harmless schema,
   scope, and `CommandRunner(sys.executable, "-c", "pass")` paths and the final
   forbidden-module check. Prefer explicit `if ...: raise SystemExit(...)`
   checks inside the child so `PYTHONOPTIMIZE` cannot remove the exercises.

3. `docs/engagement-v2-contracts.md:75` and
   `docs/engagement-v2-contracts.md:80` — Two exact remote-protocol facts are
   documented incorrectly or incompletely.

   Impact: the Markdown code span contains two literal reverse solidi in
   `HBV2RUN\\x00`; inline code does not collapse them. The implemented and
   normative eight-byte magic is `b"HBV2RUN\x00"`. The replay text also calls
   the value merely a “600-second replay reservation”, while the normative rule
   is retention for 600 seconds **after expiry**, or until a longer in-progress
   run finalizes. P4 consumers relying on this boundary document could implement
   incompatible framing or an insufficient replay window.

   Concrete correction: render the magic unambiguously as
   `b"HBV2RUN\x00"` (one escape introducer) or as its eight hexadecimal bytes,
   and state the full replay retention rule: 600 seconds after expiry, extended
   until a longer in-progress run finalizes.

4. `docs/next-steps.md:3` and `docs/next-steps.md:8` — The new “after P0”
   status snapshot puts P0 under an obsolete “Implemented and verified” gate
   claim.

   Impact: the document now presents itself as the current post-P0 starting
   point and adds P0 under a heading that still says `912 tests passing; 913
   collected`. Existing Task 5 evidence in the same SDD record already reports
   `1129 passed, 1 skipped`, before later Task 6 and Task 7 tests. Task 8 owns
   the fresh full gates and remains incomplete, while the OpenSpec checkboxes
   intentionally remain unchecked. The resulting status is neither current nor
   an accurate statement of P0 verification, despite correctly labeling the
   change Ready.

   Concrete correction: separate the historical v1 verification snapshot from
   current P0 status, and describe P0 as the current Ready change with Task 8
   full verification/delivery still pending. Do not publish a new total until
   Task 8 records a fresh full-suite result.

### Minor

1. `docs/engagement-v2-contracts.md:21` — The protocol interface map omits
   `FrameType`.

   Impact: `FrameType` is in `protocol.__all__` and is required to construct
   `Frame`; the stated public module map is therefore incomplete.

   Concrete correction: include immutable `FrameType` in the `protocol` row.

## Confirmed checks

- `git diff --name-status 2070e15..9a7cb17` contains only the four planned Task
  7 deliverables.
- There is no diff under `src/hackbot/` and therefore no production runtime
  change in this range.
- `SCHEMA_VERSION == 1` in `src/hackbot/programs/schema.py`, including at
  `2070e15`.
- The OpenSpec `tasks.md` bytes are identical at both ends of the range; all
  checkboxes remain unchanged.
- The exact required non-activation sentence is present.
- `docs/next-steps.md` states P0 is active/Ready and P1–P7 remain dependent.
- The workflow inventory points P0 to
  `openspec/changes/engagement-v2-security-contracts/`.
- The local OpenSpec Markdown target resolves to the expected repository
  directory, and the Issue #1 URL uses the repository's configured GitHub
  origin.
- The documented schema and fixture check/regeneration command forms match the
  implemented script CLIs.
- The documented numerical canonical, safe-pattern, protocol, nonce, lifetime,
  skew, and egress-age bounds match the inspected implementation, subject to
  Important finding 3 for magic and replay-retention wording.
- No P0 SSH transport, helper process, replay cache, loader, policy engine, or
  executor implementation was found; P0 provides contracts, schemas, and
  framing/validation primitives only.
- `git diff --check 2070e15..9a7cb17` exits zero.

## Verification boundary

⚠️ Cannot verify from diff: the reported historical pytest/Ruff/mypy/schema and
fixture command outputs were not rerun as part of this read-only review, per the
instruction not to rerun broad gates. The live existence, title, and Project
field state of GitHub Issue #1 are also external state not established by the
diff; only the URL's repository/issue shape and match to the configured origin
were verified.

## Final ruling

Spec compliance remains **FAIL** until the AST `ImportFrom` false negatives and
runtime entrypoint coverage are corrected. Task quality is **WITH FIXES**
because the isolation proof is unsound and the operator-facing status/protocol
documentation contains material inaccuracies.
