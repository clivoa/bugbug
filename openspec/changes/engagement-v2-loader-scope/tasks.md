## 1. Hardened decode and document loading

- [x] 1.1 Add failing tests for descriptor-based loading: `O_NOFOLLOW` symlink refusal, regular-file requirement, and inode/size/mtime recheck that rejects a file replaced or truncated mid-read (fail closed, no snapshot).
- [x] 1.2 Add failing tests mapping every hardening rejection to its exact P0 reason code (`INVALID_DOCUMENT_SIZE`, `INVALID_DOCUMENT_ENCODING`, `INVALID_SCHEMA_VERSION`, `INVALID_DUPLICATE_KEY`, `INVALID_UNKNOWN_FIELD`, `INVALID_DOCUMENT_STRUCTURE` for alias/merge/tag/non-regular, `INVALID_CANONICAL_VALUE` for float/non-NFC, `INVALID_LIMIT` for nesting).
- [x] 1.3 Implement `engagement_v2.loader` descriptor reads and a hardened JSON/YAML decode path (alias/merge/tag-free, node-level duplicate detection) that emits only P0 reason codes, until 1.1–1.2 pass.

## 2. Coherent snapshot and confirmation

- [x] 2.1 Add failing tests proving one immutable snapshot is produced only when all documents validate, one invalid document yields no snapshot, and the snapshot object is frozen.
- [x] 2.2 Add failing tests for confirmation: matching digest confirms; a security-relevant change denies `DENY_AUTHORIZATION_STALE`; unconfirmed/field-incomplete denies `DENY_AUTHORIZATION_UNCONFIRMED`; a note/comment/key-order-only change stays confirmed; verification does no I/O.
- [x] 2.3 Implement the security-relevant projection, `authority_digest` recompute-and-compare, and the frozen snapshot type until 2.1–2.2 pass.

## 3. Engagement namespace identity

- [x] 3.1 Add failing tests: identity is stable across identical confirmed loads, changes on any security-relevant change, and contains no secret, local path, or timestamp (golden vector).
- [x] 3.2 Implement the identity projection and digest until 3.1 passes.

## 4. Typed scope v2 engine

- [x] 4.1 Add failing tests for the closed `ScopeDenyReason` set and default-deny/deny-wins: in-scope authorize, no-match deny, exclusion-beats-match, unparsable-target deny.
- [x] 4.2 Add failing tests for typed cross-protocol non-authorization: domain rule does not authorize LDAP/SMB/SSH/RDP/WinRM; `hosts` no suffix match; `network_endpoints` exact scheme/host/port; `urls` segment-aware path.
- [x] 4.3 Add failing tests for CIDR: literal-IP containment authorize, resolving-hostname denied `dns-resolution-not-authoritative`, overlapping exclusion wins, cross-family never matches.
- [x] 4.4 Add failing tests proving discovered targets are hypotheses that must independently re-match and that DNS/PTR/cert/self-report never widen scope.
- [x] 4.5 Implement `engagement_v2.scope` decision engine (no DNS, immutable inputs) until 4.1–4.4 pass.

## 5. Dry-run migration analysis

- [x] 5.1 Add failing tests: dry-run leaves the engagement directory byte-for-byte unchanged (name/size/hash snapshot before and after), missing profile rejected, invalid v1 engagement blocks analysis and writes nothing.
- [x] 5.2 Add failing tests: proposed tree preserves exact scope/authorization, new sensitive capabilities default to false, empty `actions.yaml` proposed, prior approvals marked historical, and unenforceable features are warned and not presented as ready.
- [x] 5.3 Implement the in-memory `engagement_v2` dry-run analyzer and the read-only `hackbot engagement migrate --dry-run` CLI wiring until 5.1–5.2 pass.

## 6. Integration boundary and v1 compatibility

- [x] 6.1 Tighten the P0 non-integration guard into an allowlist test: only the declared v2 entry modules import `hackbot.engagement_v2`; v1 program/risk/scope/tools and default v1 CLI paths still must not.
- [x] 6.2 Add and pass a guard test proving a schema v1 engagement keeps v1 loader/caller/approval/exit-code behavior and never invokes the v2 loader.

## 7. Fixtures and documentation

- [x] 7.1 Add deterministic synthetic v1 and v2 engagement fixtures (example domains/hosts/CIDRs/endpoints; no real target or credential material) with a regenerate/check tool proving reproducible bytes.
- [x] 7.2 Document the P1 public loader/scope/identity/dry-run interfaces, the closed scope-reason set, the confirmation/identity projections, and that P1 performs no execution and no effective migration.

## 8. Verification and delivery

- [x] 8.1 Run focused P1 tests, the full pytest suite, Ruff check/format, mypy, schema/fixture drift, OpenSpec strict validation, the secret-scan regex over new paths, and `git diff --check`; record fresh outputs.
- [ ] 8.2 Request independent review, resolve findings, update Issue #2/Project fields, and archive the OpenSpec change only after implementation, verification, and merge.
