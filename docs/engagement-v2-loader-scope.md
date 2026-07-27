# Engagement v2 loader and scope (P1)

**Status:** implemented on `feat/engagement-v2-loader-scope`.

P1 is the first phase that consumes the archived P0 contracts at runtime. It
turns four on-disk authority documents into one coherent, confirmed, immutable
snapshot, decides v2 targets against a typed scope, and offers a read-only
migration analysis. **P1 performs no execution and no effective migration:** it
opens no socket, spawns no child, resolves no secret, and writes no engagement
file. Action binding and policy (P2), the executor and secrets (P3), the remote
helper (P4), and effective migration/restore (P7) remain out of scope.

## Public interfaces

`hackbot.engagement_v2.loader`

- `load_engagement(engagement_dir) -> EngagementSnapshot` — read
  `program`, `scope`, `authorization`, and optional `runner` documents, validate
  them through the P0 contract layer, verify the confirmed-authority digest, and
  return one frozen `EngagementSnapshot` (`program`, `scope`, `authorization`,
  `runner`, `profile`, `authority_digest`, `identity`). Any failure raises
  `ContractError` with an exact P0 reason and returns no snapshot.

`hackbot.engagement_v2.scope`

- `ScopeV2(scope_document)` with `check(target) -> ScopeV2Decision` — typed,
  default-deny, deny-wins decisions. Performs no DNS or network I/O.
- `ScopeDenyReason` — the closed decision-reason set:
  `authorized`, `out-of-scope-no-match`, `excluded-by-rule`,
  `cross-protocol-not-authorized`, `unparsable-target`, and
  `dns-resolution-not-authoritative`.

`hackbot.engagement_v2.projection`

- `security_projection(program=, scope=, runner=)` — the explicit allowlist of
  security-relevant values the confirmed-authority digest covers.
- `projection_digest(projection)` — the P0 authority digest of that projection.
- `engagement_identity(authority_digest)` — the stable namespace identity.

`hackbot.engagement_v2.migration`

- `analyze_migration(v1_program=, v1_scope=, v1_authorization=, profile=)
  -> MigrationAnalysis` — a pure, read-only proposed v2 tree plus warnings. It
  imports no v1 module and writes nothing.

CLI: `hackbot engagement migrate --engagement DIR --to 2 --profile PROFILE
--dry-run [--json]` — reads and v1-validates the source engagement, then prints
the proposed v2 files and warnings. It is the only supported migration mode in
this release; without `--dry-run` it refuses with a clear error and writes
nothing.

## Fail-closed loading

Each security-critical document is opened with `O_NOFOLLOW` (symlinks refused),
required to be a regular file, and read in full from one stable descriptor. The
descriptor's `(st_dev, st_ino, st_size, st_mtime_ns)` is rechecked after the
read and any growth or shrink fails closed, so a file replaced or truncated
mid-read never becomes authority. All four documents are validated before any
snapshot object is built; one invalid document yields no snapshot and no partial
authority. Decoding enforces the P0 limits and strict primitive model: bounded
size before decode, UTF-8 only, no arbitrary object construction, and rejection
of duplicate keys, unknown top-level fields, YAML aliases/merge keys/tags,
non-NFC strings, floats, excessive nesting, and unsupported versions — each with
its exact P0 reason code.

## Confirmation and identity projections

The confirmed-authority digest binds the **security-relevant projection**, not
raw bytes. The projection is an explicit allowlist:

- `profile`;
- `policy` — the five numeric `testing_rules` limits, every sensitive boolean
  present, and the security-relevant list fields (sorted, set-like);
- `scope` — `in_scope`/`out_of_scope`, each scope kind sorted and de-duplicated;
- `runner` — the P0 `RUNNER_SECURITY_PROJECTION_FIELDS` (trust root, SSH options,
  helper identity, privileges, egress), excluding the private-key path and
  connection timeout.

Non-security content (notes, comments, key ordering, local private-key paths,
connection timeouts, secrets) is excluded, so semantically equal authority is
byte-identical after P0 `canonical_bytes`. The loader recomputes the digest and
compares it to `authorization.json`'s `confirmed_authority_digest`:

- any security-relevant mismatch → `DENY_AUTHORIZATION_STALE`;
- `confirmed` not true or a missing confirmation field →
  `DENY_AUTHORIZATION_UNCONFIRMED`.

The **engagement namespace identity** is a domain-separated digest
(`hackbot-engagement-namespace-v1`) of the confirmed authority digest. It is
stable across identical loads, changes whenever the security-relevant authority
changes, and — being a hash — embeds no secret, local path, or timestamp.

## Typed scope decisions

Authorization is typed so a rule of one kind never authorizes a target of an
incompatible kind:

- `domains`/`wildcard_domains` authorize domain operations and HTTP(S) URLs on
  matching names only; a wildcard matches strict subdomains, not the apex.
- `urls` authorize the matching HTTP(S) host with segment-aware path matching.
- `hosts` authorize the exact host (no suffix matching) and network endpoints on
  that exact hostname.
- `network_endpoints` authorize only the exact scheme, host, and port.
- `cidrs` authorize a target only when its literal IP is contained in the CIDR;
  a hostname that would merely resolve into the CIDR is denied
  `dns-resolution-not-authoritative`. Exclusions deny on network overlap and win
  over any in-scope match; IPv4 and IPv6 are compared within their own family.

Discovered targets are hypotheses: they are authorized only if they
independently match an in-scope rule and no exclusion. Mutable DNS/PTR/cert data
and target self-reports never widen scope.

## Integration boundary

P1 is the first phase in which the CLI reaches `hackbot.engagement_v2`, and only
through the declared entry module `cli/engagement_cmd.py`. The P0
non-integration guard is tightened into an allowlist: exactly that module may
import the contract package; v1 `programs`/`risk`/`scope`/`tools` and the default
CLI paths still must not, and a schema v1 engagement keeps its v1 loader, caller,
approval, and exit-code behavior (the v2 loader refuses a v1 document with
`INVALID_SCHEMA_VERSION`).
