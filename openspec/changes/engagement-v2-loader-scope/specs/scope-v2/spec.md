## ADDED Requirements

### Requirement: Default-deny typed scope decisions
The scope v2 engine SHALL decide each target against a confirmed snapshot's
scope using default-deny and deny-wins semantics: a target is authorized only
when it matches at least one in-scope rule of a compatible kind and matches no
exclusion. Every decision SHALL carry a stable machine-readable reason from a
closed set: `authorized`, `out-of-scope-no-match`, `excluded-by-rule`,
`cross-protocol-not-authorized`, `unparsable-target`, and
`dns-resolution-not-authoritative`. The engine SHALL perform no network or DNS
resolution and SHALL treat scope inputs as immutable at decision time.

#### Scenario: In-scope target with no exclusion is authorized
- **WHEN** a target matches an in-scope rule of a compatible kind and no exclusion
- **THEN** the decision is authorized with reason `authorized`

#### Scenario: Unmatched target is denied by default
- **WHEN** a target matches no in-scope rule
- **THEN** the decision denies with reason `out-of-scope-no-match`

#### Scenario: Exclusion beats an in-scope match
- **WHEN** a target matches both an in-scope rule and an exclusion
- **THEN** the decision denies with reason `excluded-by-rule`

#### Scenario: Unparsable target is denied
- **WHEN** a target cannot be parsed into a supported scope kind
- **THEN** the decision denies with reason `unparsable-target` and never defaults to authorized

### Requirement: Typed cross-protocol non-authorization
Scope authorization SHALL be typed so that a rule of one kind never authorizes a
target of an incompatible kind. A `domains` or `wildcard_domains` rule SHALL
authorize only domain operations and HTTP(S) URLs on matching names and SHALL
NOT authorize LDAP, SMB, SSH, RDP, WinRM, or any other non-HTTP service. A
`urls` rule SHALL authorize only the matching HTTP(S) host with segment-aware
path matching. A `hosts` rule SHALL authorize only the exact host and network
endpoints on that exact hostname, with no suffix matching. A `network_endpoints`
rule SHALL authorize only the exact scheme, host, and port.

#### Scenario: Web-domain rule does not authorize LDAP
- **WHEN** only a `domains` rule for `dc01.corp.example` exists and the target is `ldaps://dc01.corp.example:636`
- **THEN** the decision denies with reason `cross-protocol-not-authorized`

#### Scenario: Host rule authorizes an endpoint on the exact host
- **WHEN** a `hosts` rule for `dc01.corp.example` exists and the target is `smb://dc01.corp.example:445`
- **THEN** the decision is authorized with reason `authorized`

#### Scenario: Host rule does not suffix-match
- **WHEN** a `hosts` rule for `fileserver` exists and the target host is `fileserver.corp.example`
- **THEN** the decision denies with reason `out-of-scope-no-match`

#### Scenario: Network endpoint requires exact port
- **WHEN** a `network_endpoints` rule for `smb://fileserver:445` exists and the target is `smb://fileserver:139`
- **THEN** the decision denies with reason `out-of-scope-no-match`

### Requirement: CIDR containment and exclusion by overlap
A `cidrs` rule SHALL authorize a target only when the target's literal IP
address is contained in the CIDR; a hostname that merely resolves into the CIDR
SHALL NOT inherit authorization. A CIDR exclusion SHALL deny any target whose IP
or declared network overlaps the excluded network, and the exclusion SHALL win
over any in-scope CIDR match. IPv4 and IPv6 SHALL be compared within their own
family only.

#### Scenario: Literal IP inside CIDR is authorized
- **WHEN** an in-scope `cidrs` rule `10.20.0.0/16` exists and the target is the literal IP `10.20.5.7`
- **THEN** the decision is authorized with reason `authorized`

#### Scenario: Hostname resolving into a CIDR is not authorized
- **WHEN** an in-scope `cidrs` rule `10.20.0.0/16` exists and the target is a hostname (not a declared host/endpoint) that would resolve into it
- **THEN** the decision denies with reason `dns-resolution-not-authoritative`

#### Scenario: Overlapping exclusion wins
- **WHEN** `10.20.0.0/16` is in scope and `10.20.5.0/24` is excluded and the target IP is `10.20.5.7`
- **THEN** the decision denies with reason `excluded-by-rule`

#### Scenario: Cross-family comparison never matches
- **WHEN** an in-scope `cidrs` rule is IPv4 and the target is an IPv6 address
- **THEN** the decision denies with reason `out-of-scope-no-match`

### Requirement: Discovery never widens scope
Targets discovered during execution SHALL be recorded only as hypotheses and
SHALL NOT be authorized until they independently match an in-scope rule and no
exclusion. Mutable DNS resolution, PTR data, certificate contents, or any
target self-report SHALL NOT add or widen scope.

#### Scenario: Discovered target must independently match
- **WHEN** a target discovered during a prior action is later submitted for authorization
- **THEN** it is authorized only if it independently matches an in-scope rule and no exclusion, exactly as any other target

#### Scenario: Resolution does not authorize an undeclared host
- **WHEN** an undeclared hostname resolves to an in-scope IP
- **THEN** the decision denies with reason `dns-resolution-not-authoritative`
