"""P1 typed scope v2 decisions."""

from __future__ import annotations

from hackbot.engagement_v2.scope import ScopeDenyReason, ScopeV2


def _scope(in_scope: dict, out_of_scope: dict | None = None) -> ScopeV2:
    return ScopeV2({"in_scope": in_scope, "out_of_scope": out_of_scope or {}})


# --------------------------------------------------- default-deny / deny-wins ---
def test_in_scope_domain_is_authorized() -> None:
    decision = _scope({"domains": ["app.corp.example"]}).check("app.corp.example")
    assert decision.authorized
    assert decision.reason is ScopeDenyReason.AUTHORIZED


def test_unmatched_target_denied_by_default() -> None:
    decision = _scope({"domains": ["app.corp.example"]}).check("other.example")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH


def test_exclusion_beats_in_scope_match() -> None:
    scope = _scope({"domains": ["app.corp.example"]}, {"domains": ["app.corp.example"]})
    decision = scope.check("app.corp.example")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.EXCLUDED_BY_RULE


def test_unparsable_target_denied() -> None:
    decision = _scope({"domains": ["app.corp.example"]}).check("not a target")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.UNPARSABLE_TARGET


# ------------------------------------------------- typed cross-protocol ---
def test_domain_rule_does_not_authorize_ldap() -> None:
    decision = _scope({"domains": ["dc01.corp.example"]}).check("ldaps://dc01.corp.example:636")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.CROSS_PROTOCOL_NOT_AUTHORIZED


def test_host_rule_authorizes_endpoint_on_exact_host() -> None:
    decision = _scope({"hosts": ["dc01.corp.example"]}).check("smb://dc01.corp.example:445")
    assert decision.authorized
    assert decision.reason is ScopeDenyReason.AUTHORIZED


def test_host_rule_does_not_suffix_match() -> None:
    decision = _scope({"hosts": ["fileserver"]}).check("fileserver.corp.example")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH


def test_network_endpoint_requires_exact_port() -> None:
    decision = _scope({"network_endpoints": ["smb://fileserver:445"]}).check("smb://fileserver:139")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH


def test_network_endpoint_exact_match_authorized() -> None:
    decision = _scope({"network_endpoints": ["smb://fileserver:445"]}).check("smb://fileserver:445")
    assert decision.authorized


def test_url_authorized_by_domain() -> None:
    decision = _scope({"domains": ["app.corp.example"]}).check("https://app.corp.example/anything")
    assert decision.authorized


def test_url_segment_aware_path() -> None:
    scope = _scope({"urls": ["https://app.corp.example/admin"]})
    assert scope.check("https://app.corp.example/admin/users").authorized
    assert not scope.check("https://app.corp.example/adminszone").authorized


def test_wildcard_domain_matches_subdomain_only() -> None:
    scope = _scope({"wildcard_domains": ["*.apps.corp.example"]})
    assert scope.check("a.apps.corp.example").authorized
    assert not scope.check("apps.corp.example").authorized


# --------------------------------------------------------- CIDR handling ---
def test_literal_ip_inside_cidr_authorized() -> None:
    decision = _scope({"cidrs": ["10.20.0.0/16"]}).check("10.20.5.7")
    assert decision.authorized


def test_hostname_resolving_into_cidr_not_authorized() -> None:
    decision = _scope({"cidrs": ["10.20.0.0/16"]}).check("host.corp.example")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.DNS_RESOLUTION_NOT_AUTHORITATIVE


def test_overlapping_exclusion_wins() -> None:
    scope = _scope({"cidrs": ["10.20.0.0/16"]}, {"cidrs": ["10.20.5.0/24"]})
    decision = scope.check("10.20.5.7")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.EXCLUDED_BY_RULE


def test_cross_family_never_matches() -> None:
    decision = _scope({"cidrs": ["10.20.0.0/16"]}).check("2001:db8::1")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH


def test_ip_outside_cidr_denied() -> None:
    decision = _scope({"cidrs": ["10.20.0.0/16"]}).check("10.30.0.1")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH


# --------------------------------------------- path normalization (false-allow) ---
def test_url_dot_segment_traversal_denied() -> None:
    scope = _scope({"urls": ["https://app.corp.example/admin"]})
    assert not scope.check("https://app.corp.example/admin/../secret").authorized
    assert (
        scope.check("https://app.corp.example/admin/../secret").reason
        is ScopeDenyReason.OUT_OF_SCOPE_NO_MATCH
    )


def test_url_encoded_traversal_denied() -> None:
    scope = _scope({"urls": ["https://app.corp.example/admin"]})
    assert not scope.check("https://app.corp.example/admin/%2e%2e/secret").authorized


def test_url_dot_segment_within_scope_authorized() -> None:
    scope = _scope({"urls": ["https://app.corp.example/admin"]})
    assert scope.check("https://app.corp.example/admin/./users").authorized


# --------------------------------------------- deny-wins across kinds ---
def test_cross_kind_host_exclusion_blocks_http() -> None:
    scope = _scope({"wildcard_domains": ["*.example.com"]}, {"hosts": ["secret.example.com"]})
    decision = scope.check("https://secret.example.com/")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.EXCLUDED_BY_RULE


def test_cross_kind_host_exclusion_blocks_endpoint() -> None:
    scope = _scope({"hosts": ["dc01.corp.example"]}, {"domains": ["dc01.corp.example"]})
    decision = scope.check("smb://dc01.corp.example:445")
    assert not decision.authorized
    assert decision.reason is ScopeDenyReason.EXCLUDED_BY_RULE
