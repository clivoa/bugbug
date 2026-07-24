"""
Critical scope-engine tests. These encode the non-negotiable safety properties:
out-of-scope blocked, redirects re-checked, deny-wins, default-deny, discovery
never expands scope, shared CDN/cloud ranges rejected, IP vs domain distinction,
and target content cannot mutate scope.
"""

import pytest

from hackbot.scope import Scope, ScopeKind, classify_target


@pytest.fixture
def scope():
    return Scope(
        in_scope=[
            "example.com",
            "*.api.example.com",
            "203.0.113.0/24",
            "github.com/exampleorg/webapp",
        ],
        out_of_scope=["internal.example.com", "test.api.example.com"],
        name="unit",
    )


# --- default-deny ----------------------------------------------------------
def test_unknown_host_denied(scope):
    d = scope.check("https://evil.com/path")
    assert not d.allowed and "default-deny" in d.reason


def test_apex_and_subdomain_allowed(scope):
    assert scope.check("https://example.com/").allowed
    sub = scope.check("https://blog.example.com/")
    assert sub.allowed and sub.matched_rule == "example.com"


def test_wildcard_requires_subdomain_not_apex(scope):
    assert scope.check("https://v1.api.example.com/").allowed  # subdomain ok
    # bare apex of a *. rule is NOT matched by that rule; but example.com covers it
    d = scope.check("https://api.example.com/")
    assert d.allowed and d.matched_rule == "example.com"


# --- deny wins -------------------------------------------------------------
def test_excluded_beats_included(scope):
    d = scope.check("https://internal.example.com/")
    assert not d.allowed
    assert d.rule_source == "scope.excluded_assets"


def test_excluded_subdomain_under_wildcard(scope):
    # test.api.example.com matches *.api.example.com but is explicitly excluded
    d = scope.check("https://test.api.example.com/")
    assert not d.allowed and d.matched_rule == "test.api.example.com"


# --- redirects -------------------------------------------------------------
def test_redirect_out_of_scope_blocked(scope):
    d = scope.check_redirect("https://example.com/login", "https://evil.com/steal")
    assert not d.allowed and "redirect-out" in d.risk_flags


def test_redirect_in_scope_allowed(scope):
    d = scope.check_redirect("https://example.com/a", "https://blog.example.com/b")
    assert d.allowed


# --- IP vs domain, CIDR ----------------------------------------------------
def test_ip_in_cidr_allowed(scope):
    d = scope.check("http://203.0.113.45:8080/")
    assert d.allowed and "ip-literal" in d.risk_flags


def test_ip_outside_cidr_denied(scope):
    assert not scope.check("http://198.51.100.5/").allowed


# --- shared CDN / cloud ranges --------------------------------------------
def test_shared_cdn_range_rejected_unless_explicit():
    s = Scope(in_scope=["example.com"], out_of_scope=[])
    # 104.16.0.1 is inside a Cloudflare shared range
    d = s.check("http://104.16.0.1/")
    assert not d.allowed and "shared-cdn" in d.risk_flags


def test_shared_cdn_range_allowed_if_explicitly_listed():
    s = Scope(in_scope=["example.com", "104.16.0.1"], out_of_scope=[])
    d = s.check("http://104.16.0.1/")
    assert d.allowed and "shared-cdn" in d.risk_flags


# --- discovery != authorization -------------------------------------------
def test_scope_is_immutable_no_expansion_api(scope):
    """There must be NO public method that adds scope at runtime."""
    mutators = [
        a
        for a in dir(scope)
        if a in ("add", "add_domain", "extend", "include", "expand", "add_in_scope", "update")
    ]
    assert mutators == [], f"scope must not expose expansion methods: {mutators}"


def test_discovered_asset_not_authorized(scope):
    """An asset merely 'discovered' (e.g. via cert/ASN) is still default-denied."""
    # Pretend recon found this via a shared certificate; it is not in scope.
    assert not scope.check("https://acme-cert-sibling.net/").allowed


def test_target_content_cannot_mutate_scope(scope):
    """
    Simulate malicious target content trying to widen scope. The scope object has
    no ingestion path, so a check for the injected host still denies.
    """
    injected = "attacker-controlled.com"
    # even if some code naively appended to a list it read from a page, our Scope
    # copies its rules at construction and exposes only read-only tuples:
    assert isinstance(scope.in_scope, tuple)
    with pytest.raises((AttributeError, TypeError)):
        scope.in_scope.append(injected)  # tuples are immutable
    assert not scope.check(f"https://{injected}/").allowed


# --- non-web kinds ---------------------------------------------------------
def test_repo_scope(scope):
    assert classify_target("github.com/exampleorg/webapp") == ScopeKind.REPO
    assert scope.check("https://github.com/exampleorg/webapp/blob/main/x").allowed
    assert not scope.check("https://github.com/other/repo").allowed


def test_contract_and_mobile_classification():
    assert classify_target("eth:0x" + "a" * 40) == ScopeKind.CONTRACT
    assert classify_target("com.example.app") == ScopeKind.MOBILE


# --- IPv6 CIDR -------------------------------------------------------------
def test_ipv6_cidr_in_scope():
    s = Scope(in_scope=["2001:db8::/32"], out_of_scope=[])
    d = s.check("http://[2001:db8::1]/")
    assert d.allowed and "ip-literal" in d.risk_flags
    assert s.check("2001:db8:0:0::abcd").allowed  # bare IPv6 literal


def test_ipv6_outside_cidr_denied():
    s = Scope(in_scope=["2001:db8::/32"], out_of_scope=[])
    assert not s.check("http://[2001:dead::1]/").allowed


def test_ipv4_not_matched_by_ipv6_cidr_and_vice_versa():
    s6 = Scope(in_scope=["2001:db8::/32"], out_of_scope=[])
    assert not s6.check("http://203.0.113.5/").allowed  # v4 vs v6 rule
    s4 = Scope(in_scope=["203.0.113.0/24"], out_of_scope=[])
    assert not s4.check("http://[2001:db8::1]/").allowed  # v6 vs v4 rule


# --- URL / path scope rules ------------------------------------------------
def test_path_rule_segment_aware():
    s = Scope(in_scope=["example.com/api"], out_of_scope=[])
    assert s.check("https://example.com/api").allowed
    assert s.check("https://example.com/api/users/1").allowed
    d = s.check("https://example.com/api2")  # NOT a path segment match
    assert not d.allowed and "path-out" in d.risk_flags
    assert not s.check("https://example.com/admin").allowed


def test_path_rule_with_scheme_and_wildcard():
    s = Scope(in_scope=["https://*.example.com/admin"], out_of_scope=[])
    assert s.check("https://panel.example.com/admin/x").allowed
    assert not s.check("https://panel.example.com/public").allowed
    assert not s.check("https://example.com/admin").allowed  # bare apex excluded by *.


def test_host_only_rule_matches_any_path():
    s = Scope(in_scope=["example.com"], out_of_scope=[])
    assert s.check("https://example.com/anything/at/all").allowed


# --- genuine instance immutability ----------------------------------------
def test_scope_instance_is_frozen(scope):
    with pytest.raises(AttributeError):
        scope._in = ()  # cannot reassign internal state
    with pytest.raises(AttributeError):
        scope.name = "hacked"  # cannot reassign public attr
    with pytest.raises(AttributeError):
        scope.new_attr = 1  # cannot add attributes (slots + frozen)
