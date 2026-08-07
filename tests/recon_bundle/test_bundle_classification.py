"""
Policy tests for recon-bundle classification and the generated manifest.

These enforce the risk-normalization rules: internal-recon disabled by default,
discovery never auto-expands scope, shared CDN/cloud ranges excluded, high-volume
actions require approval, macOS-incompatible commands are detected, and
attribution survives normalization.
"""

from pathlib import Path

import pytest
import yaml

from hackbot.skills.bundle_classify import classify_all, detect_portability
from hackbot.skills.bundle_parser import parse_bundle

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "references/recon/Recon-bundle.html"
MANIFEST = ROOT / "generated/recon-bundle/manifest.yaml"


@pytest.fixture(scope="module")
def classifications():
    return {c.note_id: c for c in classify_all(parse_bundle(BUNDLE))}


@pytest.fixture(scope="module")
def manifest():
    assert MANIFEST.exists(), "run scripts/generate_recon_bundle.py first"
    return yaml.safe_load(MANIFEST.read_text())


# --- internal-recon disabled by default -----------------------------------
INTERNAL = {
    "note-descoberta-hosts-rede-interna",
    "note-enumeracao-ldap",
    "note-enumeracao-linux",
}


def test_internal_recon_disabled_by_default(classifications):
    for nid in INTERNAL:
        c = classifications[nid]
        assert c.internal_pack is True
        assert c.risk_level == "disabled"
        assert c.approval_level == "forbidden-by-default"
        assert c.assessment == "internal"
        assert c.skill_target.startswith("internal-recon/")
        assert c.bug_bounty == "disabled"


def test_no_external_note_lands_in_internal_pack(classifications):
    for nid, c in classifications.items():
        if nid not in INTERNAL:
            assert not c.skill_target.startswith("internal-recon/"), nid


# --- discovery never auto-expands scope -----------------------------------
def test_asn_netblock_requires_explicit_approval(classifications):
    """ASN/netblock is a hypothesis source, never an auto scope expansion."""
    c = classifications["note-asn-netblock"]
    assert c.risk_level == 2
    assert c.approval_level == "explicit"  # never 'auto-if-in-scope'
    assert c.approval_level != "none"


def test_cdn_cloud_sections_excluded(classifications):
    """Shared CDN/cloud ranges and origin-bypass sections must be excluded."""
    asn = classifications["note-asn-netblock"]
    waf = classifications["note-waf-cdn-detection"]
    assert any("cloud" in s.lower() or "cdn" in s.lower() for s in asn.disabled_sections)
    assert any("bypass" in s.lower() or "origin" in s.lower() for s in waf.disabled_sections)


def test_no_passive_source_grants_auto_active(classifications):
    """
    Passive evidence sources (cert/github/dork/osint) must be L0 with no active
    follow-up baked in — active follow-up is a separate, gated decision.
    """
    for nid in (
        "note-consulta-certificado-tls",
        "note-github-recon",
        "note-google-dorking",
        "note-osint-tools",
    ):
        c = classifications[nid]
        assert c.risk_level == 0
        assert c.approval_level == "none"
        assert c.recon_type == "passive"


# --- high-volume active actions require approval ---------------------------
def test_high_volume_requires_explicit_approval(classifications):
    for nid in (
        "note-param-fuzzing",
        "note-enumeracao-diretorios",
        "note-port-scanning-bash",
        "note-banner-scanning",
        "note-tcp-fin-fingerprint",
    ):
        c = classifications[nid]
        assert c.risk_level == 2, nid
        assert c.approval_level == "explicit", nid


# --- macOS incompatibility detection --------------------------------------
def test_dev_tcp_detected():
    findings = detect_portability(["for p in 1 2 3; do echo > /dev/tcp/$h/$p; done"])
    assert any(f["id"] == "bash-dev-tcp" for f in findings)


def test_proc_net_arp_detected():
    findings = detect_portability(["cat /proc/net/arp"])
    assert any(f["id"] == "proc-net-arp" for f in findings)


def test_bundle_macos_findings_present(classifications):
    """The port-scan note (uses /dev/tcp) must carry a macOS finding."""
    c = classifications["note-port-scanning-bash"]
    ids = {f["id"] for f in c.macos_findings}
    assert "bash-dev-tcp" in ids


# --- manifest integrity & attribution -------------------------------------
def test_manifest_maps_all_notes(manifest):
    assert manifest["note_count"] == 19
    assert len(manifest["skills"]) == 19


def test_manifest_preserves_attribution(manifest):
    assert "cyberneon" in manifest["bundle_author"].lower()
    assert manifest["bundle_license_declared"] == "none-found"
    for s in manifest["skills"]:
        assert "cyberneon" in s["attribution"].lower()
        assert s["source_note"]
        assert s["source_file"] == "references/recon/Recon-bundle.html"


def test_manifest_source_hash_matches(manifest):
    import hashlib

    actual = hashlib.sha256(BUNDLE.read_bytes()).hexdigest()
    assert manifest["source_sha256"] == actual
