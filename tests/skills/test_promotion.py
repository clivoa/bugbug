"""Recon-bundle provenance is validated against the generated manifest."""

import yaml

from hackbot.skills.promotion import PROMOTED_ACTIONS
from hackbot.tools.actions import REGISTERED_ACTION_IDS

_MANIFEST = "generated/recon-bundle/manifest.yaml"


def _manifest_pairs():
    with open(_MANIFEST, encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle)
    pairs: set[tuple[str, str]] = set()
    internal: set[str] = set()
    for skill in manifest["skills"]:
        pairs.add((skill["skill"], skill["source_note"]))
        if skill.get("internal_pack"):
            internal.add(skill["skill"])
    return pairs, internal


def test_every_promotion_maps_to_a_real_reviewed_skill():
    pairs, internal = _manifest_pairs()
    for action_id, prov in PROMOTED_ACTIONS.items():
        assert (prov.skill_id, prov.source_note) in pairs, action_id
        assert prov.skill_id not in internal  # internal-recon is never promoted
        assert "CyberNeon" in prov.attribution


# Action IDs that derive from the recon bundle and must have provenance.
# Other registered actions (remote arsenal, cloud, web3, etc.) are not
# bundle-derived and are not expected in PROMOTED_ACTIONS.
_BUNDLE_DERIVED_PREFIXES = frozenset({
    "dns.",           # dns.lookup, dns.txt, dns.mx, dns.ns
    "net.http-get",   # core HTTP probe
    "net.http-head",  # core HTTP probe
    "net.http-options",
    "net.port-scan",  # recon bundle port scanning
    "tls.cert",       # recon bundle TLS
    "web.dir-enum",   # recon bundle directory enumeration
    "web.dir-enum-gobuster",
})


def _is_bundle_derived(action_id: str) -> bool:
    """Check if an action ID is bundle-derived (exact match or prefix)."""
    for prefix in _BUNDLE_DERIVED_PREFIXES:
        if action_id == prefix or (
            prefix.endswith(".") and action_id.startswith(prefix)
        ):
            return True
    return False


def test_every_registered_bundle_action_has_provenance():
    for action_id in REGISTERED_ACTION_IDS:
        if not _is_bundle_derived(action_id):
            continue
        assert action_id in PROMOTED_ACTIONS, (
            f"bundle-derived action {action_id!r} missing from PROMOTED_ACTIONS"
        )
