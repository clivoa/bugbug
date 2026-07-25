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
        assert "@reeshasx" in prov.attribution


def test_every_registered_bundle_action_has_provenance():
    for action_id in REGISTERED_ACTION_IDS:
        if action_id in ("net.http-post",):  # generic POST, not bundle-derived
            continue
        assert action_id in PROMOTED_ACTIONS, action_id
