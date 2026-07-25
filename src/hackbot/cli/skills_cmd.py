"""Local, stdlib-only listing of code-owned actions and bundle provenance."""

from __future__ import annotations

import json


def cmd_list(*, as_json: bool) -> int:
    from hackbot.skills.promotion import PROMOTED_ACTIONS
    from hackbot.tools.actions import REGISTERED_ACTION_IDS

    ids = sorted(set(REGISTERED_ACTION_IDS) | set(PROMOTED_ACTIONS))
    rows: list[dict[str, object]] = []
    for action_id in ids:
        prov = PROMOTED_ACTIONS.get(action_id)
        rows.append(
            {
                "action_id": action_id,
                "available": action_id in REGISTERED_ACTION_IDS,
                "skill": prov.skill_id if prov else None,
                "source_note": prov.source_note if prov else None,
                "bundle_risk_level": prov.bundle_risk_level if prov else None,
                "approval_level": prov.approval_level if prov else None,
                "attribution": prov.attribution if prov else None,
            }
        )
    if as_json:
        print(json.dumps({"skills": rows}, indent=2, sort_keys=True))
    else:
        for row in rows:
            mark = "available" if row["available"] else "unavailable"
            skill = row["skill"] or "(not bundle-derived)"
            print(f"  {row['action_id']:<18} [{mark:<11}] {skill}")
    return 0
