"""Local, stdlib-only listing of code-owned actions and bundle provenance."""

from __future__ import annotations

import json
import os
import sys


def _remote_available(engagement: str | None) -> dict[str, bool]:
    """Probe the remote host for each registered action's tool; raise on error."""
    from hackbot.risk.registry import RegistryError
    from hackbot.tools.actions import REAL_ACTIONS, REGISTERED_ACTION_IDS
    from hackbot.tools.remote import RemoteError, RemoteRunner, load_remote_config

    if not engagement:
        raise RemoteError("--runner remote requires --engagement")
    tool_of: dict[str, str] = {}
    for action_id in REGISTERED_ACTION_IDS:
        try:
            definition = REAL_ACTIONS.require(action_id)
        except RegistryError:
            continue
        if definition.executable:
            tool_of[action_id] = os.path.basename(definition.executable)
    config = load_remote_config(os.path.join(engagement, "runner.json"))
    present = RemoteRunner(config).probe(set(tool_of.values()))
    return {action_id: tool in present for action_id, tool in tool_of.items()}


def cmd_list(*, as_json: bool, engagement: str | None = None, runner: str = "local") -> int:
    from hackbot.skills.promotion import PROMOTED_ACTIONS
    from hackbot.tools.actions import REGISTERED_ACTION_IDS

    remote: dict[str, bool] | None = None
    if runner == "remote":
        from hackbot.tools.remote import RemoteError

        try:
            remote = _remote_available(engagement)
        except RemoteError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    elif runner != "local":
        print(f"error: unknown runner: {runner}", file=sys.stderr)
        return 2

    ids = sorted(set(REGISTERED_ACTION_IDS) | set(PROMOTED_ACTIONS))
    rows: list[dict[str, object]] = []
    for action_id in ids:
        prov = PROMOTED_ACTIONS.get(action_id)
        row: dict[str, object] = {
            "action_id": action_id,
            "available": action_id in REGISTERED_ACTION_IDS,
            "skill": prov.skill_id if prov else None,
            "source_note": prov.source_note if prov else None,
            "bundle_risk_level": prov.bundle_risk_level if prov else None,
            "approval_level": prov.approval_level if prov else None,
            "attribution": prov.attribution if prov else None,
        }
        if remote is not None:
            # None = the action is not registered locally, so its tool is unknown
            # and was not probed (e.g. nmap absent on this host).
            row["remote_available"] = remote.get(action_id)
        rows.append(row)
    if as_json:
        print(json.dumps({"skills": rows}, indent=2, sort_keys=True))
    else:
        for row in rows:
            mark = "available" if row["available"] else "unavailable"
            if remote is not None:
                avail = row.get("remote_available")
                mark = "remote" if avail else ("unknown" if avail is None else "no-remote")
            skill = row["skill"] or "(not bundle-derived)"
            print(f"  {row['action_id']:<20} [{mark:<11}] {skill}")
    return 0
