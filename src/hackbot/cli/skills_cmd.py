"""List code-owned actions and their skill domains."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _load_skills_yaml() -> dict[str, object] | None:
    """Load skills/skills.yaml from the project root, returning the parsed registry."""
    candidates = [
        Path(__file__).resolve().parent.parent.parent.parent.parent / "skills" / "skills.yaml",
        Path.cwd() / "skills" / "skills.yaml",
    ]
    for path in candidates:
        if path.is_file():
            try:
                import yaml as _yaml  # type: ignore[import-not-found]
                with open(path, encoding="utf-8") as fh:
                    return _yaml.safe_load(fh)
            except Exception:
                pass
    return None


def _skill_for_action(action_id: str, registry: dict[str, object] | None) -> str | None:
    """Look up which skill domain an action belongs to."""
    if not registry:
        return None
    skills = registry.get("skills", {})
    if not isinstance(skills, dict):
        return None
    for _key, skill in skills.items():
        if not isinstance(skill, dict):
            continue
        actions = skill.get("actions", [])
        if isinstance(actions, list) and action_id in actions:
            return skill.get("display", _key)
    return None


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
    from hackbot.tools.actions import REGISTERED_ACTION_IDS

    registry = _load_skills_yaml()

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

    ids = sorted(REGISTERED_ACTION_IDS)
    rows: list[dict[str, object]] = []
    for action_id in ids:
        skill_domain = _skill_for_action(action_id, registry)
        row: dict[str, object] = {
            "action_id": action_id,
            "available": True,
            "skill_domain": skill_domain,
        }
        if remote is not None:
            row["remote_available"] = remote.get(action_id)
        rows.append(row)

    # Summarize skill domains
    if registry and not as_json:
        skills = registry.get("skills", {})
        if isinstance(skills, dict):
            domains = sorted(
                {s.get("display", k) for k, s in skills.items() if isinstance(s, dict)}
            )
            print(f"Skill domains: {len(domains)} loaded from skills/skills.yaml")
            for domain in domains:
                count = sum(
                    1
                    for s in skills.values()
                    if isinstance(s, dict)
                    and s.get("display") == domain
                    and isinstance(s.get("actions"), list)
                    and len(s["actions"])
                )
                disabled = any(
                    isinstance(s, dict) and s.get("disabled_by_default")
                    for s in skills.values()
                    if s.get("display") == domain
                )
                flag = " [DISABLED]" if disabled else ""
                print(f"  {domain}{flag} ({count} actions)")
            print()

    if as_json:
        print(json.dumps({"skills": rows, "registry_loaded": registry is not None}, indent=2, sort_keys=True))
    else:
        for row in rows:
            mark = "available" if row["available"] else "unavailable"
            if remote is not None:
                avail = row.get("remote_available")
                mark = "remote" if avail else ("unknown" if avail is None else "no-remote")
            skill = row.get("skill_domain") or "(unmapped)"
            print(f"  {row['action_id']:<40} [{mark:<11}] {skill}")
    return 0
