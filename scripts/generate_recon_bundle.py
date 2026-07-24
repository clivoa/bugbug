#!/usr/bin/env python3
"""
generate_recon_bundle — build the normalized (reviewed) layer from the immutable
bundle. Reads references/recon/Recon-bundle.html as INERT DATA and writes:

  generated/recon-bundle/notes/<note-id>.json   normalized note + classification
  generated/recon-bundle/manifest.yaml          skill<-note mapping (required schema)

Nothing here executes bundle commands. The original file is never modified.

Usage: PYTHONPATH=src python3 scripts/generate_recon_bundle.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hackbot.skills.bundle_classify import classify_all  # noqa: E402
from hackbot.skills.bundle_parser import bundle_metadata, parse_bundle  # noqa: E402

BUNDLE = ROOT / "references/recon/Recon-bundle.html"
OUT = ROOT / "generated/recon-bundle"
ATTRIB = "@reeshasx (CyberNeon Recon Bundle) — https://x.com/reeshasx"


def _yaml_str(s: str) -> str:
    s = (s or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return f'"{s}"'


def _yaml_list(items: list[str], indent: str) -> str:
    if not items:
        return " []"
    return "\n" + "\n".join(f"{indent}- {_yaml_str(i)}" for i in items)


def main() -> int:
    meta = bundle_metadata(BUNDLE)
    notes = parse_bundle(BUNDLE)
    cls = {c.note_id: c for c in classify_all(notes)}
    src_hash = hashlib.sha256(BUNDLE.read_bytes()).hexdigest()

    (OUT / "notes").mkdir(parents=True, exist_ok=True)

    # per-note normalized JSON
    for n in notes:
        c = cls[n.note_id]
        payload = {
            "note": n.to_dict(),
            "classification": c.to_dict(),
            "attribution": ATTRIB,
            "source_file": "references/recon/Recon-bundle.html",
            "source_sha256": src_hash,
        }
        (OUT / "notes" / f"{n.note_id}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # manifest.yaml (required schema: skill/source_file/source_note/... per entry)
    lines: list[str] = []
    lines.append("# Recon bundle normalization manifest")
    lines.append("# Maps each normalized skill back to its immutable source note.")
    lines.append(
        "# GENERATED — do not edit by hand. Regenerate via scripts/generate_recon_bundle.py"
    )
    lines.append(f"bundle_title: {_yaml_str(meta.get('title', ''))}")
    lines.append(f"bundle_author: {_yaml_str(meta.get('author', ''))}")
    lines.append(f"bundle_author_link: {_yaml_str(meta.get('author_link', ''))}")
    lines.append(f"bundle_license_declared: {_yaml_str(meta.get('license_declared', ''))}")
    lines.append(
        'bundle_authorization: "local private use with attribution (operator 2026-07-24); redistribution NOT authorized"'
    )
    lines.append('source_file: "references/recon/Recon-bundle.html"')
    lines.append(f'source_sha256: "{src_hash}"')
    lines.append(f"note_count: {len(notes)}")
    lines.append("skills:")
    for n in notes:
        c = cls[n.note_id]
        skill_name = c.skill_target.split("/")[-1]
        commands_excluded = list(c.disabled_sections)
        risk_changes = []
        if c.risk_level == "disabled":
            risk_changes.append("moved to internal-recon; disabled by default")
        elif c.risk_level == 2:
            risk_changes.append("active sections require explicit approval (L2)")
        if c.disabled_sections:
            risk_changes.append("scope-leaving / protection-bypass sections excluded")
        adaptations = [f"{m['id']}: {m['adaptation']}" for m in c.macos_findings]
        lines.append(f"  - skill: {_yaml_str(c.skill_target)}")
        lines.append(f"    skill_name: {_yaml_str(skill_name)}")
        lines.append('    source_file: "references/recon/Recon-bundle.html"')
        lines.append(f"    source_note: {_yaml_str(n.note_id)}")
        lines.append(f"    source_heading: {_yaml_str(n.title)}")
        lines.append(f"    source_updated_date: {_yaml_str(n.updated)}")
        lines.append(f"    recon_type: {_yaml_str(c.recon_type)}")
        lines.append(f"    assessment: {_yaml_str(c.assessment)}")
        lines.append(f"    bug_bounty: {_yaml_str(c.bug_bounty)}")
        lines.append(f"    risk_level: {_yaml_str(str(c.risk_level))}")
        lines.append(f"    approval_level: {_yaml_str(c.approval_level)}")
        lines.append(f"    internal_pack: {'true' if c.internal_pack else 'false'}")
        lines.append(f"    command_count: {len(n.commands)}")
        lines.append(f"    adaptations:{_yaml_list(adaptations, '      ')}")
        lines.append(f"    risk_changes:{_yaml_list(risk_changes, '      ')}")
        lines.append(
            '    commands_rewritten: "all commands converted to validated tool adapters (see src/hackbot/tools)"'
        )
        lines.append(f"    commands_excluded:{_yaml_list(commands_excluded, '      ')}")
        lines.append(f"    attribution: {_yaml_str(ATTRIB)}")

    (OUT / "manifest.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {len(notes)} note JSON files -> {OUT / 'notes'}")
    print(f"wrote manifest -> {OUT / 'manifest.yaml'}")
    print(f"source sha256 = {src_hash[:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
