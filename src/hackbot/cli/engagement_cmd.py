"""`hackbot engagement` — read-only engagement v2 helpers.

P1 exposes only the read-only dry-run migration analysis. It reads and
v1-validates the source engagement, then prints the proposed v2 tree and
warnings. It writes nothing: no engagement file, backup, temporary tree, or
in-place edit. Effective migration and restore are delivered later (P7).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hackbot.engagement_v2.migration import MigrationError, analyze_migration


def _read_document(path: Path) -> dict:
    from hackbot.programs import loader as v1_loader

    return v1_loader._load_mapping(path)


def _validate_v1(engagement_dir: Path) -> tuple[dict, dict, dict]:
    from hackbot.programs import loader as v1_loader

    program_path = _resolve(engagement_dir, "program")
    scope_path = _resolve(engagement_dir, "scope")
    if program_path is None or scope_path is None:
        raise MigrationError("v1 engagement is missing program or scope document")

    # The authoritative scope is validated strictly (default-deny). An invalid
    # scope blocks the analysis and nothing is written.
    scope_errors = v1_loader.validate_file(scope_path)
    if scope_errors:
        raise MigrationError(f"invalid v1 scope {scope_path.name}: {'; '.join(scope_errors)}")

    program = _read_document(program_path)
    if not isinstance(program, dict):
        raise MigrationError("v1 program document must be a mapping")
    version = program.get("schema_version")
    if version is not None and version != 1:
        raise MigrationError(f"unsupported v1 program schema_version: {version!r}")

    scope = _read_document(scope_path)
    auth_path = _resolve(engagement_dir, "authorization")
    authorization = _read_document(auth_path) if auth_path is not None else {}
    return program, scope, authorization


def _resolve(engagement_dir: Path, stem: str) -> Path | None:
    for suffix in (".yaml", ".yml", ".json"):
        candidate = engagement_dir / f"{stem}{suffix}"
        if candidate.is_file():
            return candidate
    return None


def run_migrate(args: argparse.Namespace) -> int:
    if args.to != 2:
        print("error: only --to 2 is supported", file=sys.stderr)
        return 2
    if not args.dry_run:
        print(
            "error: effective migration is not available yet; only --dry-run analysis "
            "is supported in this release",
            file=sys.stderr,
        )
        return 2
    if not args.profile:
        print("error: --profile is required for migration", file=sys.stderr)
        return 2

    engagement_dir = Path(args.engagement)
    try:
        from hackbot.programs.loader import ProgramError
        from hackbot.programs.schema import ValidationError

        try:
            v1_program, v1_scope, v1_authorization = _validate_v1(engagement_dir)
        except (ProgramError, ValidationError) as exc:
            raise MigrationError(str(exc)) from exc
        analysis = analyze_migration(
            v1_program=v1_program,
            v1_scope=v1_scope,
            v1_authorization=v1_authorization,
            profile=args.profile,
        )
    except MigrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "profile": analysis.profile,
                    "ready": analysis.ready,
                    "warnings": list(analysis.warnings),
                    "proposed": dict(analysis.proposed),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"dry-run migration analysis (profile: {analysis.profile})")
        print("proposed v2 files:")
        for name in analysis.proposed:
            print(f"  - {name}")
        print("warnings:")
        for warning in analysis.warnings:
            print(f"  - {warning}")
        print(f"ready to apply: {analysis.ready} (analysis only; nothing written)")
    return 0
