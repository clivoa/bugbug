"""
hackbot CLI — the operator entry point.

Wires the pieces that exist today: `doctor`, `scope`, `secrets`. Built on the
standard-library argparse so the core runs with no third-party dependencies (and
installs/runs fully offline). Richer UX (typer/rich) can layer on later.

Safety: `secrets set` reads the value from getpass/stdin (never argv). `doctor`
is strictly read-only. Nothing here performs target-network activity — that lives
behind the scope + risk gates in later phases.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

VERSION = "0.1.0"


# ------------------------------------------------------------ subcommands ---
def _cmd_doctor(args: argparse.Namespace) -> int:
    from hackbot import doctor

    if args.json:
        print(json.dumps(doctor.as_dict(no_net=args.no_net), indent=2))
    else:
        print(doctor.render_text(no_net=args.no_net))
    return 0


def _load_scope(args: argparse.Namespace):
    from hackbot.scope import Scope

    if getattr(args, "scope_file", None):
        # validated, typed scope.yaml/json via the strict schema (default-deny)
        from hackbot.programs import loader
        from hackbot.programs.schema import ValidationError

        try:
            return loader.load_scope_file(args.scope_file, name="cli")
        except ValidationError as e:
            print("invalid scope file (default-deny):", file=sys.stderr)
            for m in e.errors:
                print(f"  - {m}", file=sys.stderr)
            raise SystemExit(2) from None
        except loader.ProgramError as e:
            print(f"error: {e}", file=sys.stderr)
            raise SystemExit(2) from None
    in_scope = list(args.in_scope or [])
    out_scope = list(args.out_scope or [])
    if not in_scope:
        print("error: no in-scope rules given (use --in or --scope-file)", file=sys.stderr)
        raise SystemExit(2)
    return Scope(in_scope=in_scope, out_of_scope=out_scope, name="cli")


def _cmd_scope(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    decision = scope.check(args.target)
    if args.action == "explain" or args.json:
        if args.json:
            print(
                json.dumps(
                    {
                        "allowed": decision.allowed,
                        "target": decision.target,
                        "kind": decision.kind.value,
                        "reason": decision.reason,
                        "matched_rule": decision.matched_rule,
                        "rule_source": decision.rule_source,
                        "risk_flags": list(decision.risk_flags),
                    },
                    indent=2,
                )
            )
        else:
            print(decision.explain())
    else:
        print(f"{'ALLOW' if decision.allowed else 'DENY '}  {decision.target}  ({decision.reason})")
    return 0 if decision.allowed else 1


class _SecretsUnavailable(Exception):
    """Raised (and handled cleanly) when the keychain backend cannot be created."""


def _secret_manager():
    from hackbot.security.secrets import (
        InMemoryBackend,
        KeyringBackend,
        SecretError,
        SecretManager,
    )

    backend = os.environ.get("HACKBOT_SECRET_BACKEND", "keyring").lower()
    if backend == "memory":
        return SecretManager(backend=InMemoryBackend())
    try:
        return SecretManager(backend=KeyringBackend())
    except SecretError as e:
        raise _SecretsUnavailable(str(e)) from e


def _cmd_secrets(args: argparse.Namespace) -> int:
    # The import DRY-RUN only reads local files — it must work in a stdlib-only
    # install with NO keychain backend present. Handle it before touching keyring.
    if args.action == "import-claude-settings" and args.dry_run:
        from hackbot.security import claude_import as ci

        results = ci.plan_imports(args.dir or ".claude")
        print(ci.render_plan(results, applied=False))
        print("\n[dry-run] nothing was imported. Re-run without --dry-run to apply.")
        return 0

    try:
        mgr = _secret_manager()
    except _SecretsUnavailable as e:
        # Missing optional dependency: guide the user, never dump a traceback.
        print(
            "secrets backend unavailable: " + str(e) + "\n"
            "  install the keychain backend:  pip install 'hackbot[secrets]'\n"
            "  (or, for tests only:           HACKBOT_SECRET_BACKEND=memory)",
            file=sys.stderr,
        )
        return 3
    if args.action == "list":
        status = mgr.status()
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            for name, present in status.items():
                print(f"  {'[set]    ' if present else '[missing]'} {name}")
        return 0
    if args.action == "set":
        # value read WITHOUT echo (getpass) or from stdin pipe; never from argv.
        if sys.stdin.isatty():
            value = getpass.getpass(f"Enter value for {args.name} (hidden): ")
        else:
            value = sys.stdin.readline().rstrip("\n")
        try:
            cname = mgr.set(args.name, value)
        except Exception as e:  # noqa: BLE001
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"stored {cname} (value not displayed)")
        return 0
    if args.action == "test":
        present = mgr.exists(args.name)
        print(f"{args.name}: {'present' if present else 'MISSING'}")
        return 0 if present else 1
    if args.action == "delete":
        ok = mgr.delete(args.name)
        print(f"{'deleted' if ok else 'not found'}: {args.name}")
        return 0 if ok else 1
    if args.action == "import-claude-settings":
        from hackbot.security import claude_import as ci

        directory = args.dir or ".claude"
        results = ci.apply_imports(directory, mgr, force=args.force)
        print(ci.render_plan(results, applied=True))
        _ok, _skipped, failed = ci.summarize(results)
        return 0 if failed == 0 else 4  # partial completion -> nonzero
    return 2


def _cmd_program(args: argparse.Namespace) -> int:
    from pathlib import Path

    from hackbot.programs import engagement, loader, schema

    if args.paction == "validate":
        errors = loader.validate_file(args.file)
        if errors:
            print(f"INVALID: {args.file}", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            return 1
        print(f"valid: {args.file}")
        return 0

    # import
    try:
        doc, scope = loader.load_program_file(args.file, name="import")
    except schema.ValidationError as e:
        print("INVALID program — refusing import (default-deny):", file=sys.stderr)
        for m in e.errors:
            print(f"  - {m}", file=sys.stderr)
        return 1
    except loader.ProgramError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    program_block = doc.get("program") or {}
    platform = args.platform or program_block.get("platform")
    program = args.program or program_block.get("name")
    if not platform or not program:
        print(
            "error: platform/program required (via --platform/--program or "
            "program.platform / program.name)",
            file=sys.stderr,
        )
        return 2

    scope_doc = {"schema_version": schema.SCHEMA_VERSION, **(doc.get("scope") or {})}
    rules_md = Path(args.rules).read_text(encoding="utf-8") if args.rules else None
    try:
        path = engagement.create_engagement(
            args.engagements_dir,
            platform=platform,
            program=program,
            program_doc=doc,
            scope_doc=scope_doc,
            rules_md=rules_md,
        )
    except engagement.EngagementExists as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except loader.ProgramError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"created engagement: {path}")
    print(
        f"  in-scope rules: {len(scope.in_scope)}  |  "
        f"out-of-scope rules: {len(scope.out_of_scope)}  |  authorization: NOT confirmed"
    )
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"hackbot {VERSION}")
    return 0


# ---------------------------------------------------------------- parser ---
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hackbot",
        description="Local, safety-controlled bug-bounty research workstation.",
    )
    p.add_argument("--version", action="version", version=f"hackbot {VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("doctor", help="read-only environment diagnostic")
    d.add_argument("--json", action="store_true")
    d.add_argument("--no-net", action="store_true")
    d.set_defaults(func=_cmd_doctor)

    s = sub.add_parser("scope", help="check/explain whether a target is in scope")
    s.add_argument("action", choices=["check", "explain"])
    s.add_argument("target")
    s.add_argument(
        "--in", dest="in_scope", action="append", metavar="RULE", help="in-scope rule (repeatable)"
    )
    s.add_argument(
        "--out",
        dest="out_scope",
        action="append",
        metavar="RULE",
        help="out-of-scope rule (repeatable)",
    )
    s.add_argument("--scope-file", help="JSON file: {in_scope:[...], out_of_scope:[...]}")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_scope)

    sec = sub.add_parser("secrets", help="manage secrets in the OS keychain (values never shown)")
    sec.add_argument("action", choices=["list", "set", "test", "delete", "import-claude-settings"])
    sec.add_argument("name", nargs="?", help="secret name/alias (e.g. shodan, kimi3)")
    sec.add_argument("--dir", help="directory of Claude settings files (import-claude-settings)")
    sec.add_argument(
        "--dry-run",
        action="store_true",
        help="import-claude-settings: show the plan, import nothing",
    )
    sec.add_argument(
        "--force",
        action="store_true",
        help="import-claude-settings: replace an existing keychain entry (default: skip)",
    )
    sec.add_argument("--json", action="store_true")
    sec.set_defaults(func=_cmd_secrets)

    pr = sub.add_parser("program", help="validate/import LOCAL program & scope files (no network)")
    pr.add_argument("paction", choices=["validate", "import"])
    pr.add_argument("file", help="program.yaml/.json (import) or program/scope file (validate)")
    pr.add_argument("--platform", help="override platform (else program.platform)")
    pr.add_argument("--program", help="override program name (else program.name)")
    pr.add_argument("--rules", help="optional rules.md file to store with the engagement")
    pr.add_argument("--engagements-dir", default="engagements")
    pr.set_defaults(func=_cmd_program)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=_cmd_version)
    return p


def app(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "secrets" and args.action in ("set", "test", "delete") and not args.name:
        parser.error(f"secrets {args.action} requires a name")
    return args.func(args)


def main() -> None:  # console_script wrapper
    raise SystemExit(app())


if __name__ == "__main__":
    main()
