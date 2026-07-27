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


_APPROVAL_FIELDS = (
    ("action_id", "action"),
    ("target", "target"),
    ("effective_risk", "risk"),
    ("argv", "argv"),
    ("rate", "rate"),
    ("concurrency", "concurrency"),
    ("hypothesis_id", "hypothesis"),
    ("rationale", "rationale"),
    ("expected_impact", "expected impact"),
    ("data_touched", "data touched"),
    ("stop_condition", "stop condition"),
    ("program_rule", "authorizing rule"),
    ("cleanup_plan", "cleanup plan"),
    ("created_at", "created"),
    ("expires_at", "expires"),
)


def _render_challenge(challenge: object) -> str:
    """Render the operator-review fields only; never the internal binding."""
    lines = ["", "L2 approval required — review every field before confirming:"]
    for attr, label in _APPROVAL_FIELDS:
        value = getattr(challenge, attr, "")
        if attr == "effective_risk":
            value = getattr(value, "name", value)
        lines.append(f"  {label:>16}: {value}")
    lines.append(f"  {'challenge':>16}: {getattr(challenge, 'challenge_digest', '')}")
    return "\n".join(lines) + "\n"


def _read_approval_from_tty(challenge: object) -> None:
    """Confirm an L2 grant interactively through /dev/tty only.

    Raises ``OSError`` when no interactive TTY is available or when the operator
    does not type the exact short code derived from the challenge digest. There
    is no argv, environment, stdin, or piped fallback: a wrong or absent
    confirmation leaves the challenge pending.
    """
    digest = getattr(challenge, "challenge_digest", "")
    expected = f"APPROVE-{digest[:12]}"
    try:
        tty = open("/dev/tty", "r+", encoding="utf-8")  # noqa: SIM115 - closed in finally
    except OSError as exc:
        raise OSError("interactive TTY required to grant an approval") from exc
    try:
        if not tty.isatty():
            raise OSError("interactive TTY required to grant an approval")
        tty.write(_render_challenge(challenge))
        tty.write(f"\nType '{expected}' to approve (anything else cancels): ")
        tty.flush()
        typed = tty.readline()
    finally:
        tty.close()
    if typed.strip() != expected:
        raise OSError("approval confirmation did not match; approval cancelled")


def _cmd_risk(args: argparse.Namespace) -> int:
    from hackbot.cli import risk_cmd

    if args.raction == "evaluate":
        return risk_cmd.cmd_evaluate(args.engagement, args.request, as_json=args.json)
    return 2


def _cmd_approval(args: argparse.Namespace) -> int:
    from hackbot.cli import risk_cmd

    if args.aaction == "status":
        return risk_cmd.cmd_status(args.engagement, args.challenge_id, as_json=args.json)
    if args.aaction == "grant":
        return risk_cmd.cmd_grant(args.engagement, args.challenge_id, as_json=args.json)
    return 2


def _cmd_tool(args: argparse.Namespace) -> int:
    from hackbot.cli import tool_cmd

    if args.taction == "run":
        return tool_cmd.cmd_run(
            args.engagement,
            args.action_id,
            args.request,
            as_json=args.json,
            approve=args.approve,
            runner=args.runner,
        )
    return 2


def _cmd_skills(args: argparse.Namespace) -> int:
    from hackbot.cli import skills_cmd

    if args.saction == "list":
        return skills_cmd.cmd_list(
            as_json=args.json, engagement=args.engagement, runner=args.runner
        )
    return 2


def _cmd_wordlists(args: argparse.Namespace) -> int:
    from hackbot.cli import wordlists_cmd

    if args.wlaction == "list":
        return wordlists_cmd.cmd_list(
            engagement=args.engagement, runner=args.runner, as_json=args.json
        )
    return 2


def _cmd_finding(args: argparse.Namespace) -> int:
    from hackbot.cli import finding_cmd

    if args.faction == "add":
        return finding_cmd.cmd_add(args.engagement, args.descriptor, as_json=args.json)
    if args.faction == "report":
        return finding_cmd.cmd_report(
            args.engagement,
            platform=args.platform,
            templates_dir=args.templates_dir,
        )
    if args.faction == "list":
        return finding_cmd.cmd_list(args.engagement, as_json=args.json)
    return 2


def _cmd_engagement(args: argparse.Namespace) -> int:
    from hackbot.cli.engagement_cmd import run_migrate

    if args.eaction == "migrate":
        return run_migrate(args)
    print(f"error: unknown engagement action {args.eaction!r}", file=sys.stderr)
    return 2


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

    rk = sub.add_parser("risk", help="evaluate a local action request against the policy gate")
    rk_sub = rk.add_subparsers(dest="raction", required=True)
    rk_eval = rk_sub.add_parser(
        "evaluate", help="evaluate REQUEST.json (never executes the action)"
    )
    rk_eval.add_argument("request", help="local request JSON file")
    rk_eval.add_argument("--engagement", required=True, help="engagement directory")
    rk_eval.add_argument("--json", action="store_true")
    rk.set_defaults(func=_cmd_risk)

    ap = sub.add_parser("approval", help="inspect or grant a pending L2 approval (TTY-only)")
    ap_sub = ap.add_subparsers(dest="aaction", required=True)
    ap_grant = ap_sub.add_parser("grant", help="interactively grant a pending challenge (TTY only)")
    ap_grant.add_argument("challenge_id", help="64-hex challenge id")
    ap_grant.add_argument("--engagement", required=True, help="engagement directory")
    ap_grant.add_argument("--json", action="store_true")
    ap_status = ap_sub.add_parser("status", help="report the stored state of a challenge id")
    ap_status.add_argument("challenge_id", help="64-hex challenge id")
    ap_status.add_argument("--engagement", required=True, help="engagement directory")
    ap_status.add_argument("--json", action="store_true")
    ap.set_defaults(func=_cmd_approval)

    tl = sub.add_parser("tool", help="run a code-owned action through the risk gate")
    tl_sub = tl.add_subparsers(dest="taction", required=True)
    tl_run = tl_sub.add_parser("run", help="evaluate then run an action (only if allowed)")
    tl_run.add_argument("action_id", help="code-owned action id (e.g. net.http-get)")
    tl_run.add_argument("request", help="local request JSON file")
    tl_run.add_argument("--engagement", required=True, help="engagement directory")
    tl_run.add_argument(
        "--approve",
        action="store_true",
        help="approve an L2 action at the TTY and run it once",
    )
    tl_run.add_argument(
        "--runner",
        default="local",
        help="where to execute: local | remote (remote reads <engagement>/runner.json)",
    )
    tl_run.add_argument("--json", action="store_true")
    tl.set_defaults(func=_cmd_tool)

    fd = sub.add_parser("finding", help="record and report reproducible findings")
    fd_sub = fd.add_subparsers(dest="faction", required=True)
    fd_add = fd_sub.add_parser("add", help="add a finding from a local descriptor")
    fd_add.add_argument("descriptor", help="local finding JSON file")
    fd_add.add_argument("--engagement", required=True, help="engagement directory")
    fd_add.add_argument("--json", action="store_true")
    fd_report = fd_sub.add_parser("report", help="render all findings to markdown")
    fd_report.add_argument("--engagement", required=True, help="engagement directory")
    fd_report.add_argument(
        "--platform",
        default="generic",
        help="report format: generic|hackerone|bugcrowd|yeswehack|intigriti|immunefi",
    )
    fd_report.add_argument(
        "--templates-dir",
        help="explicit root containing <platform>/report.md and finding.md",
    )
    fd_list = fd_sub.add_parser("list", help="list findings")
    fd_list.add_argument("--engagement", required=True, help="engagement directory")
    fd_list.add_argument("--json", action="store_true")
    fd.set_defaults(func=_cmd_finding)

    sk = sub.add_parser("skills", help="list code-owned actions and recon-bundle provenance")
    sk_sub = sk.add_subparsers(dest="saction", required=True)
    sk_list = sk_sub.add_parser("list", help="list actions, availability, and attribution")
    sk_list.add_argument("--engagement", help="engagement dir (for --runner remote)")
    sk_list.add_argument(
        "--runner", default="local", help="availability to show: local | remote (probes the host)"
    )
    sk_list.add_argument("--json", action="store_true")
    sk.set_defaults(func=_cmd_skills)

    wl = sub.add_parser("wordlists", help="enumerate wordlist files on a remote host")
    wl_sub = wl.add_subparsers(dest="wlaction", required=True)
    wl_list = wl_sub.add_parser("list", help="list wordlist paths under known roots (remote)")
    wl_list.add_argument("--engagement", help="engagement dir (reads runner.json)")
    wl_list.add_argument("--runner", default="remote", help="remote-only (reads the host)")
    wl_list.add_argument("--json", action="store_true")
    wl.set_defaults(func=_cmd_wordlists)

    eng = sub.add_parser("engagement", help="read-only engagement v2 helpers (no network)")
    eng_sub = eng.add_subparsers(dest="eaction", required=True)
    eng_migrate = eng_sub.add_parser(
        "migrate", help="analyze a v1->v2 migration (dry-run only; writes nothing)"
    )
    eng_migrate.add_argument("--engagement", required=True, help="v1 engagement directory")
    eng_migrate.add_argument("--to", type=int, required=True, help="target schema version (2)")
    eng_migrate.add_argument(
        "--profile",
        choices=["bug-bounty", "local-lab", "private-pentest"],
        help="explicit v2 profile (required)",
    )
    eng_migrate.add_argument(
        "--dry-run", action="store_true", help="analysis only; the only supported mode"
    )
    eng_migrate.add_argument("--json", action="store_true")
    eng.set_defaults(func=_cmd_engagement)

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
