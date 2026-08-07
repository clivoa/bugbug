"""hunt commands — recon, surface, hypothesis.

These commands form the core bug bounty workflow:
  recon   — passive and active reconnaissance
  surface — attack surface mapping and classification
  hypothesis — generate and rank testable vulnerability hypotheses

All commands are read-only analysis of local data or passive external queries.
Active probing requires explicit tool invocation through the risk gate.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Shared data types
# ---------------------------------------------------------------------------


@dataclass
class ReconTarget:
    """A discovered asset during reconnaissance."""

    value: str
    kind: str  # domain, ip, url, repo, contract, mobile
    source: str
    confidence: str  # high, medium, low
    notes: str = ""


@dataclass
class SurfaceElement:
    """One element of the attack surface."""

    asset: str
    category: str  # web_app, api, auth, file_handling, admin, etc.
    technology: str = ""
    endpoints: list[str] = field(default_factory=list)
    auth_required: bool = False
    third_party: bool = False
    notes: str = ""


@dataclass
class Hypothesis:
    """A testable vulnerability hypothesis."""

    id: str
    title: str
    asset: str
    observation: str
    assumption: str
    vulnerability_class: str
    potential_impact: str
    evidence_required: str
    safe_initial_test: str
    intrusive_test: str = ""
    risk_level: str = "L0"
    approval_required: bool = False
    stop_conditions: list[str] = field(default_factory=list)
    status: str = "candidate"


# ---------------------------------------------------------------------------
# recon
# ---------------------------------------------------------------------------


def cmd_recon(
    engagement_dir: str,
    *,
    mode: str = "passive",
    as_json: bool = False,
) -> int:
    """Run reconnaissance against the engagement's scoped assets.

    Args:
        engagement_dir: Path to the engagement directory.
        mode: 'passive' (L0), 'active-low' (L1), or 'plan' (show what would run).
        as_json: Output JSON instead of human-readable text.
    """
    import sys
    from pathlib import Path

    eng_path = Path(engagement_dir)
    if not eng_path.is_dir():
        print(f"error: engagement directory not found: {engagement_dir}", file=sys.stderr)
        return 2

    # Load scope from the engagement directory
    scope_yaml = eng_path / "scope.yaml"
    program_yaml = eng_path / "program.yaml"
    in_scope: list[str] = []
    out_scope: list[str] = []

    if scope_yaml.is_file():
        try:
            from hackbot.programs import loader

            doc, scope_obj = loader.load_program_file(
                str(program_yaml) if program_yaml.is_file() else str(scope_yaml), name="recon"
            )
            in_scope = list(scope_obj.in_scope) if hasattr(scope_obj, "in_scope") else []
            out_scope = list(scope_obj.out_of_scope) if hasattr(scope_obj, "out_of_scope") else []
        except Exception:
            # Fallback: read scope directly
            try:
                import yaml

                with open(scope_yaml, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                if isinstance(data, dict):
                    in_scope = data.get("in_scope", [])
                    out_scope = data.get("out_of_scope", [])
            except Exception:
                pass

    if mode == "plan":
        plan = _build_recon_plan(in_scope, out_scope)
        if as_json:
            print(json.dumps(plan, indent=2))
        else:
            _print_recon_plan(plan)
        return 0

    if mode not in ("passive", "active-low"):
        print(f"error: unknown recon mode: {mode}", file=__import__("sys").stderr)
        return 2

    # For passive/active-low, provide a structured plan that models can use
    plan = _build_recon_plan(in_scope, out_scope)
    if as_json:
        print(json.dumps({"mode": mode, "plan": plan}, indent=2))
    else:
        print(f"Recon mode: {mode}")
        print(f"In-scope rules: {len(in_scope)}")
        print()
        _print_recon_plan(plan)
        print()
        print("Run individual actions through: hackbot tool run <action-id> --engagement <path>")
    return 0


def _build_recon_plan(in_scope: Sequence[str], out_scope: Sequence[str]) -> dict[str, Any]:
    """Build a structured recon plan from scope rules."""
    domains = [r for r in in_scope if not r.startswith("re:") and "/" not in r and ":" not in r]
    urls = [r for r in in_scope if "://" in r]
    wildcards = [r for r in in_scope if r.startswith("*.")]

    steps: list[dict[str, Any]] = []

    if domains or wildcards:
        steps.append(
            {
                "phase": "certificate-transparency",
                "action": "Passive — crt.sh, CertSpotter",
                "risk": "L0",
                "targets": list(domains) + list(wildcards),
                "tool": None,  # HTTP-based, no local tool required
            }
        )
        steps.append(
            {
                "phase": "dns-enumeration",
                "action": "dns.lookup",
                "risk": "L1",
                "targets": list(domains) + list(wildcards),
                "tool": "dig",
                "notes": "Query A, AAAA, MX, NS, TXT, CNAME records",
            }
        )
        steps.append(
            {
                "phase": "http-probe",
                "action": "net.http-get / net.http-head",
                "risk": "L1",
                "targets": list(domains) + list(wildcards),
                "tool": "curl",
                "notes": "Probe ports 80/443, collect headers and status codes",
            }
        )

    if urls:
        steps.append(
            {
                "phase": "endpoint-discovery",
                "action": "net.http-get",
                "risk": "L1",
                "targets": list(urls),
                "tool": "curl",
                "notes": "Fetch known URLs, extract links, check for API docs, robots.txt",
            }
        )

    steps.append(
        {
            "phase": "passive-analysis",
            "action": "Local analysis only — no network",
            "risk": "L0",
            "targets": [],
            "tool": None,
            "notes": (
                "Wayback Machine CDX, GitHub code search, Shodan host lookup, "
                "WHOIS, ASN metadata, Google dorking. All passive — no direct "
                "target interaction."
            ),
        }
    )

    return {
        "engagement_scope": {
            "in_scope": list(in_scope),
            "out_of_scope": list(out_scope),
        },
        "recon_steps": steps,
    }


def _print_recon_plan(plan: dict[str, Any]) -> None:
    """Pretty-print a recon plan."""
    print("── Recon Plan ──")
    for step in plan.get("recon_steps", []):
        risk = step.get("risk", "?")
        phase = step.get("phase", "?")
        tool = step.get("tool") or "no tool"
        targets = step.get("targets", [])
        notes = step.get("notes", "")
        print(f"  [{risk}] {phase} ({tool})")
        if targets:
            print(f"        targets: {', '.join(targets[:5])}")
            if len(targets) > 5:
                print(f"                 ... and {len(targets) - 5} more")
        if notes:
            print(f"        {notes}")
        print()


# ---------------------------------------------------------------------------
# surface
# ---------------------------------------------------------------------------


def cmd_surface(
    engagement_dir: str,
    *,
    as_json: bool = False,
) -> int:
    """Map and classify the attack surface from recon data.

    Reads recon output from the engagement directory and classifies discovered
    assets by category, technology, and authentication requirements.
    """
    import sys

    eng_path = Path(engagement_dir)
    if not eng_path.is_dir():
        print(f"error: engagement directory not found: {engagement_dir}", file=sys.stderr)
        return 2

    recon_dir = eng_path / "recon"
    if not recon_dir.is_dir():
        print(
            f"No recon data found. Run recon first:\n  hackbot recon --engagement {engagement_dir}",
            file=sys.stderr,
        )
        return 2

    surfaces = _classify_surfaces(recon_dir)

    if as_json:
        print(
            json.dumps(
                {"engagement": str(eng_path), "surfaces": [s.__dict__ for s in surfaces]},
                indent=2,
            )
        )
    else:
        _print_surfaces(surfaces)
    return 0


def _classify_surfaces(recon_dir: Path) -> list[SurfaceElement]:
    """Read recon output files and classify the attack surface."""
    surfaces: list[SurfaceElement] = []

    # Try to read live hosts
    live_hosts_file = recon_dir / "live-hosts.txt"
    if live_hosts_file.is_file():
        hosts = live_hosts_file.read_text().splitlines()
        for host in hosts:
            host = host.strip()
            if not host or host.startswith("#"):
                continue
            surfaces.append(
                SurfaceElement(
                    asset=host,
                    category="web_app",
                    notes="Live HTTP host from recon",
                )
            )

    # Try to read subdomains
    subdomains_file = recon_dir / "all-subdomains.txt"
    if subdomains_file.is_file():
        for line in subdomains_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            surfaces.append(
                SurfaceElement(
                    asset=line,
                    category="domain",
                    notes="Discovered subdomain",
                )
            )

    # Try to read URLs
    urls_file = recon_dir / "urls-archived.txt"
    if urls_file.is_file():
        for line in urls_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            surfaces.append(
                SurfaceElement(
                    asset=line,
                    category="url",
                    notes="Archived/discovered URL",
                )
            )

    # Try to read third-party services
    third_party_file = recon_dir / "third-party-services.txt"
    if third_party_file.is_file():
        for line in third_party_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            surfaces.append(
                SurfaceElement(
                    asset=line,
                    category="third_party",
                    third_party=True,
                    notes="Third-party service dependency",
                )
            )

    return surfaces


def _print_surfaces(surfaces: list[SurfaceElement]) -> None:
    """Pretty-print the attack surface map."""
    if not surfaces:
        print("(empty — no recon data classified)")
        return

    by_category: dict[str, list[SurfaceElement]] = {}
    for s in surfaces:
        by_category.setdefault(s.category, []).append(s)

    print("── Attack Surface Map ──")
    for category, items in sorted(by_category.items()):
        print(f"\n  [{category}] ({len(items)} elements)")
        for item in items[:10]:
            flags = ""
            if item.third_party:
                flags += " [third-party]"
            if item.auth_required:
                flags += " [auth]"
            print(f"    - {item.asset}{flags}")
        if len(items) > 10:
            print(f"    ... and {len(items) - 10} more")
    print()


# ---------------------------------------------------------------------------
# hypothesis
# ---------------------------------------------------------------------------


def cmd_hypothesis(
    engagement_dir: str,
    *,
    action: str = "generate",
    vulnerability_class: str | None = None,
    as_json: bool = False,
) -> int:
    """Generate and manage vulnerability hypotheses.

    Args:
        engagement_dir: Path to the engagement directory.
        action: 'generate' (from surface map) or 'list' (existing hypotheses).
        vulnerability_class: Filter hypotheses by class (e.g. idor, oauth, xss).
        as_json: Output JSON.
    """
    import sys

    eng_path = Path(engagement_dir)
    if not eng_path.is_dir():
        print(f"error: engagement directory not found: {engagement_dir}", file=sys.stderr)
        return 2

    if action == "list":
        hypotheses_dir = eng_path / "hypotheses"
        if not hypotheses_dir.is_dir():
            print("(no hypotheses yet — run 'hackbot hypothesis generate')")
            return 0
        hypotheses = _load_hypotheses(hypotheses_dir, vulnerability_class)
        if as_json:
            print(
                json.dumps(
                    {"engagement": str(eng_path), "hypotheses": [h.__dict__ for h in hypotheses]},
                    indent=2,
                )
            )
        else:
            _print_hypotheses(hypotheses)
        return 0

    if action == "generate":
        # Read surface map to generate hypotheses
        recon_dir = eng_path / "recon"
        surfaces = _classify_surfaces(recon_dir) if recon_dir.is_dir() else []

        hypotheses = _generate_hypotheses(surfaces, vulnerability_class)

        # Save hypotheses
        hyp_dir = eng_path / "hypotheses"
        hyp_dir.mkdir(parents=True, exist_ok=True)
        _save_hypotheses(hyp_dir, hypotheses)

        if as_json:
            print(
                json.dumps(
                    {"engagement": str(eng_path), "hypotheses": [h.__dict__ for h in hypotheses]},
                    indent=2,
                )
            )
        else:
            print(f"Generated {len(hypotheses)} hypotheses in {hyp_dir}")
            _print_hypotheses(hypotheses)
        return 0

    print(f"error: unknown hypothesis action: {action}", file=sys.stderr)
    return 2


def _generate_hypotheses(
    surfaces: list[SurfaceElement],
    vuln_class: str | None = None,
) -> list[Hypothesis]:
    """Generate hypotheses from surface elements using vulnerability-class templates."""
    templates = _hypothesis_templates()
    hypotheses: list[Hypothesis] = []

    for i, surface in enumerate(surfaces):
        applicable = [t for t in templates if vuln_class is None or t["class"] == vuln_class]
        for tmpl in applicable[:3]:  # max 3 hypotheses per surface element
            hid = f"H-{i:04d}-{tmpl['class']}"
            hypotheses.append(
                Hypothesis(
                    id=hid,
                    title=f"{tmpl['class'].upper()} on {surface.asset}",
                    asset=surface.asset,
                    observation=f"Discovered {surface.category} asset: {surface.asset}",
                    assumption=tmpl["assumption"],
                    vulnerability_class=tmpl["class"],
                    potential_impact=tmpl["potential_impact"],
                    evidence_required=tmpl["evidence_required"],
                    safe_initial_test=tmpl["safe_test"],
                    intrusive_test=tmpl.get("intrusive_test", ""),
                    risk_level=tmpl.get("risk_level", "L0"),
                    approval_required=tmpl.get("risk_level", "L0") in ("L2", "L3"),
                    stop_conditions=tmpl.get("stop_conditions", []),
                    status="candidate",
                )
            )
    return hypotheses


def _hypothesis_templates() -> list[dict[str, Any]]:
    """Return vulnerability class templates for hypothesis generation."""
    return [
        {
            "class": "idor",
            "assumption": "Object references may be predictable and lack authorization checks",
            "potential_impact": "Unauthorized access to other users' data or functionality",
            "evidence_required": "Two owned accounts showing different object IDs; proof of cross-account access",
            "safe_test": "Compare object IDs across two owned test accounts; note if sequential or predictable",
            "intrusive_test": "Access resource B from account A using only the object ID (requires second account)",
            "risk_level": "L2",
            "stop_conditions": [
                "Confirm access to one non-sensitive resource from another account",
                "Stop immediately — do not enumerate",
            ],
        },
        {
            "class": "oauth",
            "assumption": "OAuth flow may have redirect_uri validation weakness or missing state parameter",
            "potential_impact": "Account takeover via authorization code theft",
            "evidence_required": "Proof of redirect_uri bypass or CSRF via missing/predictable state",
            "safe_test": "Inspect OAuth flow: redirect_uri parameter validation, state parameter presence and randomness",
            "intrusive_test": "Test redirect_uri with a controlled domain (requires explicit approval and owned callback server)",
            "risk_level": "L2",
            "stop_conditions": [
                "Confirm redirect_uri weakness with a single test callback",
                "Stop — do not exploit against other users",
            ],
        },
        {
            "class": "xss",
            "assumption": "User input may be reflected or stored without proper encoding",
            "potential_impact": "Client-side code execution in victim's browser",
            "evidence_required": "alert(document.domain) or equivalent proof of JS execution",
            "safe_test": 'Inject harmless HTML/JS markers: <b>test</b>, "autofocus onfocus=alert(document.domain) //',
            "intrusive_test": "Test stored XSS with a self-XSS payload in your own data (requires account)",
            "risk_level": "L2",
            "stop_conditions": [
                "Confirm JS execution with alert(document.domain)",
                "Stop — never exploit against other users or exfiltrate cookies",
            ],
        },
        {
            "class": "ssrf",
            "assumption": "Webhook/URL/fetch functionality may allow requests to internal services",
            "potential_impact": "Access to internal services, cloud metadata, or internal APIs",
            "evidence_required": "HTTP/DNS callback proving server-side request to controlled infrastructure",
            "safe_test": "Submit a URL pointing to a callback service you control (Burp Collaborator, interact.sh)",
            "intrusive_test": "Probe 169.254.169.254 (AWS) or metadata.google.internal (GCP) — only if callback confirms SSRF",
            "risk_level": "L2",
            "stop_conditions": [
                "Confirm SSRF with a single callback",
                "Never use SSRF to scan internal network or pivot to other hosts",
            ],
        },
        {
            "class": "sql-injection",
            "assumption": "SQL queries may be constructed with unsanitized user input",
            "potential_impact": "Database access, data exfiltration, potential RCE",
            "evidence_required": "Error message, time delay, or boolean indicator proving SQL interpretation",
            "safe_test": "Submit single-quote, double-quote, backslash; observe error messages or response differences",
            "intrusive_test": "Time-based: sleep(5) equivalent for the database engine; stop after confirming delay",
            "risk_level": "L2",
            "stop_conditions": [
                "Confirm SQL injection with a time delay or single error message",
                "Never use UNION SELECT to extract data without additional explicit approval",
                "Never run sqlmap --dump",
            ],
        },
        {
            "class": "auth-bypass",
            "assumption": "Authentication checks may be inconsistently applied across endpoints",
            "potential_impact": "Unauthorized access to protected functionality or data",
            "evidence_required": "Access to protected endpoint/resource without valid authentication",
            "safe_test": "Map all endpoints from JS/sitemap; attempt access without auth cookie; check response codes",
            "risk_level": "L1",
            "stop_conditions": [
                "Confirm access to a single protected endpoint without auth",
                "Stop — do not enumerate all protected resources",
            ],
        },
        {
            "class": "business-logic",
            "assumption": "Multi-step business flows may have inconsistent state validation",
            "potential_impact": "Financial loss, inventory manipulation, privilege escalation",
            "evidence_required": "Proof of workflow step bypass, race condition, or inconsistent validation",
            "safe_test": "Map the business flow: document each step, parameters, and state transitions",
            "intrusive_test": "Test race condition: submit same coupon/redeem request twice concurrently (minimal value)",
            "risk_level": "L2",
            "stop_conditions": [
                "Confirm logic flaw with minimal-value transaction",
                "Stop — do not exploit for financial gain",
            ],
        },
        {
            "class": "jwt-attack",
            "assumption": "JWT implementation may have algorithm confusion or weak signing",
            "potential_impact": "Token forgery, privilege escalation, account takeover",
            "evidence_required": "Valid JWT from application; proof of modified JWT accepted by server",
            "safe_test": "Decode and inspect JWT: algorithm, claims, signature; test alg:none acceptance",
            "intrusive_test": "Sign modified JWT with recovered/forged key",
            "risk_level": "L2",
            "stop_conditions": [
                "Confirm algorithm confusion with a self-signed test token",
                "Stop — do not access other users' data",
            ],
        },
        {
            "class": "cors-misconfig",
            "assumption": "CORS configuration may be overly permissive",
            "potential_impact": "Cross-origin data theft, CSRF protection bypass",
            "evidence_required": "Access-Control-Allow-Origin reflecting arbitrary Origin header",
            "safe_test": "Send request with Origin: https://evil.com; check ACAO header in response",
            "risk_level": "L1",
            "stop_conditions": [
                "Confirm ACAO reflects arbitrary origin",
                "Stop — do not craft a working exploit page unless needed for proof",
            ],
        },
        {
            "class": "rate-limit",
            "assumption": "Rate limiting may be missing on sensitive endpoints",
            "potential_impact": "Brute-force attacks, resource exhaustion, enumeration",
            "evidence_required": "Proof that a sensitive endpoint accepts rapid repeated requests",
            "safe_test": "Send 5-10 rapid requests to login/2FA/password-reset endpoint; observe if rate-limited",
            "risk_level": "L1",
            "stop_conditions": [
                "Confirm missing rate limit with ≤10 requests",
                "Stop — do not perform actual brute-force attack",
            ],
        },
    ]


def _save_hypotheses(hyp_dir: Path, hypotheses: list[Hypothesis]) -> None:
    """Save hypotheses as JSON files in the engagement hypotheses directory."""
    for h in hypotheses:
        filename = f"{h.id}.json"
        with open(hyp_dir / filename, "w", encoding="utf-8") as fh:
            json.dump(h.__dict__, fh, indent=2)


def _load_hypotheses(hyp_dir: Path, vuln_class: str | None = None) -> list[Hypothesis]:
    """Load hypotheses from the engagement hypotheses directory."""
    hypotheses: list[Hypothesis] = []
    for fpath in sorted(hyp_dir.glob("H-*.json")):
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            if vuln_class and data.get("vulnerability_class") != vuln_class:
                continue
            hypotheses.append(Hypothesis(**data))
        except Exception:
            continue
    return hypotheses


def _print_hypotheses(hypotheses: list[Hypothesis]) -> None:
    """Pretty-print hypotheses."""
    if not hypotheses:
        print("(no hypotheses)")
        return

    # Group by vulnerability class
    by_class: dict[str, list[Hypothesis]] = {}
    for h in hypotheses:
        by_class.setdefault(h.vulnerability_class, []).append(h)

    print("── Hypotheses ──")
    for vclass, items in sorted(by_class.items()):
        print(f"\n  [{vclass}] ({len(items)} hypotheses)")
        for h in items[:5]:
            status_mark = {
                "candidate": "○",
                "testing": "◉",
                "confirmed": "✓",
                "rejected": "✗",
                "reported": "📋",
            }.get(h.status, "?")
            approval = " [APPROVAL REQUIRED]" if h.approval_required else ""
            print(f"    {status_mark} {h.id}: {h.title}{approval}")
            print(f"       assumption: {h.assumption[:100]}")
        if len(items) > 5:
            print(f"    ... and {len(items) - 5} more")
    print()


# ---------------------------------------------------------------------------
# profile
# ---------------------------------------------------------------------------

_AVAILABLE_PROFILES: dict[str, dict[str, Any]] = {
    "web2": {
        "description": "Standard web application — Burp, crawling, auth, business logic",
        "skill_packs": ["core", "recon", "web", "api", "auth", "reporting"],
        "preferred_tools": ["curl", "ffuf", "nuclei"],
        "default_rate": 1,
    },
    "api": {
        "description": "API-focused — schema discovery, authorization, object-level access",
        "skill_packs": ["core", "recon", "api", "auth", "reporting"],
        "preferred_tools": ["curl", "ffuf"],
        "default_rate": 5,
    },
    "mobile": {
        "description": "Mobile application — static analysis, API backends, deep links",
        "skill_packs": ["core", "mobile", "api", "auth", "reporting"],
        "preferred_tools": ["apktool", "jadx"],
        "default_rate": 1,
    },
    "cloud": {
        "description": "Cloud/DevOps — storage, containers, CI/CD, infrastructure-as-code",
        "skill_packs": ["core", "cloud", "source-review", "reporting"],
        "preferred_tools": ["curl"],
        "default_rate": 1,
    },
    "source-code": {
        "description": "Source code review — SAST, secrets, dependency scanning",
        "skill_packs": ["core", "source-review", "reporting"],
        "preferred_tools": ["semgrep", "gitleaks"],
        "default_rate": 0,  # no network for pure source review
    },
    "ai-llm": {
        "description": "AI/LLM application — prompt injection, tool use, RAG, data leakage",
        "skill_packs": ["core", "ai-security", "api", "reporting"],
        "preferred_tools": ["curl"],
        "default_rate": 1,
    },
    "web3": {
        "description": "Web3/smart contracts — Slither/Aderyn, Foundry, fork-based PoCs",
        "skill_packs": ["core", "web3", "source-review", "reporting"],
        "preferred_tools": [],
        "default_rate": 0,
    },
    "hybrid": {
        "description": "Multi-surface — combines web, API, mobile, and cloud profiles",
        "skill_packs": ["core", "recon", "web", "api", "auth", "cloud", "mobile", "reporting"],
        "preferred_tools": ["curl", "ffuf"],
        "default_rate": 1,
    },
}


def cmd_profile_show(engagement_dir: str, *, as_json: bool = False) -> int:
    """Show the active profile for an engagement."""
    import sys

    eng_path = Path(engagement_dir)
    if not eng_path.is_dir():
        print(f"error: engagement directory not found: {engagement_dir}", file=sys.stderr)
        return 2

    program_yaml = eng_path / "program.yaml"
    profile = "web2"  # default
    if program_yaml.is_file():
        try:
            import yaml

            with open(program_yaml, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            profile = data.get("program", {}).get("profile", "web2")
        except Exception:
            pass

    info = _AVAILABLE_PROFILES.get(profile, _AVAILABLE_PROFILES["web2"])
    if as_json:
        print(json.dumps({"engagement": str(eng_path), "profile": profile, **info}, indent=2))
    else:
        print(f"Engagement: {eng_path}")
        print(f"Profile: {profile}")
        print(f"Description: {info['description']}")
        print(f"Skill packs: {', '.join(info['skill_packs'])}")
        print(f"Default rate: {info['default_rate']} req/s")
    return 0


def cmd_profile_list(*, as_json: bool = False) -> int:
    """List all available profiles."""
    if as_json:
        print(json.dumps(_AVAILABLE_PROFILES, indent=2))
    else:
        print("── Available Profiles ──")
        for name, info in sorted(_AVAILABLE_PROFILES.items()):
            print(f"\n  {name}")
            print(f"    {info['description']}")
            print(f"    Skills: {', '.join(info['skill_packs'])}")
            print(f"    Default rate: {info['default_rate']} req/s")
    return 0
