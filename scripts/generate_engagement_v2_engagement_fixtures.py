#!/usr/bin/env python3
"""Generate the deterministic engagement-v2 loader/migration fixture corpus.

The corpus is synthetic: it uses only example domains, hosts, CIDRs, and
endpoints and contains no real target or credential material. The v2 confirmed
engagement's authority digest is stamped from the same code-owned projection the
loader recomputes, so the committed fixture confirms and any drift is caught by
``--check``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Final

_PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from hackbot.engagement_v2.projection import (  # noqa: E402
    projection_digest,
    security_projection,
)

_DEFAULT_ROOT: Final = _PROJECT_ROOT / "tests" / "fixtures" / "engagement_v2_loader"

_V2_PROGRAM: Final[dict[str, object]] = {
    "schema_version": 2,
    "profile": "private-pentest",
    "program": {
        "name": "example.internal",
        "platform": "private",
        "source": "operator",
    },
    "testing_rules": {
        "max_requests_per_second": 10,
        "concurrency": 4,
        "timeout_seconds": 60,
        "output_cap_bytes": 2097152,
        "max_targets_per_action": 256,
        "authenticated_testing_allowed": True,
        "destructive_testing_allowed": False,
        "prohibited_tools": ["metasploit"],
    },
    "reporting": {"duplicate_policy": "first-wins"},
}
_V2_SCOPE: Final[dict[str, object]] = {
    "schema_version": 2,
    "in_scope": {
        "domains": ["app.corp.example"],
        "wildcard_domains": ["*.apps.corp.example"],
        "urls": ["https://app.corp.example/admin"],
        "hosts": ["dc01.corp.example", "fileserver"],
        "cidrs": ["10.20.0.0/16"],
        "network_endpoints": ["ldaps://dc01.corp.example:636", "smb://fileserver:445"],
    },
    "out_of_scope": {"hosts": ["printer01"], "cidrs": ["10.20.5.0/24"]},
}
_V2_RUNNER: Final[dict[str, object]] = {
    "schema_version": 2,
    "role": "execution-node",
    "node_identity": "lab.node",
    "ssh": {
        "host": "10.10.0.5",
        "port": 22,
        "user": "operator",
        "identity": "lab.key",
        "private_key_path": "/home/operator/.ssh/id_ed25519",
        "known_hosts_path": "/home/operator/.ssh/known_hosts",
        "host_key_sha256": "sha256:" + "1" * 64,
        "connection_timeout_seconds": 10,
        "options": {"batch_mode": True},
    },
    "helper": {
        "path": "/opt/hackbot/helper",
        "protocol_version": 1,
        "sha256": "sha256:" + "2" * 64,
    },
    "operating_system": "linux",
    "architecture": "x86_64",
    "permitted_privileges": ["network-raw"],
    "source_identity": {"mode": "direct-interface", "address": "10.10.0.5"},
    "egress_attestation": None,
    "privilege_signer_public_key_fingerprint": "sha256:" + "3" * 64,
}

_V1_PROGRAM_YAML: Final = (
    "schema_version: 1\n"
    "program:\n"
    "  name: example-internal\n"
    "  platform: private\n"
    "testing_rules:\n"
    "  max_requests_per_second: 10\n"
    "  concurrency: 4\n"
    "  automated_scanning_allowed: true\n"
    "  denial_of_service_allowed: false\n"
)
_V1_SCOPE_YAML: Final = (
    "schema_version: 1\n"
    "in_scope:\n"
    "  domains:\n"
    "    - app.corp.example\n"
    "out_of_scope:\n"
    "  domains:\n"
    "    - printer01.corp.example\n"
)
_V1_AUTHORIZATION: Final[dict[str, object]] = {
    "confirmed": True,
    "confirmation_timestamp": "2026-07-01T00:00:00Z",
    "confirmed_by": "operator",
    "note": "v1 engagement",
}


def _pretty_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _generated_bytes() -> dict[str, bytes]:
    digest = projection_digest(
        security_projection(program=_V2_PROGRAM, scope=_V2_SCOPE, runner=_V2_RUNNER)
    )
    v2_authorization = {
        "schema_version": 2,
        "confirmed": True,
        "confirmation_timestamp": "2026-07-01T00:00:00Z",
        "confirmed_by": "operator",
        "confirmed_authority_digest": digest,
        "note": "engagement reviewed",
    }
    return {
        "v2-confirmed/program.json": _pretty_json(_V2_PROGRAM),
        "v2-confirmed/scope.json": _pretty_json(_V2_SCOPE),
        "v2-confirmed/authorization.json": _pretty_json(v2_authorization),
        "v2-confirmed/runner.json": _pretty_json(_V2_RUNNER),
        "v1-source/program.yaml": _V1_PROGRAM_YAML.encode("utf-8"),
        "v1-source/scope.yaml": _V1_SCOPE_YAML.encode("utf-8"),
        "v1-source/authorization.json": _pretty_json(_V1_AUTHORIZATION),
    }


def generate(root: Path, *, check: bool) -> tuple[str, ...]:
    """Generate fixtures below *root*, or report drift without mutating it."""

    generated = _generated_bytes()
    differing: list[str] = []
    for relative_path, value in generated.items():
        destination = root / relative_path
        current = destination.read_bytes() if destination.is_file() else None
        if current == value:
            continue
        differing.append(relative_path)
        if not check:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(value)
    return tuple(sorted(differing))


def main(arguments: list[str]) -> int:
    if arguments not in ([], ["--check"]):
        raise SystemExit("usage: generate_engagement_v2_engagement_fixtures.py [--check]")
    differing = generate(_DEFAULT_ROOT, check=arguments == ["--check"])
    if arguments == ["--check"] and differing:
        print("\n".join(differing))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
