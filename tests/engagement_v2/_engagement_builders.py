"""Deterministic synthetic engagement v2 documents for P1 tests.

The documents use only example domains, hosts, CIDRs, and endpoints and contain
no real target or credential material. The confirmed-authority digest is stamped
from the same code-owned projection the loader recomputes, so a correctly built
engagement confirms and any mutation invalidates.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from hackbot.engagement_v2.projection import projection_digest, security_projection


def program_doc() -> dict[str, Any]:
    return {
        "schema_version": 2,
        "profile": "bug-bounty",
        "program": {
            "name": "example.program",
            "platform": "hackerone",
            "source": "operator",
        },
        "testing_rules": {
            "max_requests_per_second": 5,
            "concurrency": 2,
            "timeout_seconds": 30,
            "output_cap_bytes": 65536,
            "max_targets_per_action": 64,
            "automated_scanning_allowed": True,
            "destructive_testing_allowed": False,
            "prohibited_tools": ["nuclei"],
        },
        "reporting": {"duplicate_policy": "first-wins"},
    }


def scope_doc() -> dict[str, Any]:
    return {
        "schema_version": 2,
        "in_scope": {
            "domains": ["app.corp.example"],
            "wildcard_domains": ["*.apps.corp.example"],
            "urls": ["https://app.corp.example/admin"],
            "hosts": ["dc01.corp.example", "fileserver"],
            "cidrs": ["10.20.0.0/16"],
            "network_endpoints": ["ldaps://dc01.corp.example:636", "smb://fileserver:445"],
        },
        "out_of_scope": {
            "hosts": ["printer01"],
            "cidrs": ["10.20.5.0/24"],
        },
    }


def runner_doc() -> dict[str, Any]:
    return {
        "schema_version": 2,
        "role": "execution-node",
        "node_identity": "kali.node",
        "ssh": {
            "host": "10.10.0.5",
            "port": 22,
            "user": "operator",
            "identity": "kali.key",
            "private_key_path": "/home/operator/.ssh/id_ed25519",
            "known_hosts_path": "/home/operator/.ssh/known_hosts",
            "host_key_sha256": "sha256:" + "a" * 64,
            "connection_timeout_seconds": 10,
            "options": {"batch_mode": True},
        },
        "helper": {
            "path": "/opt/hackbot/helper",
            "protocol_version": 1,
            "sha256": "sha256:" + "b" * 64,
        },
        "operating_system": "linux",
        "architecture": "x86_64",
        "permitted_privileges": ["network-raw"],
        "source_identity": {"mode": "direct-interface", "address": "10.10.0.5"},
        "egress_attestation": None,
        "privilege_signer_public_key_fingerprint": "sha256:" + "c" * 64,
    }


def authorization_doc(digest: str) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "confirmed": True,
        "confirmation_timestamp": "2026-07-27T12:00:00Z",
        "confirmed_by": "operator-id",
        "confirmed_authority_digest": digest,
        "note": "Engagement reviewed",
    }


def stamp_digest(
    program: dict[str, Any], scope: dict[str, Any], runner: dict[str, Any] | None
) -> str:
    projection = security_projection(program=program, scope=scope, runner=runner)
    return projection_digest(projection)


def write_engagement(
    directory: Path,
    *,
    program: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None,
    runner: dict[str, Any] | None = None,
    include_runner: bool = False,
    confirmed: bool = True,
    digest_override: str | None = None,
) -> Path:
    program = copy.deepcopy(program if program is not None else program_doc())
    scope = copy.deepcopy(scope if scope is not None else scope_doc())
    runner_used: dict[str, Any] | None = None
    if include_runner:
        runner_used = copy.deepcopy(runner if runner is not None else runner_doc())

    digest = digest_override or stamp_digest(program, scope, runner_used)
    authorization = authorization_doc(digest)
    if not confirmed:
        authorization["confirmed"] = False

    directory.mkdir(parents=True, exist_ok=True)
    (directory / "program.json").write_text(json.dumps(program), encoding="utf-8")
    (directory / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    (directory / "authorization.json").write_text(json.dumps(authorization), encoding="utf-8")
    if runner_used is not None:
        (directory / "runner.json").write_text(json.dumps(runner_used), encoding="utf-8")
    return directory
