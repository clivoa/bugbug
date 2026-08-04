#!/usr/bin/env python3
"""Generate deterministic synthetic P5b isolated-lab fixtures."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_OUTPUT = _ROOT / "tests/fixtures/engagement_v2_l3/isolated-lab.json"


def fixture_document() -> dict[str, object]:
    """Return synthetic AD/Kerberos/LDAP metadata with no authentication material."""

    return {
        "schema_version": 1,
        "synthetic": True,
        "isolated_disposable_lab_only": True,
        "ci_live_tools_allowed": False,
        "realm": "EXAMPLE.TEST",
        "hosts": [
            {
                "name": "dc01.example.test",
                "address": "192.0.2.10",
                "roles": ["directory", "dns", "kerberos", "ldap"],
                "ldap_endpoint": "ldaps://dc01.example.test:636",
            },
            {
                "name": "files01.example.test",
                "address": "192.0.2.20",
                "roles": ["file-service"],
                "ldap_endpoint": "ldaps://dc01.example.test:636",
            },
        ],
        "directory": {
            "base_dn": "DC=example,DC=test",
            "principals": ["alice@example.test", "svc-web@example.test"],
            "spns": ["HTTP/web01.example.test", "CIFS/files01.example.test"],
            "adcs_templates": ["ExampleUser", "ExampleWebServer"],
        },
        "kerberos": {
            "encryption_types": ["aes256-cts-hmac-sha1-96"],
            "ticket_metadata": [
                {
                    "principal_name": "svc-web@example.test",
                    "service_name": "HTTP/web01.example.test",
                    "renewable": False,
                }
            ],
        },
    }


def render_fixture() -> str:
    return json.dumps(fixture_document(), indent=2, sort_keys=True) + "\n"


def _publish(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    expected = render_fixture()
    if args.check:
        try:
            actual = args.output.read_text(encoding="utf-8")
        except OSError:
            print(f"fixture missing: {args.output}", file=sys.stderr)
            return 1
        if actual != expected:
            print(f"fixture drift: {args.output}", file=sys.stderr)
            return 1
        return 0
    _publish(args.output, expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
