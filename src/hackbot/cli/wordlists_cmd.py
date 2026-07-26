"""Remote-only enumeration of wordlist files under a fixed code-owned allowlist.

Discovery only: paths are display-only. When an operator later uses one as a
``{wordlist}``, the risk model re-validates it (absolute, no control chars) and
the gate runs as usual. Nothing here selects, ranks, or runs a wordlist.
"""

from __future__ import annotations

import json
import os
import sys

from hackbot.tools.remote import RemoteError, RemoteRunner, load_remote_config


def cmd_list(*, engagement: str | None, runner: str = "remote", as_json: bool = False) -> int:
    if runner != "remote":
        print(f"error: unknown runner: {runner} (wordlists is remote-only)", file=sys.stderr)
        return 2
    if not engagement:
        print("error: --runner remote requires --engagement", file=sys.stderr)
        return 2
    try:
        config = load_remote_config(os.path.join(engagement, "runner.json"))
        entries = RemoteRunner(config).discover_wordlists()
    except RemoteError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    # Sort entries by path for consistent output
    sorted_entries = sorted(entries, key=lambda e: e.path)
    if as_json:
        print(
            json.dumps(
                {
                    "wordlists": [
                        {"path": e.path, "size_bytes": e.size_bytes} for e in sorted_entries
                    ]
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        if not sorted_entries:
            print("no wordlists found under known roots")
        else:
            print(f"{len(sorted_entries)} wordlist(s):")
            for e in sorted_entries:
                print(f"  {e.size_bytes:>12}  {e.path}")
    return 0
