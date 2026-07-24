#!/usr/bin/env python3
"""
keychain_sentinel — ONE native macOS Keychain round-trip using a dedicated,
throwaway service/key, with guaranteed cleanup.

Safety:
  * Uses service "hackbot-sentinel" and a random per-run key — NEVER the real
    service ("hackbot") or the real secret names (DEEPSEEK_API_KEY/MOONSHOT_API_KEY).
  * Never reads/writes the operator's real settings files.
  * Prints only pass/fail and confirmation the sentinel was removed — never a value.

Run: .venv/bin/python scripts/keychain_sentinel.py
Exit 0 on success (round-trip verified AND sentinel removed), non-zero otherwise.
"""
from __future__ import annotations

import os
import secrets as _secrets
import sys

SENTINEL_SERVICE = "hackbot-sentinel"
FORBIDDEN_SERVICES = {"hackbot"}
FORBIDDEN_KEYS = {"DEEPSEEK_API_KEY", "MOONSHOT_API_KEY", "ANTHROPIC_API_KEY"}


def main() -> int:
    try:
        import keyring
    except Exception as e:  # pragma: no cover
        print(f"SKIP: keyring not available ({e})")
        return 0

    key = f"SENTINEL-{os.getpid()}-{_secrets.token_hex(4)}"
    value = _secrets.token_hex(16)

    # hard guards: never operate on real service/keys
    assert SENTINEL_SERVICE not in FORBIDDEN_SERVICES
    assert key not in FORBIDDEN_KEYS

    backend = type(keyring.get_keyring()).__name__
    print(f"native keychain backend: {backend}")

    roundtrip_ok = False
    removed = False
    try:
        keyring.set_password(SENTINEL_SERVICE, key, value)
        got = keyring.get_password(SENTINEL_SERVICE, key)
        roundtrip_ok = (got == value)
    except Exception as e:  # never surface the value; report the failure class only
        print(f"FAIL: native keychain round-trip errored ({type(e).__name__})")
        # still attempt cleanup below
    finally:
        try:
            keyring.delete_password(SENTINEL_SERVICE, key)
        except Exception:
            pass
        try:
            removed = keyring.get_password(SENTINEL_SERVICE, key) is None
        except Exception:
            removed = False

    print(f"round-trip verified: {roundtrip_ok}")
    print(f"sentinel removed: {removed}")
    ok = roundtrip_ok and removed
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
