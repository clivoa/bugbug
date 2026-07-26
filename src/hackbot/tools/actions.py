"""Immutable, code-owned real action definitions.

CLI input can never register or mutate an action. The first member,
``net.http-get``, is a low-impact passive fetch backed by ``curl`` (resolved
from a small absolute-path allowlist); ``network_access=True`` forces a scope
check, so it only runs against in-scope targets.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from hackbot.risk.models import ActionDefinition, RiskLevel
from hackbot.risk.registry import ActionRegistry

_WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"

_CURL_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/curl",
    "/opt/homebrew/bin/curl",
    "/usr/local/bin/curl",
)
_DIG_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/dig",
    "/opt/homebrew/bin/dig",
    "/usr/local/bin/dig",
)
_OPENSSL_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/openssl",
    "/opt/homebrew/bin/openssl",
    "/usr/local/bin/openssl",
)
_NMAP_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/nmap",
    "/opt/homebrew/bin/nmap",
    "/usr/local/bin/nmap",
)
_FFUF_CANDIDATES: tuple[str, ...] = (
    "/opt/homebrew/bin/ffuf",
    "/usr/local/bin/ffuf",
    "/usr/bin/ffuf",
)


def resolve_executable(candidates: Sequence[str]) -> str | None:
    for candidate in candidates:
        if os.path.isabs(candidate) and os.path.isfile(candidate):
            return candidate
    return None


def curl_path() -> str | None:
    return resolve_executable(_CURL_CANDIDATES)


def dig_path() -> str | None:
    return resolve_executable(_DIG_CANDIDATES)


def openssl_path() -> str | None:
    return resolve_executable(_OPENSSL_CANDIDATES)


def nmap_path() -> str | None:
    return resolve_executable(_NMAP_CANDIDATES)


def ffuf_path() -> str | None:
    return resolve_executable(_FFUF_CANDIDATES)


def web_content_wordlist() -> str:
    return str(_WORDLIST_DIR / "web-content.txt")


def _build_definitions() -> list[ActionDefinition]:
    definitions: list[ActionDefinition] = []
    curl = curl_path()
    if curl is not None:
        definitions.append(
            ActionDefinition(
                "net.http-get",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=curl,
                argv_template=(curl, "-sS", "--max-time", "10", "{target}"),
            )
        )
        definitions.append(
            ActionDefinition(
                "net.http-post",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                state_changing=True,
                executable=curl,
                argv_template=(curl, "-sS", "-X", "POST", "--max-time", "10", "{target}"),
            )
        )
        definitions.append(
            ActionDefinition(
                "net.http-head",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=curl,
                argv_template=(curl, "-sS", "-I", "--max-time", "10", "{target}"),
            )
        )
        definitions.append(
            ActionDefinition(
                "net.http-options",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=curl,
                argv_template=(curl, "-sS", "-i", "-X", "OPTIONS", "--max-time", "10", "{target}"),
            )
        )
    dig = dig_path()
    if dig is not None:
        definitions.append(
            ActionDefinition(
                "dns.lookup",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=dig,
                argv_template=(dig, "+short", "{target}"),
            )
        )
        for action_id, record in (("dns.txt", "TXT"), ("dns.mx", "MX"), ("dns.ns", "NS")):
            definitions.append(
                ActionDefinition(
                    action_id,
                    RiskLevel.L0,
                    network_access=True,
                    uses_external_tool=True,
                    executable=dig,
                    argv_template=(dig, "+short", "{target}", record),
                )
            )
    openssl = openssl_path()
    if openssl is not None:
        definitions.append(
            ActionDefinition(
                "tls.cert",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                executable=openssl,
                argv_template=(openssl, "s_client", "-connect", "{target}"),
            )
        )
    nmap = nmap_path()
    if nmap is not None:
        definitions.append(
            ActionDefinition(
                "net.port-scan",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                high_volume=True,
                executable=nmap,
                argv_template=(nmap, "-Pn", "-T3", "--top-ports", "100", "{target}"),
            )
        )
    ffuf = ffuf_path()
    if ffuf is not None and Path(web_content_wordlist()).is_file():
        definitions.append(
            ActionDefinition(
                "web.dir-enum",
                RiskLevel.L0,
                network_access=True,
                uses_external_tool=True,
                high_volume=True,
                executable=ffuf,
                argv_template=(ffuf, "-s", "-u", "{target}", "-w", web_content_wordlist()),
            )
        )
    # Remote-only ("arsenal") action: a bare tool name registers unconditionally
    # and runs only via the SSH RemoteRunner (the local runner rejects a
    # non-absolute executable). The wordlist path is on the remote host.
    definitions.append(
        ActionDefinition(
            "web.dir-enum-gobuster",
            RiskLevel.L0,
            network_access=True,
            uses_external_tool=True,
            high_volume=True,
            executable="gobuster",
            argv_template=(
                "gobuster",
                "dir",
                "-u",
                "{target}",
                "-w",
                "/usr/share/wordlists/dirb/common.txt",
                "-q",
            ),
        )
    )
    return definitions


_DEFINITIONS = _build_definitions()
REAL_ACTIONS = ActionRegistry(_DEFINITIONS)
REGISTERED_ACTION_IDS: tuple[str, ...] = tuple(d.action_id for d in _DEFINITIONS)

__all__ = [
    "REAL_ACTIONS",
    "REGISTERED_ACTION_IDS",
    "curl_path",
    "dig_path",
    "ffuf_path",
    "nmap_path",
    "openssl_path",
    "resolve_executable",
    "web_content_wordlist",
]
