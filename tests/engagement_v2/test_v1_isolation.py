"""Guards which keep the P0 engagement-v2 contracts out of the v1 runtime."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

V1_ROOTS = (
    Path("src/hackbot/cli"),
    Path("src/hackbot/programs"),
    Path("src/hackbot/risk"),
    Path("src/hackbot/scope"),
    Path("src/hackbot/tools"),
)
_SOURCE_ROOT = Path("src")
_V2_MODULE = "hackbot.engagement_v2"


def _importing_package(path: Path) -> tuple[str, ...]:
    return path.relative_to(_SOURCE_ROOT).with_suffix("").parts[:-1]


def _imported_modules(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    package = _importing_package(path)
    imported: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend((node.lineno, alias.name) for alias in node.names)
            continue
        if not isinstance(node, ast.ImportFrom):
            continue

        base = package
        if node.level:
            base = package[: len(package) - (node.level - 1)]
        module_parts = tuple(node.module.split(".")) if node.module else ()
        module = ".".join((*base, *module_parts))
        if module:
            imported.append((node.lineno, module))
        imported.extend(
            (node.lineno, ".".join((*base, *module_parts, alias.name)))
            for alias in node.names
            if alias.name != "*"
        )
    return imported


def test_v1_source_does_not_import_engagement_v2() -> None:
    offenders = []
    for root in V1_ROOTS:
        for path in root.rglob("*.py"):
            for line, module in _imported_modules(path):
                if module == _V2_MODULE or module.startswith(f"{_V2_MODULE}."):
                    offenders.append(f"{path.as_posix()}:{line} imports {module}")
    assert offenders == []


def test_v1_runtime_does_not_activate_engagement_v2() -> None:
    exercise_v1_entrypoints = """
from hackbot.cli import main as cli_main
from hackbot.programs.schema import validate_scope
from hackbot.risk import ActionRegistry
from hackbot.risk.policy import RiskEngine
from hackbot.scope import Scope
from hackbot.tools.runner import CommandRunner
import sys

assert cli_main.build_parser().parse_args(["version"]).command == "version"
assert validate_scope({"schema_version": 1, "in_scope": {"domains": ["example.invalid"]}})
assert Scope(["example.invalid"]).check("api.example.invalid").allowed
assert isinstance(RiskEngine(ActionRegistry(())), RiskEngine)
assert CommandRunner(timeout_seconds=1).run([sys.executable, "-c", "pass"]).exit_code == 0

offenders = sorted(
    name
    for name in sys.modules
    if name == "hackbot.engagement_v2" or name.startswith("hackbot.engagement_v2.")
)
if offenders:
    raise SystemExit("; ".join(offenders))
"""
    completed = subprocess.run(
        [sys.executable, "-c", exercise_v1_entrypoints],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_current_runtime_schema_remains_v1() -> None:
    from hackbot.programs.schema import SCHEMA_VERSION

    assert SCHEMA_VERSION == 1


def test_contract_document_declares_v2_unavailable() -> None:
    text = Path("docs/engagement-v2-contracts.md").read_text(encoding="utf-8")

    assert "P0 does not enable engagement v2 execution" in text
