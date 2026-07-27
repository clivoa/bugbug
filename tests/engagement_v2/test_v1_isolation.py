"""Guards which keep the P0 engagement-v2 contracts out of the v1 runtime."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

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

        base: tuple[str, ...] = ()
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


def _write_test_module(source_root: Path, relative_path: str, source: str) -> Path:
    path = source_root / relative_path
    path.parent.mkdir(parents=True)
    path.write_text(source, encoding="utf-8")
    return path


def test_ast_detects_absolute_engagement_v2_import_forms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "src"
    monkeypatch.setattr(sys.modules[__name__], "_SOURCE_ROOT", source_root)
    path = _write_test_module(
        source_root,
        "hackbot/cli/probe.py",
        "\n".join(
            (
                "import hackbot.engagement_v2",
                "from hackbot.engagement_v2 import ContractError",
                "from hackbot import engagement_v2",
            )
        ),
    )

    imported = set(_imported_modules(path))

    assert {
        (1, "hackbot.engagement_v2"),
        (2, "hackbot.engagement_v2"),
        (2, "hackbot.engagement_v2.ContractError"),
        (3, "hackbot.engagement_v2"),
    } <= imported


def test_ast_detects_absolute_engagement_v2_import_forms_from_a_package_initializer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "src"
    monkeypatch.setattr(sys.modules[__name__], "_SOURCE_ROOT", source_root)
    path = _write_test_module(
        source_root,
        "hackbot/plugin/__init__.py",
        "\n".join(
            (
                "import hackbot.engagement_v2",
                "from hackbot.engagement_v2 import ContractError",
                "from hackbot import engagement_v2",
            )
        ),
    )

    imported = set(_imported_modules(path))

    assert {
        (1, "hackbot.engagement_v2"),
        (2, "hackbot.engagement_v2"),
        (2, "hackbot.engagement_v2.ContractError"),
        (3, "hackbot.engagement_v2"),
    } <= imported


def test_ast_resolves_relative_import_from_a_normal_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "src"
    monkeypatch.setattr(sys.modules[__name__], "_SOURCE_ROOT", source_root)
    path = _write_test_module(
        source_root,
        "hackbot/cli/probe.py",
        "from ..engagement_v2 import ReasonCode\n",
    )

    assert _importing_package(path) == ("hackbot", "cli")
    assert _imported_modules(path) == [
        (1, "hackbot.engagement_v2"),
        (1, "hackbot.engagement_v2.ReasonCode"),
    ]


def test_ast_resolves_relative_import_from_a_package_initializer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "src"
    monkeypatch.setattr(sys.modules[__name__], "_SOURCE_ROOT", source_root)
    path = _write_test_module(
        source_root,
        "hackbot/plugin/__init__.py",
        "from ..engagement_v2 import ReasonCode\n",
    )

    assert _importing_package(path) == ("hackbot", "plugin")
    assert _imported_modules(path) == [
        (1, "hackbot.engagement_v2"),
        (1, "hackbot.engagement_v2.ReasonCode"),
    ]


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
from hackbot.risk import (
    ActionDefinition,
    ActionRegistry,
    ActionRequest,
    AuthorizationState,
    DecisionKind,
    PolicyContext,
    RiskLevel,
    TestingPolicy,
)
from hackbot.risk.identity import canonical_engagement_identity
from hackbot.risk.policy import RiskEngine
from hackbot.scope import Scope
from hackbot.tools.runner import CommandRunner
from datetime import UTC, datetime
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

if cli_main.app(["version"]) != 0:
    raise SystemExit("v1 CLI entrypoint failed")
if not validate_scope({"schema_version": 1, "in_scope": {"domains": ["example.invalid"]}}):
    raise SystemExit("v1 schema validation failed")
if not Scope(["example.invalid"]).check("api.example.invalid").allowed:
    raise SystemExit("v1 scope check failed")
with TemporaryDirectory() as temporary_directory:
    engagement_path, engagement_id = canonical_engagement_identity(Path(temporary_directory))
    request = ActionRequest(
        engagement_id=engagement_id,
        engagement_path=engagement_path,
        action_id="fixture.l0",
        target="https://api.example.invalid",
        argv=(),
        hypothesis_id="fixture",
        rationale="fixture",
        rate=1,
        concurrency=1,
        data_touched="fixture",
        expected_impact="fixture",
        stop_condition="fixture",
        cleanup_plan="fixture",
        program_rule="fixture",
    )
    context = PolicyContext(
        engagement_id=engagement_id,
        engagement_path=engagement_path,
        program_id="fixture",
        authorization=AuthorizationState(True, datetime(2026, 7, 27, tzinfo=UTC), "operator"),
        scope=Scope(["example.invalid"]),
        testing_policy=TestingPolicy(1, 1, False, False, False, False, False, False, False),
        active_profile=None,
        policy_digest="fixture",
    )
    decision = RiskEngine(ActionRegistry([ActionDefinition("fixture.l0", RiskLevel.L0)])).evaluate(
        request,
        context,
    )
    if decision.kind is not DecisionKind.ALLOW or decision.reason_code != "ALLOW":
        raise SystemExit("v1 risk decision failed")
if CommandRunner(timeout_seconds=1).run([sys.executable, "-c", "pass"]).exit_code != 0:
    raise SystemExit("v1 command runner failed")

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
    assert 'b"HBV2RUN\\x00"' in text
    assert "600 seconds after expiry" in text
    assert "until a longer in-progress run finalizes" in text
    assert (
        "| `protocol` | Immutable `FrameType`, `Frame`, `FramedMessage`, `RunBinding`, "
        "plus `write_message`, `read_message`, and `response_chain`. |"
    ) in text


def test_next_steps_separates_historical_v1_snapshot_from_p0_status() -> None:
    text = Path("docs/next-steps.md").read_text(encoding="utf-8")

    assert "Historical v1 verification snapshot" in text
    assert "P0 tasks 1.1–8.2 are complete" in text
    assert "Current normative text lives under `openspec/specs/`" in text
    assert "P1 is **Ready**" in text
