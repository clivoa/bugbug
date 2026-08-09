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

# P1 introduces the first declared v2 consumers reachable from the CLI. Only
# these modules may import hackbot.engagement_v2; every other v1 module must not.
_V2_ENTRY_ALLOWLIST = frozenset(
    {
        Path("src/hackbot/cli/engagement_cmd.py"),
    }
)


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


def _v2_importers() -> set[Path]:
    importers: set[Path] = set()
    for root in V1_ROOTS:
        for path in root.rglob("*.py"):
            for _line, module in _imported_modules(path):
                if module == _V2_MODULE or module.startswith(f"{_V2_MODULE}."):
                    importers.add(path)
    return importers


def test_v1_source_does_not_import_engagement_v2_outside_allowlist() -> None:
    offenders = []
    for path in _v2_importers():
        if path in _V2_ENTRY_ALLOWLIST:
            continue
        for line, module in _imported_modules(path):
            if module == _V2_MODULE or module.startswith(f"{_V2_MODULE}."):
                offenders.append(f"{path.as_posix()}:{line} imports {module}")
    assert offenders == []


def test_only_declared_v2_entry_points_import_engagement_v2() -> None:
    # The set of v1-root files importing the contract package must be exactly the
    # declared allowlist: no accidental new consumer, and the allowlist stays live.
    assert _v2_importers() == set(_V2_ENTRY_ALLOWLIST)


def test_default_cli_module_does_not_import_engagement_v2() -> None:
    # cli/main.py reaches the v2 entry point lazily inside the command handler,
    # so importing the CLI never loads the contract package.
    for line, module in _imported_modules(Path("src/hackbot/cli/main.py")):
        assert not (module == _V2_MODULE or module.startswith(f"{_V2_MODULE}.")), (
            f"cli/main.py:{line} imports {module}"
        )


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


def test_l3_activation_and_stale_rejection_leave_v1_bytes_and_globals_unchanged() -> None:
    """P5b authority checks stay isolated from all schema-v1 state and fixtures."""

    from dataclasses import replace
    from types import MappingProxyType

    import hackbot.programs.schema as v1_schema
    from hackbot.engagement_v2.errors import ContractError, ReasonCode
    from hackbot.engagement_v2.l3_contracts import activate_catalog, decide_l3
    from hackbot.engagement_v2.loader import EngagementSnapshot
    from hackbot.engagement_v2.projection import (
        engagement_identity,
        projection_digest,
        security_projection,
    )

    fixture_root = Path("tests/fixtures/engagement_v2_loader/v1-source")
    before_bytes = {
        path.name: path.read_bytes() for path in sorted(fixture_root.iterdir()) if path.is_file()
    }
    before_globals = (v1_schema.SCHEMA_VERSION, frozenset(vars(v1_schema)))
    program = {
        "profile": "local-lab",
        "testing_rules": {
            "payload_execution_allowed": True,
            "state_changing_allowed": True,
        },
    }
    scope = {
        "schema_version": 2,
        "in_scope": {"urls": ["https://app.corp.example/admin"]},
        "out_of_scope": {},
    }
    authority_digest = projection_digest(
        security_projection(program=program, scope=scope, runner=None)
    )
    snapshot = EngagementSnapshot(
        program=MappingProxyType(program),
        scope=MappingProxyType(scope),
        authorization=MappingProxyType(
            {
                "confirmed": True,
                "confirmed_authority_digest": authority_digest,
            }
        ),
        runner=None,
        profile="local-lab",
        authority_digest=authority_digest,
        identity=engagement_identity(authority_digest),
    )
    activation = activate_catalog(
        snapshot,
        internal_recon_confirmed=True,
        project_root=Path.cwd(),
    )
    with pytest.raises(ContractError) as excinfo:
        decide_l3(
            {
                "action_id": "operator.internal.payload.verify",
                "parameters": {"host": "https://app.corp.example/admin"},
            },
            replace(snapshot, authority_digest="sha256:" + "f" * 64),
            activation,
            platform="linux",
        )
    assert excinfo.value.reason_code is ReasonCode.DENY_AUTHORIZATION_STALE

    after_bytes = {
        path.name: path.read_bytes() for path in sorted(fixture_root.iterdir()) if path.is_file()
    }
    assert after_bytes == before_bytes
    assert (v1_schema.SCHEMA_VERSION, frozenset(vars(v1_schema))) == before_globals


def test_v2_loader_rejects_a_v1_engagement(tmp_path: Path) -> None:
    # A schema v1 engagement is never silently upgraded: the v2 loader refuses it
    # with INVALID_SCHEMA_VERSION, so v1 engagements stay on the v1 path.
    import json

    from hackbot.engagement_v2.errors import ContractError, ReasonCode
    from hackbot.engagement_v2.loader import load_engagement

    (tmp_path / "program.json").write_text(
        json.dumps({"schema_version": 1, "program": {"name": "acme"}}), encoding="utf-8"
    )
    (tmp_path / "scope.json").write_text(
        json.dumps({"schema_version": 1, "in_scope": {}, "out_of_scope": {}}), encoding="utf-8"
    )
    (tmp_path / "authorization.json").write_text(json.dumps({"confirmed": False}), encoding="utf-8")
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert excinfo.value.reason_code is ReasonCode.INVALID_SCHEMA_VERSION


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


def test_next_steps_separates_historical_v1_snapshot_from_current_status() -> None:
    text = Path("docs/next-steps.md").read_text(encoding="utf-8")

    assert "Historical v1 verification snapshot" in text
    current, historical = text.split("## Historical v1 verification snapshot", maxsplit=1)
    assert "Current delivery: P7" in current
    assert "P0 — security contracts" in current
    assert "P6 — autonomous workflow contracts" in current
    # Historical section should reference test counts from the v1 era
    assert "1504 passed" in historical or "912 passing" in historical
    assert "P1 is **Ready**" not in text
