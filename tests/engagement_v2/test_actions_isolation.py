"""Guards proving the P2 manifest/binder/policy layer executes nothing."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_P2_MODULES = (
    Path("src/hackbot/engagement_v2/manifest.py"),
    Path("src/hackbot/engagement_v2/binder.py"),
    Path("src/hackbot/engagement_v2/policy.py"),
)
_FORBIDDEN_MODULES = {"subprocess", "socket", "keyring", "asyncio", "http", "urllib.request"}
_FORBIDDEN_CALLS = {"system", "popen", "exec", "execv", "execve", "spawn", "spawnv", "fork"}


def _imports(tree: ast.AST) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


@pytest.mark.parametrize("path", _P2_MODULES, ids=lambda p: p.name)
def test_p2_module_imports_nothing_executing(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    offenders = {module for module in _imports(tree) if module.split(".")[0] in _FORBIDDEN_MODULES}
    assert offenders == set(), f"{path}: forbidden imports {offenders}"


@pytest.mark.parametrize("path", _P2_MODULES, ids=lambda p: p.name)
def test_p2_module_makes_no_exec_call(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    offenders = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _FORBIDDEN_CALLS
    ]
    assert offenders == [], f"{path}: forbidden calls {offenders}"
