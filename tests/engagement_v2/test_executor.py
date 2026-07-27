"""P3 local executor, secrets, evidence, and cleanup."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from hackbot.engagement_v2 import executor as executor_mod
from hackbot.engagement_v2.binder import BoundCommand, SecretReference
from hackbot.engagement_v2.constants import ResourceCleanupState, TargetCleanupState
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.executor import run
from hackbot.engagement_v2.manifest import validate_manifest
from hackbot.engagement_v2.secrets import namespaced_key

pytest.importorskip("yaml")

_ID = "engv2:sha256test"


class _Backend:
    def __init__(self) -> None:
        self._d: dict[str, str] = {}

    def set(self, key: str, value: str) -> None:
        self._d[key] = value

    def get(self, name: str) -> str | None:
        return self._d.get(name)


def _action(**over):
    base = {
        "id": "operator.echo",
        "title": "echo",
        "risk": "L0",
        "platforms": ["linux"],
        "architectures": ["x86_64"],
        "executables": {"linux": "/bin/echo"},
        "required_privileges": [],
        "parameters": {},
        "secrets": {},
        "targets": [],
        "characteristics": {},
        "rate_control": {"kind": "not-applicable"},
        "capabilities": [],
        "vulnerability_types": [],
        "impacts": [],
        "evidence_policy": {"mode": "metadata-only"},
        "argv": ["hello"],
    }
    base.update(over)
    registry = validate_manifest({"schema_version": 1, "actions": [base]})
    return registry["operator.echo"]


def _decision(allow: bool = True):
    kind = SimpleNamespace(value="ALLOW" if allow else "DENY")
    return SimpleNamespace(kind=kind, reason="ALLOW" if allow else "out-of-scope-no-match")


def _snapshot(identity: str = _ID):
    return SimpleNamespace(identity=identity)


def _bound(executable: str, *tokens):
    return BoundCommand(
        executable=executable, argv=(executable, *tokens), targets={}, secret_references=frozenset()
    )


# ------------------------------------------------------------- gate + spawn ---
def test_allow_spawns_and_captures(tmp_path: Path) -> None:
    result = run(
        _bound("/bin/echo", "hello"),
        _action(),
        _snapshot(),
        _decision(),
        secret_backend=_Backend(),
        base_dir=str(tmp_path),
    )
    assert result.executed is True
    assert result.exit_code == 0


def test_deny_does_not_spawn(tmp_path: Path) -> None:
    result = run(
        _bound("/bin/echo", "hello"),
        _action(),
        _snapshot(),
        _decision(allow=False),
        secret_backend=_Backend(),
        base_dir=str(tmp_path),
    )
    assert result.executed is False
    assert list(tmp_path.iterdir()) == []  # no run resources created


def test_private_environment_is_sanitized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HACKBOT_TEST_SECRET", "leaky-value")
    action = _action(
        executables={"linux": "/usr/bin/env"},
        evidence_policy={"mode": "redacted-output"},
        argv=["-0"],
    )
    result = run(
        _bound("/usr/bin/env"),
        action,
        _snapshot(),
        _decision(),
        secret_backend=_Backend(),
        base_dir=str(tmp_path),
        output_persistence_allowed=True,
    )
    stdout = bytes(result.evidence["stdout"])  # type: ignore[arg-type]
    assert b"leaky-value" not in stdout
    assert b"HOME=" in stdout


# ----------------------------------------------------------------- secrets ---
def test_secret_file_is_redacted_in_output(tmp_path: Path) -> None:
    backend = _Backend()
    backend.set(namespaced_key(_ID, "api_key"), "s3cr3t-token-value")
    action = _action(
        executables={"linux": "/bin/cat"},
        secrets={"api_key": {"transport": "file"}},
        evidence_policy={"mode": "redacted-output"},
        argv=["{secret_file:api_key}"],
    )
    bound = BoundCommand(
        executable="/bin/cat",
        argv=("/bin/cat", SecretReference("api_key")),
        targets={},
        secret_references=frozenset({"api_key"}),
    )
    result = run(
        bound,
        action,
        _snapshot(),
        _decision(),
        secret_backend=backend,
        base_dir=str(tmp_path),
        output_persistence_allowed=True,
    )
    stdout = bytes(result.evidence["stdout"])  # type: ignore[arg-type]
    assert b"s3cr3t-token-value" not in stdout
    assert b"[REDACTED-SECRET]" in stdout


def test_secret_never_in_audit(tmp_path: Path) -> None:
    backend = _Backend()
    backend.set(namespaced_key(_ID, "api_key"), "s3cr3t-token-value")
    action = _action(
        executables={"linux": "/bin/cat"},
        secrets={"api_key": {"transport": "file"}},
        argv=["{secret_file:api_key}"],
    )
    bound = BoundCommand(
        executable="/bin/cat",
        argv=("/bin/cat", SecretReference("api_key")),
        targets={},
        secret_references=frozenset({"api_key"}),
    )
    result = run(
        bound, action, _snapshot(), _decision(), secret_backend=backend, base_dir=str(tmp_path)
    )
    audit_text = repr(result.audit)
    assert "s3cr3t-token-value" not in audit_text
    projection = str(result.audit["argv_projection"])
    assert "{secret_file}" in projection  # placeholder kept, binding id stripped
    assert "api_key" not in projection


def test_missing_secret_fails_closed(tmp_path: Path) -> None:
    action = _action(
        executables={"linux": "/bin/cat"},
        secrets={"api_key": {"transport": "file"}},
        argv=["{secret_file:api_key}"],
    )
    bound = BoundCommand(
        executable="/bin/cat",
        argv=("/bin/cat", SecretReference("api_key")),
        targets={},
        secret_references=frozenset({"api_key"}),
    )
    result = run(
        bound, action, _snapshot(), _decision(), secret_backend=_Backend(), base_dir=str(tmp_path)
    )
    assert result.executed is False
    assert "api_key" not in result.reason  # secret-free failure


def test_cross_engagement_secret_fails_closed(tmp_path: Path) -> None:
    backend = _Backend()
    backend.set(namespaced_key("engv2:OTHER", "api_key"), "foreign")
    action = _action(
        executables={"linux": "/bin/cat"},
        secrets={"api_key": {"transport": "file"}},
        argv=["{secret_file:api_key}"],
    )
    bound = BoundCommand(
        executable="/bin/cat",
        argv=("/bin/cat", SecretReference("api_key")),
        targets={},
        secret_references=frozenset({"api_key"}),
    )
    result = run(
        bound, action, _snapshot(_ID), _decision(), secret_backend=backend, base_dir=str(tmp_path)
    )
    assert result.executed is False


# ---------------------------------------------------------------- evidence ---
def test_credential_action_cannot_use_redacted_output(tmp_path: Path) -> None:
    action = _action(
        capabilities=["credential-access"],
        evidence_policy={"mode": "redacted-output"},
    )
    with pytest.raises(ContractError) as excinfo:
        run(
            _bound("/bin/echo", "hi"),
            action,
            _snapshot(),
            _decision(),
            secret_backend=_Backend(),
            base_dir=str(tmp_path),
            output_persistence_allowed=True,
        )
    assert excinfo.value.reason_code is ReasonCode.EVIDENCE_POLICY_DENIED


def test_spawn_failure_cleans_up_secret_and_fails_closed(tmp_path: Path) -> None:
    backend = _Backend()
    backend.set(namespaced_key(_ID, "api_key"), "s3cr3t-token-value")
    action = _action(
        executables={"linux": "/nonexistent/bogus-exe"},
        secrets={"api_key": {"transport": "file"}},
        argv=["{secret_file:api_key}"],
    )
    bound = BoundCommand(
        executable="/nonexistent/bogus-exe",
        argv=("/nonexistent/bogus-exe", SecretReference("api_key")),
        targets={},
        secret_references=frozenset({"api_key"}),
    )
    result = run(
        bound, action, _snapshot(), _decision(), secret_backend=backend, base_dir=str(tmp_path)
    )
    assert result.executed is False
    # No secret material and no run directory survive.
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []
    assert [p for p in tmp_path.iterdir() if p.name.startswith("run-")] == []
    # The failure reason leaks neither the secret nor the executable path.
    assert "s3cr3t-token-value" not in result.reason
    assert "/nonexistent" not in result.reason


def test_structured_mode_requires_persistence(tmp_path: Path) -> None:
    action = _action(evidence_policy={"mode": "structured"})
    with pytest.raises(ContractError) as excinfo:
        run(
            _bound("/bin/echo", "hi"),
            action,
            _snapshot(),
            _decision(),
            secret_backend=_Backend(),
            base_dir=str(tmp_path),
            output_persistence_allowed=False,
        )
    assert excinfo.value.reason_code is ReasonCode.EVIDENCE_POLICY_DENIED


def test_structured_mode_stores_no_raw_output(tmp_path: Path) -> None:
    action = _action(evidence_policy={"mode": "structured"})
    result = run(
        _bound("/bin/echo", "hi"),
        action,
        _snapshot(),
        _decision(),
        secret_backend=_Backend(),
        base_dir=str(tmp_path),
        output_persistence_allowed=True,
    )
    assert "stdout" not in result.evidence


def test_metadata_only_stores_no_raw_output(tmp_path: Path) -> None:
    result = run(
        _bound("/bin/echo", "sensitive-looking"),
        _action(),
        _snapshot(),
        _decision(),
        secret_backend=_Backend(),
        base_dir=str(tmp_path),
    )
    assert "stdout" not in result.evidence


# ----------------------------------------------------------------- cleanup ---
def test_resource_cleanup_removes_private_dir(tmp_path: Path) -> None:
    result = run(
        _bound("/bin/echo", "hi"),
        _action(),
        _snapshot(),
        _decision(),
        secret_backend=_Backend(),
        base_dir=str(tmp_path),
    )
    assert result.resource_cleanup_status == ResourceCleanupState.COMPLETE.value
    assert [p for p in tmp_path.iterdir() if p.is_dir()] == []


def test_resource_cleanup_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor_mod.shutil, "rmtree", lambda *a, **k: None)
    result = run(
        _bound("/bin/echo", "hi"),
        _action(),
        _snapshot(),
        _decision(),
        secret_backend=_Backend(),
        base_dir=str(tmp_path),
    )
    assert result.resource_cleanup_status == ResourceCleanupState.FAILED.value


def test_deadline_terminates_the_child(tmp_path: Path) -> None:
    action = _action(executables={"linux": "/bin/sleep"}, argv=["10"])
    result = run(
        _bound("/bin/sleep", "10"),
        action,
        _snapshot(),
        _decision(),
        secret_backend=_Backend(),
        base_dir=str(tmp_path),
        timeout_seconds=0.5,
    )
    assert result.timed_out is True
    assert result.resource_cleanup_status == ResourceCleanupState.COMPLETE.value


def test_stdin_secret_transport(tmp_path: Path) -> None:
    backend = _Backend()
    backend.set(namespaced_key(_ID, "api_key"), "stdin-secret-value")
    action = _action(
        executables={"linux": "/bin/cat"},
        secrets={"api_key": {"transport": "stdin"}},
        evidence_policy={"mode": "redacted-output"},
        argv=["hello"],  # cat with a literal token still reads no stdin; use bare cat below
    )
    bound = BoundCommand(
        executable="/bin/cat", argv=("/bin/cat",), targets={}, secret_references=frozenset()
    )
    result = run(
        bound,
        action,
        _snapshot(),
        _decision(),
        secret_backend=backend,
        base_dir=str(tmp_path),
        output_persistence_allowed=True,
        stdin_secret="api_key",
    )
    stdout = bytes(result.evidence["stdout"])  # type: ignore[arg-type]
    assert b"stdin-secret-value" not in stdout
    assert b"[REDACTED-SECRET]" in stdout


def test_target_self_report_is_unverified(tmp_path: Path) -> None:
    result = run(
        _bound("/bin/echo", "hi"),
        _action(),
        _snapshot(),
        _decision(),
        secret_backend=_Backend(),
        base_dir=str(tmp_path),
        target_self_report="done",
    )
    assert result.target_cleanup_status == TargetCleanupState.UNVERIFIED_SELF_REPORT.value
