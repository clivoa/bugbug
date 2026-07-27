"""Gate-bound local executor for the P2 bound command.

The executor spawns a child only on a policy `ALLOW`, only the P2 bound argv, with
`shell=False`, inside a private mode-0700 directory used as CWD/HOME/TMPDIR with a
sanitized environment. It resolves secrets after `ALLOW` within the engagement
namespace, delivers them only via stdin or a protected file, retains conservative
redacted evidence, and cleans up resources and target state independently and
fail-closed with a secret-free audit record.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from hackbot.engagement_v2.binder import BoundCommand, FileReference, SecretReference
from hackbot.engagement_v2.constants import (
    EvidenceMode,
    LifecycleState,
    ResourceCleanupState,
    TargetCleanupState,
)
from hackbot.engagement_v2.evidence import check_evidence_mode, redact
from hackbot.engagement_v2.manifest import ActionDefinition
from hackbot.engagement_v2.secrets import (
    SecretBackend,
    SecretResolutionError,
    resolve_secret,
    write_protected_file,
)

_CLEANUP_GRACE_SECONDS = 5.0


@dataclass(frozen=True)
class ExecutionResult:
    lifecycle: str
    executed: bool
    reason: str
    exit_code: int | None = None
    timed_out: bool = False
    evidence: Mapping[str, object] = field(default_factory=dict)
    resource_cleanup_status: str = ResourceCleanupState.NOT_REQUIRED.value
    target_cleanup_status: str = TargetCleanupState.NOT_REQUIRED.value
    audit: Mapping[str, object] = field(default_factory=dict)


def _sanitized_env(private_dir: str) -> dict[str, str]:
    # Minimal allowlist: no inherited operator or host secret.
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": private_dir,
        "TMPDIR": private_dir,
        "LANG": "C",
    }


def _audit_projection(action: ActionDefinition, bound: BoundCommand) -> tuple[str, ...]:
    # Placeholder projection: the code-owned template, never concrete values,
    # secret material, or ephemeral paths.
    return (bound.executable, *action.argv_template)


def run(
    bound: BoundCommand,
    action: ActionDefinition,
    snapshot: object,
    decision: object,
    *,
    secret_backend: SecretBackend,
    base_dir: str,
    output_persistence_allowed: bool = False,
    timeout_seconds: float = 30.0,
    output_cap_bytes: int = 1_048_576,
    stdin_secret: str | None = None,
    target_self_report: str | None = None,
) -> ExecutionResult:
    """Execute a bound command locally, or fail closed without spawning."""

    audit_argv = _audit_projection(action, bound)
    reason_deny = getattr(decision, "reason", "")
    if getattr(getattr(decision, "kind", None), "value", "") != "ALLOW":
        # Non-ALLOW: no spawn, no run resources.
        return ExecutionResult(
            lifecycle=LifecycleState.VALIDATED.value,
            executed=False,
            reason=reason_deny or "not-allowed",
            audit={"argv_projection": audit_argv, "decision": reason_deny},
        )

    identity = getattr(snapshot, "identity", "")

    # Evidence mode is checked before any spawn.
    check_evidence_mode(
        action.evidence_mode,
        action.capabilities,
        output_persistence_allowed=output_persistence_allowed,
    )

    private_dir = _make_private_dir(base_dir)
    resource_status = ResourceCleanupState.NOT_REQUIRED.value
    try:
        # Resolve secrets after ALLOW, within the engagement namespace.
        resolved: dict[str, bytes] = {}
        for name in sorted(action.secret_bindings):
            resolved[name] = resolve_secret(secret_backend, identity, name)

        argv = _materialize(bound, resolved, private_dir)
        stdin_bytes = resolved.get(stdin_secret) if stdin_secret else None

        exit_code, stdout, stderr, timed_out = _spawn(
            argv, private_dir, stdin_bytes, timeout_seconds, output_cap_bytes
        )
        evidence = _finalize_evidence(action, stdout, stderr, resolved.values())
        resource_status = _resource_cleanup(private_dir)
        target_status = _target_cleanup(target_self_report)
        audit = {
            "engagement_identity": identity,
            "argv_projection": audit_argv,
            "decision": "ALLOW",
            "exit_code": exit_code,
            "timed_out": timed_out,
            "resource_cleanup_status": resource_status,
            "target_cleanup_status": target_status,
        }
        return ExecutionResult(
            lifecycle=LifecycleState.FINALIZED.value,
            executed=True,
            reason="ALLOW",
            exit_code=exit_code,
            timed_out=timed_out,
            evidence=evidence,
            resource_cleanup_status=resource_status,
            target_cleanup_status=target_status,
            audit=audit,
        )
    except SecretResolutionError as exc:
        # Fail closed before spawn; executed stays false; message is secret-free.
        resource_status = _resource_cleanup(private_dir)
        return ExecutionResult(
            lifecycle=LifecycleState.PREPARED.value,
            executed=False,
            reason=str(exc),
            resource_cleanup_status=resource_status,
            audit={"argv_projection": audit_argv, "decision": "ALLOW"},
        )
    finally:
        if os.path.isdir(private_dir) and resource_status == ResourceCleanupState.COMPLETE.value:
            shutil.rmtree(private_dir, ignore_errors=True)


def _make_private_dir(base_dir: str) -> str:
    os.makedirs(base_dir, exist_ok=True)
    path = os.path.join(base_dir, f"run-{os.getpid()}-{time.monotonic_ns():x}")
    os.mkdir(path, mode=0o700)
    os.chmod(path, 0o700)
    return path


def _materialize(bound: BoundCommand, resolved: Mapping[str, bytes], private_dir: str) -> list[str]:
    argv: list[str] = []
    for token in bound.argv:
        if isinstance(token, str):
            argv.append(token)
        elif isinstance(token, SecretReference):
            argv.append(write_protected_file(private_dir, resolved[token.name]))
        elif isinstance(token, FileReference) and token.kind == "targets_file":
            payload = "\n".join(bound.targets.get(token.name, ())).encode("utf-8")
            argv.append(write_protected_file(private_dir, payload))
        else:  # artifact_file or anything unexpected -> fail closed
            raise SecretResolutionError("unsupported argv reference for local execution")
    return argv


def _spawn(
    argv: list[str],
    private_dir: str,
    stdin_bytes: bytes | None,
    timeout_seconds: float,
    output_cap_bytes: int,
) -> tuple[int | None, bytes, bytes, bool]:
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_sanitized_env(private_dir),
        cwd=private_dir,
        shell=False,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(input=stdin_bytes, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        try:
            stdout, stderr = proc.communicate(timeout=_CLEANUP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            stdout, stderr = b"", b""
    return proc.returncode, stdout[:output_cap_bytes], stderr[:output_cap_bytes], timed_out


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        proc.kill()


def _finalize_evidence(
    action: ActionDefinition, stdout: bytes, stderr: bytes, secret_values: Iterable[bytes]
) -> dict[str, object]:
    metadata = {"stdout_bytes": len(stdout), "stderr_bytes": len(stderr)}
    if action.evidence_mode == EvidenceMode.METADATA_ONLY.value:
        return {"mode": action.evidence_mode, "metadata": metadata}
    values = list(secret_values)
    return {
        "mode": action.evidence_mode,
        "metadata": metadata,
        "stdout": redact(stdout, values),
        "stderr": redact(stderr, values),
    }


def _resource_cleanup(private_dir: str) -> str:
    shutil.rmtree(private_dir, ignore_errors=True)
    if os.path.isdir(private_dir):
        # Unconfirmed cleanup: fail closed and leave a protected marker.
        marker = os.path.join(private_dir, "cleanup-incomplete")
        try:
            with open(os.open(marker, os.O_WRONLY | os.O_CREAT, 0o600), "wb"):
                pass
        except OSError:
            pass
        return ResourceCleanupState.FAILED.value
    return ResourceCleanupState.COMPLETE.value


def _target_cleanup(target_self_report: str | None) -> str:
    if target_self_report is not None:
        # A target's own receipt is never independent proof.
        return TargetCleanupState.UNVERIFIED_SELF_REPORT.value
    return TargetCleanupState.NOT_REQUIRED.value
