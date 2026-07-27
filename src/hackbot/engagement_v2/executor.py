"""Gate-bound local executor for the P2 bound command.

The executor spawns a child only on a policy `ALLOW`, only the P2 bound argv, with
`shell=False`, inside a private mode-0700 directory used as CWD/HOME/TMPDIR with a
sanitized environment. It resolves secrets after `ALLOW` within the engagement
namespace, delivers them only via stdin or a protected file, retains conservative
redacted evidence, and cleans up resources and target state independently and
fail-closed with a secret-free audit record. Any error after the private
directory is created routes through cleanup and returns a fail-closed result.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import BinaryIO

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
_READ_CHUNK = 65536
_PLACEHOLDER_ID = re.compile(
    r"\{(value|target|targets_file|artifact_file|secret_file):[a-z][a-z0-9_]{0,63}\}"
)


class _ExecutionAbort(Exception):
    """Internal fail-closed abort with a secret-free, path-free reason."""


@dataclass(frozen=True)
class ExecutionResult:
    lifecycle: str
    executed: bool
    reason: str
    exit_code: int | None = None
    timed_out: bool = False
    truncated: bool = False
    evidence: Mapping[str, object] = field(default_factory=dict)
    resource_cleanup_status: str = ResourceCleanupState.NOT_REQUIRED.value
    target_cleanup_status: str = TargetCleanupState.NOT_REQUIRED.value
    audit: Mapping[str, object] = field(default_factory=dict)
    states: tuple[str, ...] = ()


def _sanitized_env(private_dir: str) -> dict[str, str]:
    # Minimal allowlist: no inherited operator or host secret.
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": private_dir,
        "TMPDIR": private_dir,
        "LANG": "C",
    }


def _audit_projection(action: ActionDefinition, bound: BoundCommand) -> tuple[str, ...]:
    # Code-owned placeholder projection with binding ids stripped, so neither a
    # secret name, a concrete value, nor an ephemeral path can enter audit.
    tokens = (
        _PLACEHOLDER_ID.sub(lambda m: "{" + m.group(1) + "}", t) for t in action.argv_template
    )
    return (bound.executable, *tokens)


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
    if getattr(getattr(decision, "kind", None), "value", "") != "ALLOW":
        # Non-ALLOW: no spawn, no run resources.
        return ExecutionResult(
            lifecycle=LifecycleState.VALIDATED.value,
            executed=False,
            reason=getattr(decision, "reason", "") or "not-allowed",
            audit={"argv_projection": audit_argv, "decision": getattr(decision, "reason", "")},
            states=(LifecycleState.RECEIVED.value, LifecycleState.VALIDATED.value),
        )

    identity = getattr(snapshot, "identity", "")

    # Evidence mode is checked before any spawn or resource creation.
    check_evidence_mode(
        action.evidence_mode,
        action.capabilities,
        output_persistence_allowed=output_persistence_allowed,
    )

    private_dir = _make_private_dir(base_dir)
    resource_status = ResourceCleanupState.FAILED.value
    try:
        if action.secret_bindings and not identity:
            raise _ExecutionAbort("engagement identity is required to resolve secrets")
        resolved: dict[str, bytes] = {}
        for name in sorted(action.secret_bindings):
            resolved[name] = resolve_secret(secret_backend, identity, name)

        argv = _materialize(bound, resolved, private_dir)
        stdin_bytes = resolved.get(stdin_secret) if stdin_secret else None

        try:
            exit_code, stdout, stderr, timed_out, truncated = _spawn(
                argv, private_dir, stdin_bytes, timeout_seconds, output_cap_bytes
            )
        except OSError as exc:
            # e.g. a missing or non-executable bound executable: fail closed
            # without leaking the path.
            raise _ExecutionAbort("could not start the bound executable") from exc

        evidence = _finalize_evidence(action, stdout, stderr, resolved.values())
        resource_status = _resource_cleanup(private_dir, base_dir)
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
            truncated=truncated,
            evidence=evidence,
            resource_cleanup_status=resource_status,
            target_cleanup_status=target_status,
            audit=audit,
            states=_SUCCESS_STATES,
        )
    except (SecretResolutionError, _ExecutionAbort) as exc:
        # Fail closed before or during spawn; executed stays false and the
        # reason is secret-free and path-free.
        resource_status = _resource_cleanup(private_dir, base_dir)
        return ExecutionResult(
            lifecycle=LifecycleState.PREPARED.value,
            executed=False,
            reason=str(exc),
            resource_cleanup_status=resource_status,
            audit={
                "argv_projection": audit_argv,
                "decision": "ALLOW",
                "resource_cleanup_status": resource_status,
            },
            states=(LifecycleState.ALLOWED.value, LifecycleState.PREPARED.value),
        )
    except BaseException:
        # Any other failure still cleans up and re-raises (never leaks secrets on
        # disk); the finally guarantees removal.
        _resource_cleanup(private_dir, base_dir)
        raise


_SUCCESS_STATES = (
    LifecycleState.ALLOWED.value,
    LifecycleState.PREPARED.value,
    LifecycleState.SPAWNED.value,
    LifecycleState.INTERACTION_ATTEMPTED.value,
    LifecycleState.CHILD_FINISHED.value,
    LifecycleState.EVIDENCE_FINALIZED.value,
    LifecycleState.RESOURCE_CLEANUP.value,
    LifecycleState.TARGET_CLEANUP.value,
    LifecycleState.FINALIZED.value,
)


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
            raise _ExecutionAbort("unsupported argv reference for local execution")
    return argv


def _read_capped(pipe: BinaryIO, cap: int, sink: list[bytes]) -> None:
    buffer = bytearray()
    try:
        while True:
            chunk = pipe.read(_READ_CHUNK)
            if not chunk:
                break
            if len(buffer) < cap:
                buffer += chunk[: cap - len(buffer)]
            # Bytes beyond the cap are read and discarded so memory stays bounded.
    finally:
        sink.append(bytes(buffer))


def _spawn(
    argv: list[str],
    private_dir: str,
    stdin_bytes: bytes | None,
    timeout_seconds: float,
    output_cap_bytes: int,
) -> tuple[int | None, bytes, bytes, bool, bool]:
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
    assert proc.stdout is not None and proc.stderr is not None
    out_sink: list[bytes] = []
    err_sink: list[bytes] = []
    out_reader = threading.Thread(
        target=_read_capped, args=(proc.stdout, output_cap_bytes, out_sink)
    )
    err_reader = threading.Thread(
        target=_read_capped, args=(proc.stderr, output_cap_bytes, err_sink)
    )
    out_reader.start()
    err_reader.start()

    if stdin_bytes is not None and proc.stdin is not None:
        try:
            proc.stdin.write(stdin_bytes)
        except BrokenPipeError:
            pass
        finally:
            proc.stdin.close()

    timed_out = False
    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
    out_reader.join(_CLEANUP_GRACE_SECONDS)
    err_reader.join(_CLEANUP_GRACE_SECONDS)
    stdout = out_sink[0] if out_sink else b""
    stderr = err_sink[0] if err_sink else b""
    truncated = len(stdout) >= output_cap_bytes or len(stderr) >= output_cap_bytes
    return proc.returncode, stdout, stderr, timed_out, truncated


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        proc.kill()
    try:
        proc.wait(timeout=_CLEANUP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass


def _finalize_evidence(
    action: ActionDefinition, stdout: bytes, stderr: bytes, secret_values: Iterable[bytes]
) -> dict[str, object]:
    metadata = {"stdout_bytes": len(stdout), "stderr_bytes": len(stderr)}
    # metadata-only and structured store no raw tool output; only redacted-output
    # persists redacted stdout/stderr.
    if action.evidence_mode != EvidenceMode.REDACTED_OUTPUT.value:
        return {"mode": action.evidence_mode, "metadata": metadata}
    values = list(secret_values)
    return {
        "mode": action.evidence_mode,
        "metadata": metadata,
        "stdout": redact(stdout, values),
        "stderr": redact(stderr, values),
    }


def _resource_cleanup(private_dir: str, base_dir: str) -> str:
    shutil.rmtree(private_dir, ignore_errors=True)
    if not os.path.isdir(private_dir):
        return ResourceCleanupState.COMPLETE.value
    # Unconfirmed cleanup: fail closed and leave a protected marker in a stable
    # cleanup/ location (never inside the doomed private directory).
    cleanup_dir = os.path.join(base_dir, "cleanup")
    try:
        os.makedirs(cleanup_dir, mode=0o700, exist_ok=True)
        marker = os.path.join(cleanup_dir, f"incomplete-{os.path.basename(private_dir)}")
        with open(os.open(marker, os.O_WRONLY | os.O_CREAT, 0o600), "wb"):
            pass
    except OSError:
        pass
    return ResourceCleanupState.FAILED.value


def _target_cleanup(target_self_report: str | None) -> str:
    if target_self_report is not None:
        # A target's own receipt is never independent proof.
        return TargetCleanupState.UNVERIFIED_SELF_REPORT.value
    return TargetCleanupState.NOT_REQUIRED.value
