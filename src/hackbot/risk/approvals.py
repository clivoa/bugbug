"""Canonical, local-only storage for exact five-minute L2 approvals.

The supported macOS/Linux runtime requires both :mod:`fcntl` locking and a
native atomic no-overwrite rename primitive (``renameatx_np`` on macOS or
``renameat2`` on Linux).  The store fails closed when either capability is
unavailable.  Windows is intentionally not claimed as a supported
approval-store platform until it has equivalent primitives.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hackbot.programs.decoding import DuplicateJSONKeyError, strict_json_loads
from hackbot.risk.identity import EngagementIdentityError, canonical_engagement_identity
from hackbot.risk.models import (
    ActionDefinition,
    ActionRequest,
    ApprovalChallenge,
    ApprovalGrant,
    PolicyContext,
    RiskLevel,
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$", re.ASCII)
_APPROVED_BY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$", re.ASCII)
_EVENT_RESULT_RE = re.compile(r"^[a-z][a-z-]{0,63}$", re.ASCII)
_EVENT_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$", re.ASCII)
_SECRET_RE = re.compile(
    r"(?ix)("
    r"(?:proxy-)?authorization\s*:\s*\S+"
    r"|(?:cookie|set-cookie|x-auth-token|x-api-key|authentication-info)\s*:\s*\S+"
    r"|\b(?:session(?:[ _-]?id)?|sessionid|auth[ _-]?session(?:[ _-]?id)?)"
    r"\s*[:=]\s*\S+"
    r"|\b(?:api[ _-]?key|token|secret|password|private[ _-]?key)\s*[:=]\s*\S+"
    r"|\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"
    r"|\b(?:sk|ghp|xox[baprs])[_-][A-Za-z0-9_-]{12,}"
    r")"
)
_SECRET_NAME_RE = re.compile(
    r"(?i)^(?:authorization|proxy-authorization|cookie|set-cookie|x-auth-token|"
    r"x-api-key|authentication-info|session(?:[ _-]?id)?|sessionid|"
    r"auth[ _-]?session(?:[ _-]?id)?)$"
)
_ARTIFACT_LIMIT = 65_536
_TRANSACTION_LIMIT = 196_608
_VERSION = 1
_STATE_NAMES = ("pending", "granted", "consumed", "expired")
_DIRECTORY_NAMES = (*_STATE_NAMES, "locks", "transactions")
_EVENT_KEYS = frozenset(
    {
        "timestamp",
        "engagement_id",
        "action_id",
        "challenge_digest",
        "effective_risk",
        "result",
        "reason_code",
    }
)
_TRANSACTION_KEYS = frozenset(
    {
        "version",
        "operation",
        "challenge_digest",
        "source",
        "destination",
        "source_checksum",
        "source_identity",
        "artifact",
        "event",
        "transition_at",
    }
)
_ARTIFACT_KEYS = frozenset(
    {
        "action_id",
        "challenge",
        "approved_at",
        "approved_by",
        "challenge_digest",
        "created_at",
        "effective_risk",
        "engagement_id",
        "engagement_path",
        "expires_at",
        "kind",
        "nonce",
        "policy_digest",
        "scope_digest",
        "version",
    }
)
_PENDING_KEYS = _ARTIFACT_KEYS - {"approved_at", "approved_by"}
_GRANT_KEYS = _ARTIFACT_KEYS


class ApprovalError(Exception):
    """A controlled, safe approval failure suitable for a deny decision."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ApprovalReceipt:
    status: str


def canonical_bytes(value: Mapping[str, object]) -> bytes:
    """Encode a JSON object in the one allowed canonical representation."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _utc(value: object, *, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ApprovalError("APPROVAL_INVALID_CLOCK", f"{name} must be an aware UTC timestamp")
    try:
        if value.utcoffset() != timedelta(0):
            raise ApprovalError("APPROVAL_INVALID_CLOCK", f"{name} must be an aware UTC timestamp")
        return value.astimezone(UTC)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ApprovalError(
            "APPROVAL_INVALID_CLOCK", f"{name} must be an aware UTC timestamp"
        ) from exc


def _timestamp(value: datetime) -> str:
    return _utc(value, name="timestamp").isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, *, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ApprovalError("APPROVAL_MALFORMED", f"malformed {name}")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (OverflowError, ValueError) as exc:
        raise ApprovalError("APPROVAL_MALFORMED", f"malformed {name}") from exc
    return _utc(parsed, name=name)


def _scope_snapshot(context: PolicyContext) -> dict[str, tuple[str, ...]]:
    scope = context.scope
    in_scope = getattr(scope, "in_scope", None)
    out_of_scope = getattr(scope, "out_of_scope", None)
    if not isinstance(in_scope, tuple) or not isinstance(out_of_scope, tuple):
        raise ApprovalError("APPROVAL_INVALID_SCOPE", "scope snapshot is malformed")
    if any(not isinstance(item, str) for item in (*in_scope, *out_of_scope)):
        raise ApprovalError("APPROVAL_INVALID_SCOPE", "scope snapshot is malformed")
    return {"in_scope": tuple(sorted(in_scope)), "out_of_scope": tuple(sorted(out_of_scope))}


def _definition_snapshot(definition: ActionDefinition) -> dict[str, object]:
    return {
        "action_id": definition.action_id,
        "minimum_risk": int(definition.minimum_risk),
        "network_access": definition.network_access,
        "low_impact_allowlisted": definition.low_impact_allowlisted,
        "state_changing": definition.state_changing,
        "high_volume": definition.high_volume,
        "touches_third_party": definition.touches_third_party,
        "required_profile": definition.required_profile,
        "tool_id": definition.tool_id,
        "executable": definition.executable,
        "uses_external_tool": definition.uses_external_tool,
        "argv_template": definition.argv_template,
        "vulnerability_types": definition.vulnerability_types,
        "impacts": definition.impacts,
        "automated": definition.automated,
        "authenticated": definition.authenticated,
        "creates_account": definition.creates_account,
        "uses_multiple_accounts": definition.uses_multiple_accounts,
        "out_of_band": definition.out_of_band,
        "honors_required_headers": definition.honors_required_headers,
        "shell_execution": definition.shell_execution,
    }


def _challenge_fields(
    definition: ActionDefinition,
    request: ActionRequest,
    context: PolicyContext,
    *,
    created_at: datetime,
    expires_at: datetime,
    nonce: str,
) -> dict[str, object]:
    scope = _scope_snapshot(context)
    scope_digest = hashlib.sha256(canonical_bytes(scope)).hexdigest()
    risk = request.effective_risk(definition)
    return {
        "version": _VERSION,
        "engagement": {"id": context.engagement_id, "path": context.engagement_path},
        "program_id": context.program_id,
        "definition": _definition_snapshot(definition),
        "request": {
            "action_id": request.action_id,
            "target": request.target,
            "argv": request.argv,
            "hypothesis_id": request.hypothesis_id,
            "rationale": request.rationale,
            "rate": request.rate,
            "concurrency": request.concurrency,
            "data_touched": request.data_touched,
            "expected_impact": request.expected_impact,
            "stop_condition": request.stop_condition,
            "cleanup_plan": request.cleanup_plan,
            "program_rule": request.program_rule,
            "required_headers": request.required_headers,
            "requested_risk": int(request.requested_risk)
            if request.requested_risk is not None
            else None,
        },
        "effective_risk": int(risk),
        "scope": scope,
        "scope_digest": scope_digest,
        "policy_digest": context.policy_digest,
        "created_at": _timestamp(created_at),
        "expires_at": _timestamp(expires_at),
        "nonce": nonce,
    }


def _reject_secrets(value: object) -> None:
    """Reject likely credentials without retaining or echoing their values."""
    if isinstance(value, str):
        if _SECRET_RE.search(value) or _SECRET_NAME_RE.fullmatch(value.strip()):
            raise ApprovalError("APPROVAL_SECRET", "secret-bearing challenge data is not allowed")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _reject_secrets(key)
            _reject_secrets(item)
    elif isinstance(value, (tuple, list)):
        for item in value:
            _reject_secrets(item)


def _validate_context_digest(context: PolicyContext) -> None:
    """Recompute the context's code-owned digest before issuing a challenge."""
    try:
        from hackbot.risk.context import _canonical_policy_data, _policy_digest, _scope_snapshot

        scope_in, scope_out = _scope_snapshot(context.scope.in_scope, context.scope.out_of_scope)
        canonical = _canonical_policy_data(
            engagement_id=context.engagement_id,
            engagement_path=context.engagement_path,
            program_id=context.program_id,
            authorization=context.authorization,
            scope_in=scope_in,
            scope_out=scope_out,
            testing_policy=context.testing_policy,
            active_profile=context.active_profile,
        )
        if _policy_digest(canonical) != context.policy_digest:
            raise ValueError("policy digest mismatch")
    except (AttributeError, TypeError, ValueError, UnicodeError) as exc:
        raise ApprovalError(
            "APPROVAL_INVALID_CONTEXT", "current policy context is invalid"
        ) from exc


def _validate_inputs(
    definition: object, request: object, context: object, now: object, nonce: object
) -> tuple[ActionDefinition, ActionRequest, PolicyContext, datetime, str]:
    if not isinstance(definition, ActionDefinition) or not isinstance(request, ActionRequest):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "invalid challenge input")
    if not isinstance(context, PolicyContext):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "invalid policy context")
    _validate_context_digest(context)
    try:
        definition.validate()
    except ValueError as exc:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "invalid action definition") from exc
    if request.action_id != definition.action_id:
        raise ApprovalError(
            "APPROVAL_INVALID_CHALLENGE", "action definition does not match request"
        )
    if (
        request.engagement_id != context.engagement_id
        or request.engagement_path != context.engagement_path
    ):
        raise ApprovalError(
            "APPROVAL_INVALID_CHALLENGE", "engagement identity does not match context"
        )
    if request.effective_risk(definition) not in (RiskLevel.L2,):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "only L2 actions can be challenged")
    expected_argv = definition.render_argv(request)
    if expected_argv is None or request.argv != expected_argv:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "request argv does not match template")
    if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "nonce must be bounded canonical text")
    _reject_secrets(
        (
            request.argv,
            request.target,
            request.hypothesis_id,
            request.rationale,
            request.data_touched,
            request.expected_impact,
            request.stop_condition,
            request.cleanup_plan,
            request.program_rule,
            request.required_headers,
        )
    )
    try:
        from hackbot.risk.policy import RiskEngine
        from hackbot.risk.registry import ActionRegistry

        decision = RiskEngine(ActionRegistry([definition])).evaluate(
            request, context, now=_utc(now, name="now")
        )
    except (TypeError, ValueError) as exc:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge preflight is invalid") from exc
    if decision.kind.value != "requires-approval":
        raise ApprovalError("APPROVAL_NOT_AUTHORIZED", "action is not otherwise authorized")
    return definition, request, context, _utc(now, name="now"), nonce


def build_challenge(
    definition: ActionDefinition,
    request: ActionRequest,
    context: PolicyContext,
    *,
    now: datetime,
    nonce: str | None = None,
) -> ApprovalChallenge:
    """Create an exact L2 challenge without filesystem, network, or prompt I/O."""
    supplied_nonce = secrets.token_hex(16) if nonce is None else nonce
    definition, request, context, created_at, checked_nonce = _validate_inputs(
        definition, request, context, now, supplied_nonce
    )
    try:
        expires_at = created_at + timedelta(minutes=5)
    except OverflowError as exc:
        raise ApprovalError(
            "APPROVAL_INVALID_CLOCK", "challenge expiry is outside the supported range"
        ) from exc
    try:
        fields = _challenge_fields(
            definition,
            request,
            context,
            created_at=created_at,
            expires_at=expires_at,
            nonce=checked_nonce,
        )
        binding = canonical_bytes(fields)
        digest = hashlib.sha256(binding).hexdigest()
        return ApprovalChallenge(
            engagement_id=context.engagement_id,
            engagement_path=context.engagement_path,
            program_id=context.program_id,
            target=request.target,
            action_id=request.action_id,
            argv=request.argv,
            effective_risk=request.effective_risk(definition),
            rationale=request.rationale,
            hypothesis_id=request.hypothesis_id,
            expected_impact=request.expected_impact,
            rate=request.rate if request.rate is not None else 0,
            concurrency=request.concurrency if request.concurrency is not None else 0,
            data_touched=request.data_touched,
            stop_condition=request.stop_condition,
            program_rule=request.program_rule,
            cleanup_plan=request.cleanup_plan,
            scope_digest=fields["scope_digest"],  # type: ignore[arg-type]
            policy_digest=context.policy_digest,
            created_at=created_at,
            expires_at=expires_at,
            nonce=checked_nonce,
            challenge_digest=digest,
            binding=binding,
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "canonical challenge is invalid") from exc


def _validate_challenge(challenge: object) -> ApprovalChallenge:
    if not isinstance(challenge, ApprovalChallenge):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "invalid approval challenge")
    if not isinstance(challenge.engagement_path, str) or not challenge.engagement_path:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge lacks engagement path")
    if (
        not isinstance(challenge.challenge_digest, str)
        or _DIGEST_RE.fullmatch(challenge.challenge_digest) is None
    ):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge digest is malformed")
    if (
        not isinstance(challenge.policy_digest, str)
        or _DIGEST_RE.fullmatch(challenge.policy_digest) is None
        or not isinstance(challenge.scope_digest, str)
        or _DIGEST_RE.fullmatch(challenge.scope_digest) is None
    ):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge digest is malformed")
    if not isinstance(challenge.nonce, str) or _NONCE_RE.fullmatch(challenge.nonce) is None:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge nonce is malformed")
    if (
        not isinstance(challenge.binding, bytes)
        or not challenge.binding
        or len(challenge.binding) > _ARTIFACT_LIMIT
    ):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding is malformed")
    try:
        binding = strict_json_loads(challenge.binding.decode("utf-8"))
    except (
        DuplicateJSONKeyError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding is malformed") from exc
    if not isinstance(binding, dict):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding is malformed")
    try:
        canonical_binding = canonical_bytes(binding)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding is malformed") from exc
    if canonical_binding != challenge.binding:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding is malformed")
    if hashlib.sha256(challenge.binding).hexdigest() != challenge.challenge_digest:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding digest is malformed")
    request = binding.get("request")
    engagement = binding.get("engagement")
    if binding.get("policy_digest") != challenge.policy_digest:
        raise ApprovalError("APPROVAL_POLICY_MISMATCH", "challenge policy binding does not match")
    if binding.get("scope_digest") != challenge.scope_digest:
        raise ApprovalError("APPROVAL_MISMATCH", "challenge scope binding does not match")
    try:
        mismatch = (
            not isinstance(request, dict)
            or not isinstance(engagement, dict)
            or engagement.get("id") != challenge.engagement_id
            or engagement.get("path") != challenge.engagement_path
            or binding.get("program_id") != challenge.program_id
            or request.get("target") != challenge.target
            or tuple(request.get("argv", ())) != challenge.argv
            or request.get("action_id") != challenge.action_id
            or request.get("rationale") != challenge.rationale
            or request.get("hypothesis_id") != challenge.hypothesis_id
            or request.get("expected_impact") != challenge.expected_impact
            or request.get("rate") != challenge.rate
            or request.get("concurrency") != challenge.concurrency
            or request.get("data_touched") != challenge.data_touched
            or request.get("stop_condition") != challenge.stop_condition
            or request.get("program_rule") != challenge.program_rule
            or request.get("cleanup_plan") != challenge.cleanup_plan
            or binding.get("effective_risk") != int(challenge.effective_risk)
            or binding.get("created_at") != _timestamp(challenge.created_at)
            or binding.get("expires_at") != _timestamp(challenge.expires_at)
            or binding.get("nonce") != challenge.nonce
        )
    except (OverflowError, TypeError, ValueError) as exc:
        raise ApprovalError(
            "APPROVAL_INVALID_CHALLENGE", "challenge binding does not match"
        ) from exc
    if mismatch:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding does not match")
    created_at = _utc(challenge.created_at, name="challenge.created_at")
    expires_at = _utc(challenge.expires_at, name="challenge.expires_at")
    try:
        expected_expiry = created_at + timedelta(minutes=5)
    except OverflowError as exc:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge expiry is malformed") from exc
    if expires_at != expected_expiry:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge expiry is malformed")
    if challenge.effective_risk is not RiskLevel.L2:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge risk is malformed")
    return challenge


@dataclass(slots=True)
class _Layout:
    root: int
    directories: dict[str, int]

    def directory(self, name: str) -> int:
        try:
            return self.directories[name]
        except KeyError as exc:
            raise ApprovalError("APPROVAL_UNSAFE_PATH", "invalid approval state") from exc

    def close(self) -> None:
        failure: OSError | None = None
        for fd in self.directories.values():
            try:
                os.close(fd)
            except OSError as exc:
                failure = failure or exc
        try:
            os.close(self.root)
        except OSError as exc:
            failure = failure or exc
        if failure is not None:
            raise failure


@dataclass(frozen=True, slots=True)
class _Record:
    value: dict[str, object]
    raw: bytes
    identity: tuple[int, int]


class ApprovalStore:
    """Descriptor-owned, engagement-local, no-overwrite L2 persistence."""

    def __init__(self, engagement_dir: str | Path) -> None:
        engagement_fd: int | None = None
        try:
            self.engagement_path, self.engagement_id = canonical_engagement_identity(engagement_dir)
            engagement_fd = os.open(
                self.engagement_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            info = os.fstat(engagement_fd)
            path_info = os.stat(self.engagement_path, follow_symlinks=False)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
            ):
                raise OSError("unsafe engagement directory")
        except (EngagementIdentityError, OSError) as exc:
            if engagement_fd is not None:
                try:
                    os.close(engagement_fd)
                except OSError:
                    pass
            raise ApprovalError(
                "APPROVAL_INVALID_ENGAGEMENT", "invalid engagement directory"
            ) from exc
        assert engagement_fd is not None
        self._engagement_fd: int | None = engagement_fd
        self.root = str(Path(self.engagement_path) / "approvals")

    def close(self) -> None:
        """Release the descriptor anchoring the canonical engagement directory."""
        fd = getattr(self, "_engagement_fd", None)
        self._engagement_fd = None
        if fd is not None:
            os.close(fd)

    def __enter__(self) -> ApprovalStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    @staticmethod
    def _name(digest: str) -> str:
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge digest is malformed")
        return digest + ".json"

    @staticmethod
    def _identity(info: os.stat_result) -> tuple[int, int]:
        return info.st_dev, info.st_ino

    @staticmethod
    def _validate_directory(info: os.stat_result) -> None:
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()
        ):
            raise ApprovalError("APPROVAL_UNSAFE_PATH", "approval directory is unsafe")

    @staticmethod
    def _validate_regular(
        info: os.stat_result,
        *,
        limit: int,
        code: str,
        message: str,
    ) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_size > limit
        ):
            raise ApprovalError(code, message)

    @classmethod
    def _open_directory(cls, parent_fd: int, name: str) -> int:
        created = False
        try:
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                created = True
            except FileExistsError:
                pass
            fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
            if created:
                os.fchmod(fd, 0o700)
            cls._validate_directory(os.fstat(fd))
            if created:
                os.fsync(parent_fd)
            return fd
        except ApprovalError:
            if "fd" in locals():
                os.close(fd)
            raise
        except OSError as exc:
            if "fd" in locals():
                os.close(fd)
            raise ApprovalError(
                "APPROVAL_UNSAFE_PATH",
                "approval directory is unsafe or is a symlink",
            ) from exc

    @contextmanager
    def _layout(self) -> Iterator[_Layout]:
        engagement_fd = self._engagement_fd
        if engagement_fd is None:
            raise ApprovalError("APPROVAL_IO", "approval store is closed")
        root_fd: int | None = None
        directories: dict[str, int] = {}
        try:
            root_fd = self._open_directory(engagement_fd, "approvals")
            for name in _DIRECTORY_NAMES:
                directories[name] = self._open_directory(root_fd, name)
            layout = _Layout(root_fd, directories)
            root_fd = None
            directories = {}
            try:
                yield layout
            finally:
                layout.close()
        except ApprovalError:
            raise
        except OSError as exc:
            raise ApprovalError("APPROVAL_IO", "approval layout operation failed") from exc
        finally:
            for fd in directories.values():
                os.close(fd)
            if root_fd is not None:
                os.close(root_fd)

    def _assert_local(self, challenge: ApprovalChallenge) -> None:
        _validate_challenge(challenge)
        if (
            challenge.engagement_id != self.engagement_id
            or challenge.engagement_path != self.engagement_path
        ):
            raise ApprovalError(
                "APPROVAL_ENGAGEMENT_MISMATCH", "challenge engagement does not match store"
            )

    @staticmethod
    def _crash_point(_phase: str) -> None:
        """No-op fault-injection seam used to test transaction recovery."""

    @classmethod
    def _entry_info(
        cls,
        directory_fd: int,
        name: str,
        *,
        limit: int,
        code: str,
        message: str,
    ) -> os.stat_result | None:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ApprovalError(code, message) from exc
        cls._validate_regular(info, limit=limit, code=code, message=message)
        return info

    @classmethod
    def _read_json(
        cls,
        directory_fd: int,
        name: str,
        *,
        limit: int,
        code: str,
        message: str,
    ) -> _Record:
        fd: int | None = None
        try:
            fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            info = os.fstat(fd)
            cls._validate_regular(info, limit=limit, code=code, message=message)
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 65_536))
                if not chunk:
                    raise OSError("short approval record read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.fstat(fd).st_size != info.st_size:
                raise OSError("approval record changed during read")
            raw = b"".join(chunks)
            value = strict_json_loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or canonical_bytes(value) != raw:
                raise ValueError("non-canonical approval record")
            return _Record(value, raw, cls._identity(info))
        except ApprovalError:
            raise
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            DuplicateJSONKeyError,
            ValueError,
            RecursionError,
        ) as exc:
            raise ApprovalError(code, message) from exc
        finally:
            if fd is not None:
                os.close(fd)

    @classmethod
    def _write_exclusive(
        cls,
        directory_fd: int,
        name: str,
        value: Mapping[str, object],
        *,
        exists_code: str = "APPROVAL_EXISTS",
        exists_message: str = "approval record already exists",
    ) -> tuple[int, int]:
        payload = canonical_bytes(value)
        fd: int | None = None
        identity: tuple[int, int] | None = None
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
            os.fchmod(fd, 0o600)
            identity = cls._identity(os.fstat(fd))
            view = memoryview(payload)
            while view:
                wrote = os.write(fd, view)
                if wrote <= 0:
                    raise OSError("short approval record write")
                view = view[wrote:]
            os.fsync(fd)
            os.fsync(directory_fd)
            return identity
        except FileExistsError as exc:
            raise ApprovalError(exists_code, exists_message) from exc
        except (OSError, ValueError, TypeError) as exc:
            if identity is not None:
                try:
                    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if cls._identity(current) == identity:
                        os.unlink(name, dir_fd=directory_fd)
                        os.fsync(directory_fd)
                except OSError:
                    pass
            raise ApprovalError("APPROVAL_IO", "approval record write failed") from exc
        finally:
            if fd is not None:
                os.close(fd)

    @classmethod
    def _verify_identity(
        cls,
        directory_fd: int,
        name: str,
        expected: tuple[int, int],
        *,
        code: str = "APPROVAL_UNSAFE_PATH",
        message: str = "approval record changed during operation",
    ) -> os.stat_result:
        info = cls._entry_info(
            directory_fd,
            name,
            limit=_TRANSACTION_LIMIT,
            code=code,
            message=message,
        )
        if info is None or cls._identity(info) != expected:
            raise ApprovalError(code, message)
        return info

    @classmethod
    def _unlink_verified(
        cls,
        directory_fd: int,
        name: str,
        identity: tuple[int, int],
    ) -> None:
        cls._verify_identity(directory_fd, name, identity)
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)

    @staticmethod
    def _artifact(
        challenge: ApprovalChallenge, *, kind: str, grant: ApprovalGrant | None = None
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "version": _VERSION,
            "kind": kind,
            "challenge_digest": challenge.challenge_digest,
            "challenge": strict_json_loads(challenge.binding.decode("utf-8")),
            "engagement_id": challenge.engagement_id,
            "engagement_path": challenge.engagement_path,
            "action_id": challenge.action_id,
            "effective_risk": int(challenge.effective_risk),
            "policy_digest": challenge.policy_digest,
            "scope_digest": challenge.scope_digest,
            "created_at": _timestamp(challenge.created_at),
            "expires_at": _timestamp(challenge.expires_at),
            "nonce": challenge.nonce,
        }
        if grant is not None:
            value["approved_by"] = grant.approved_by
            value["approved_at"] = _timestamp(grant.approved_at)
        return value

    @staticmethod
    def _validate_artifact_value(
        value: dict[str, object], *, allowed_kinds: frozenset[str]
    ) -> None:
        kind = value.get("kind")
        if (
            not isinstance(kind, str)
            or kind not in allowed_kinds
            or set(value) != (_PENDING_KEYS if kind == "pending" else _GRANT_KEYS)
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        if value.get("version") != _VERSION:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        for key in ("challenge_digest", "policy_digest", "scope_digest"):
            digest = value.get(key)
            if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
                raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        if not isinstance(value.get("engagement_id"), str) or not isinstance(
            value.get("engagement_path"), str
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        if not isinstance(value.get("action_id"), str) or value.get("effective_risk") != int(
            RiskLevel.L2
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        nonce = value.get("nonce")
        if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        binding = value.get("challenge")
        if not isinstance(binding, dict):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        try:
            binding_bytes = canonical_bytes(binding)
            request = binding.get("request")
            engagement = binding.get("engagement")
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact") from exc
        if (
            hashlib.sha256(binding_bytes).hexdigest() != value["challenge_digest"]
            or not isinstance(request, dict)
            or not isinstance(engagement, dict)
            or engagement.get("id") != value["engagement_id"]
            or engagement.get("path") != value["engagement_path"]
            or request.get("action_id") != value["action_id"]
            or binding.get("effective_risk") != value["effective_risk"]
            or binding.get("policy_digest") != value["policy_digest"]
            or binding.get("scope_digest") != value["scope_digest"]
            or binding.get("created_at") != value["created_at"]
            or binding.get("expires_at") != value["expires_at"]
            or binding.get("nonce") != value["nonce"]
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        try:
            created_at = _parse_timestamp(value.get("created_at"), name="created_at")
            expires_at = _parse_timestamp(value.get("expires_at"), name="expires_at")
            if expires_at != created_at + timedelta(minutes=5):
                raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
            if kind == "granted":
                approved_by = value.get("approved_by")
                approved_at = _parse_timestamp(value.get("approved_at"), name="approved_at")
                if (
                    not isinstance(approved_by, str)
                    or _APPROVED_BY_RE.fullmatch(approved_by) is None
                    or not created_at <= approved_at < expires_at
                ):
                    raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        except (OverflowError, TypeError, ValueError) as exc:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact") from exc

    def _read_artifact(self, layout: _Layout, state: str, digest: str) -> _Record:
        allowed = {
            "pending": frozenset({"pending"}),
            "granted": frozenset({"granted"}),
            "consumed": frozenset({"granted"}),
            "expired": frozenset({"pending", "granted"}),
        }[state]
        record = self._read_json(
            layout.directory(state),
            self._name(digest),
            limit=_ARTIFACT_LIMIT,
            code="APPROVAL_MALFORMED",
            message="malformed approval artifact",
        )
        self._validate_artifact_value(record.value, allowed_kinds=allowed)
        if record.value["challenge_digest"] != digest:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        return record

    @staticmethod
    def _matches(challenge: ApprovalChallenge, artifact: Mapping[str, object]) -> bool:
        expected = ApprovalStore._artifact(challenge, kind=str(artifact["kind"]))
        return all(
            artifact.get(key) == value
            for key, value in expected.items()
            if key not in {"approved_at", "approved_by"}
        )

    @staticmethod
    def _event(
        challenge: ApprovalChallenge, *, result: str, reason_code: str, now: datetime
    ) -> dict[str, object]:
        if (
            _EVENT_RESULT_RE.fullmatch(result) is None
            or _EVENT_REASON_RE.fullmatch(reason_code) is None
        ):
            raise ApprovalError("APPROVAL_INVALID_EVENT", "invalid approval event")
        return {
            "timestamp": _timestamp(_utc(now, name="now")),
            "engagement_id": challenge.engagement_id,
            "action_id": challenge.action_id,
            "challenge_digest": challenge.challenge_digest,
            "effective_risk": int(challenge.effective_risk),
            "result": result,
            "reason_code": reason_code,
        }

    @staticmethod
    def _validate_event(event: object, *, digest: str | None = None) -> dict[str, object]:
        if not isinstance(event, dict) or set(event) != _EVENT_KEYS:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        try:
            _parse_timestamp(event.get("timestamp"), name="event timestamp")
        except ApprovalError as exc:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction") from exc
        if (
            not isinstance(event.get("engagement_id"), str)
            or _DIGEST_RE.fullmatch(event["engagement_id"]) is None
            or not isinstance(event.get("action_id"), str)
            or _APPROVED_BY_RE.fullmatch(event["action_id"]) is None
            or not isinstance(event.get("challenge_digest"), str)
            or _DIGEST_RE.fullmatch(event["challenge_digest"]) is None
            or event.get("effective_risk") != int(RiskLevel.L2)
            or not isinstance(event.get("result"), str)
            or _EVENT_RESULT_RE.fullmatch(event["result"]) is None
            or not isinstance(event.get("reason_code"), str)
            or _EVENT_REASON_RE.fullmatch(event["reason_code"]) is None
            or (digest is not None and event["challenge_digest"] != digest)
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        return event

    @staticmethod
    def _contains_line(fd: int, payload: bytes) -> bool:
        os.lseek(fd, 0, os.SEEK_SET)
        carry = b""
        needle = payload.removesuffix(b"\n")
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                return carry == needle
            parts = (carry + chunk).split(b"\n")
            carry = parts.pop()
            if needle in parts:
                return True

    def _append_event_record(
        self, layout: _Layout, event: dict[str, object], *, idempotent: bool
    ) -> None:
        import fcntl

        self._validate_event(event)
        payload = canonical_bytes(event) + b"\n"
        fd: int | None = None
        created = False
        try:
            try:
                fd = os.open(
                    "events.jsonl",
                    os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=layout.root,
                )
                created = True
                os.fchmod(fd, 0o600)
            except FileExistsError:
                fd = os.open(
                    "events.jsonl",
                    os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=layout.root,
                )
            self._validate_regular(
                os.fstat(fd),
                limit=sys.maxsize,
                code="APPROVAL_UNSAFE_PATH",
                message="approval audit path is unsafe",
            )
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._validate_regular(
                os.fstat(fd),
                limit=sys.maxsize,
                code="APPROVAL_UNSAFE_PATH",
                message="approval audit path is unsafe",
            )
            if not idempotent or not self._contains_line(fd, payload):
                if os.write(fd, payload) != len(payload):
                    raise OSError("short audit write")
                self._crash_point("after_event_write")
            os.fsync(fd)
            if created:
                os.fsync(layout.root)
        except ApprovalError:
            raise
        except OSError as exc:
            raise ApprovalError("APPROVAL_IO", "approval audit write failed") from exc
        finally:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(fd)

    @contextmanager
    def _digest_lock(self, layout: _Layout, digest: str) -> Iterator[None]:
        import fcntl

        name = self._name(digest) + ".lock"
        lock_dir = layout.directory("locks")
        fd: int | None = None
        try:
            try:
                fd = os.open(
                    name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=lock_dir,
                )
                os.fchmod(fd, 0o600)
                os.fsync(lock_dir)
            except FileExistsError:
                fd = os.open(
                    name,
                    os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=lock_dir,
                )
            self._validate_regular(
                os.fstat(fd),
                limit=0,
                code="APPROVAL_UNSAFE_PATH",
                message="approval lock path is unsafe",
            )
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._validate_regular(
                os.fstat(fd),
                limit=0,
                code="APPROVAL_UNSAFE_PATH",
                message="approval lock path is unsafe",
            )
            yield
        except ApprovalError:
            raise
        except OSError as exc:
            raise ApprovalError("APPROVAL_IO", "approval lock failed") from exc
        finally:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(fd)

    @staticmethod
    def _rename_noreplace(
        source_fd: int, source: str, destination_fd: int, destination: str
    ) -> None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            if sys.platform == "darwin":
                rename = libc.renameatx_np
            elif sys.platform.startswith("linux"):
                rename = libc.renameat2
            else:
                raise ApprovalError(
                    "APPROVAL_UNSAFE_PATH", "atomic no-overwrite rename is unavailable"
                )
        except (AttributeError, OSError) as exc:
            raise ApprovalError(
                "APPROVAL_UNSAFE_PATH", "atomic no-overwrite rename is unavailable"
            ) from exc
        if sys.platform == "darwin":
            rename.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            rename.restype = ctypes.c_int
            result = rename(
                source_fd,
                os.fsencode(source),
                destination_fd,
                os.fsencode(destination),
                0x00000004,
            )
        else:
            rename.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            rename.restype = ctypes.c_int
            result = rename(
                source_fd,
                os.fsencode(source),
                destination_fd,
                os.fsencode(destination),
                0x00000001,
            )
        if result != 0:
            error = ctypes.get_errno()
            if error in {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP}:
                raise ApprovalError(
                    "APPROVAL_UNSAFE_PATH", "atomic no-overwrite rename is unavailable"
                )
            raise OSError(error, os.strerror(error))

    @staticmethod
    def _checksum(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    def _state_locked(self, layout: _Layout, digest: str) -> tuple[str, _Record] | None:
        found: list[tuple[str, _Record]] = []
        name = self._name(digest)
        for state in _STATE_NAMES:
            info = self._entry_info(
                layout.directory(state),
                name,
                limit=_ARTIFACT_LIMIT,
                code="APPROVAL_MALFORMED",
                message="malformed approval artifact",
            )
            if info is not None:
                found.append((state, self._read_artifact(layout, state, digest)))
        if len(found) > 1:
            raise ApprovalError("APPROVAL_MALFORMED", "approval has multiple states")
        return found[0] if found else None

    def _transaction(
        self,
        challenge: ApprovalChallenge,
        *,
        operation: str,
        source: str | None,
        destination: str,
        source_record: _Record | None,
        artifact: dict[str, object],
        result: str,
        reason_code: str,
        event_at: datetime,
    ) -> dict[str, object]:
        return {
            "version": _VERSION,
            "operation": operation,
            "challenge_digest": challenge.challenge_digest,
            "source": source,
            "destination": destination,
            "source_checksum": self._checksum(source_record.raw)
            if source_record is not None
            else None,
            "source_identity": list(source_record.identity) if source_record is not None else None,
            "artifact": artifact,
            "event": self._event(challenge, result=result, reason_code=reason_code, now=event_at),
            "transition_at": _timestamp(event_at),
        }

    def _validate_transaction(
        self, layout: _Layout, value: dict[str, object], digest: str
    ) -> dict[str, object]:
        if (
            set(value) == {"version", "source", "destination", "challenge_digest"}
            and value.get("version") == _VERSION
        ):
            return self._upgrade_legacy_transaction(layout, value, digest)
        if set(value) == _TRANSACTION_KEYS - {"transition_at"}:
            legacy_event = value.get("event")
            value = {
                **value,
                "transition_at": legacy_event.get("timestamp")
                if isinstance(legacy_event, dict)
                else None,
            }
        if (
            set(value) != _TRANSACTION_KEYS
            or value.get("version") != _VERSION
            or value.get("challenge_digest") != digest
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        operation = value.get("operation")
        source = value.get("source")
        destination = value.get("destination")
        allowed = {
            "create": (None, "pending"),
            "grant": ("pending", "granted"),
            "consume": ("granted", "consumed"),
            "expire-pending": ("pending", "expired"),
            "expire-granted": ("granted", "expired"),
        }
        if (
            not isinstance(operation, str)
            or operation not in allowed
            or (source, destination) != allowed[operation]
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        checksum = value.get("source_checksum")
        identity = value.get("source_identity")
        if (source is None and checksum is not None) or (
            source is not None
            and (not isinstance(checksum, str) or _DIGEST_RE.fullmatch(checksum) is None)
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        if (source is None and identity is not None) or (
            source is not None
            and (
                not isinstance(identity, list)
                or len(identity) != 2
                or any(
                    isinstance(item, bool) or not isinstance(item, int) or item < 0
                    for item in identity
                )
            )
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        artifact = value.get("artifact")
        if not isinstance(artifact, dict):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        expected_kinds = {
            "create": frozenset({"pending"}),
            "grant": frozenset({"granted"}),
            "consume": frozenset({"granted"}),
            "expire-pending": frozenset({"pending"}),
            "expire-granted": frozenset({"granted"}),
        }
        self._validate_artifact_value(artifact, allowed_kinds=expected_kinds[operation])
        if artifact["challenge_digest"] != digest:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        event = self._validate_event(value.get("event"), digest=digest)
        expected_events = {
            "create": ("created", "CREATED"),
            "grant": ("granted", "GRANTED"),
            "consume": ("consumed", "CONSUMED"),
            "expire-pending": ("expired", "EXPIRED"),
            "expire-granted": ("expired", "EXPIRED"),
        }
        transition_value = value.get("transition_at")
        try:
            transition_at = _parse_timestamp(transition_value, name="transition timestamp")
            created_at = _parse_timestamp(artifact.get("created_at"), name="created_at")
            expires_at = _parse_timestamp(artifact.get("expires_at"), name="expires_at")
            if (
                (event["result"], event["reason_code"]) != expected_events[operation]
                or event["engagement_id"] != artifact["engagement_id"]
                or event["action_id"] != artifact["action_id"]
                or event["challenge_digest"] != artifact["challenge_digest"]
                or event["effective_risk"] != artifact["effective_risk"]
                or event["timestamp"] != transition_value
            ):
                raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
            if operation == "create" and transition_at != created_at:
                raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
            if operation == "grant":
                approved_at = _parse_timestamp(artifact.get("approved_at"), name="approved_at")
                if transition_at != approved_at:
                    raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
            if operation.startswith("expire-") and transition_at != expires_at:
                raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
            if operation == "consume":
                approved_at = _parse_timestamp(artifact.get("approved_at"), name="approved_at")
                if not approved_at <= transition_at < expires_at:
                    raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        except (OverflowError, TypeError, ValueError) as exc:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction") from exc
        return value

    def _upgrade_legacy_transaction(
        self, layout: _Layout, value: dict[str, object], digest: str
    ) -> dict[str, object]:
        source = value.get("source")
        destination = value.get("destination")
        if not isinstance(source, str) or not isinstance(destination, str):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        operations = {
            ("pending", "granted"): "grant",
            ("granted", "consumed"): "consume",
            ("pending", "expired"): "expire-pending",
            ("granted", "expired"): "expire-granted",
        }
        operation = operations.get((source, destination))
        if value.get("challenge_digest") != digest or operation is None:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        source_record = (
            self._read_artifact(layout, source, digest)
            if self._entry_info(
                layout.directory(source),
                self._name(digest),
                limit=_ARTIFACT_LIMIT,
                code="APPROVAL_MALFORMED",
                message="malformed approval artifact",
            )
            is not None
            else None
        )
        destination_record = (
            self._read_artifact(layout, destination, digest)
            if self._entry_info(
                layout.directory(destination),
                self._name(digest),
                limit=_ARTIFACT_LIMIT,
                code="APPROVAL_MALFORMED",
                message="malformed approval artifact",
            )
            is not None
            else None
        )
        record = destination_record or source_record
        if record is None:
            raise ApprovalError("APPROVAL_MALFORMED", "approval transaction lost state")
        artifact = record.value
        when = artifact.get("approved_at") or artifact.get("created_at")
        if destination == "expired":
            when = artifact.get("expires_at")
        event = {
            "timestamp": when,
            "engagement_id": artifact["engagement_id"],
            "action_id": artifact["action_id"],
            "challenge_digest": digest,
            "effective_risk": int(RiskLevel.L2),
            "result": destination,
            "reason_code": destination.upper(),
        }
        upgraded = {
            "version": _VERSION,
            "operation": operation,
            "challenge_digest": digest,
            "source": source,
            "destination": destination,
            "source_checksum": self._checksum(source_record.raw)
            if source_record is not None
            else self._checksum(record.raw),
            "source_identity": list(
                source_record.identity if source_record is not None else record.identity
            ),
            "artifact": artifact,
            "event": event,
            "transition_at": when,
        }
        return self._validate_transaction(layout, upgraded, digest)

    def _read_transaction(self, layout: _Layout, digest: str) -> _Record | None:
        name = self._name(digest) + ".json"
        info = self._entry_info(
            layout.directory("transactions"),
            name,
            limit=_TRANSACTION_LIMIT,
            code="APPROVAL_MALFORMED",
            message="malformed approval transaction",
        )
        if info is None:
            return None
        record = self._read_json(
            layout.directory("transactions"),
            name,
            limit=_TRANSACTION_LIMIT,
            code="APPROVAL_MALFORMED",
            message="malformed approval transaction",
        )
        self._validate_transaction(layout, record.value, digest)
        return record

    def _apply_transaction_locked(
        self,
        layout: _Layout,
        transaction: dict[str, object],
        journal_identity: tuple[int, int],
        *,
        inject_crashes: bool,
    ) -> None:
        digest = str(transaction["challenge_digest"])
        name = self._name(digest)
        source_value = transaction["source"]
        destination_value = transaction["destination"]
        if (
            source_value is not None
            and not isinstance(source_value, str)
            or not isinstance(destination_value, str)
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        source: str | None = source_value
        destination = destination_value
        operation = str(transaction["operation"])
        artifact = transaction["artifact"]
        event = transaction["event"]
        if not isinstance(artifact, dict) or not isinstance(event, dict):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval transaction")
        desired_raw = canonical_bytes(artifact)
        desired_checksum = self._checksum(desired_raw)

        state_records: dict[str, _Record] = {}
        for state in _STATE_NAMES:
            if (
                self._entry_info(
                    layout.directory(state),
                    name,
                    limit=_ARTIFACT_LIMIT,
                    code="APPROVAL_MALFORMED",
                    message="malformed approval artifact",
                )
                is not None
            ):
                state_records[state] = self._read_artifact(layout, state, digest)
        if any(state not in {source, destination} for state in state_records):
            raise ApprovalError("APPROVAL_MALFORMED", "approval has multiple states")
        source_record = state_records.get(str(source)) if source is not None else None
        destination_record = state_records.get(destination)
        source_checksum = transaction["source_checksum"]
        source_identity_value = transaction["source_identity"]
        source_identity = (
            tuple(source_identity_value) if isinstance(source_identity_value, list) else None
        )
        if source_record is not None and self._checksum(source_record.raw) != source_checksum:
            raise ApprovalError("APPROVAL_MALFORMED", "approval source was tampered")
        if source_record is not None and source_record.identity != source_identity:
            raise ApprovalError("APPROVAL_UNSAFE_PATH", "approval source inode changed")
        if (
            destination_record is not None
            and self._checksum(destination_record.raw) != desired_checksum
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "approval destination was tampered")
        if source is None and any(state != destination for state in state_records):
            raise ApprovalError("APPROVAL_MALFORMED", "approval has multiple states")

        if destination_record is None:
            if operation == "create":
                self._write_exclusive(layout.directory(destination), name, artifact)
            elif operation == "grant":
                if source_record is None:
                    raise ApprovalError("APPROVAL_MALFORMED", "approval transaction lost state")
                self._write_exclusive(layout.directory(destination), name, artifact)
            else:
                if source_record is None or source is None:
                    raise ApprovalError("APPROVAL_MALFORMED", "approval transaction lost state")
                if inject_crashes:
                    self._crash_point("before_rename")
                self._verify_identity(
                    layout.directory(source),
                    name,
                    source_record.identity,
                )
                if (
                    self._entry_info(
                        layout.directory(destination),
                        name,
                        limit=_ARTIFACT_LIMIT,
                        code="APPROVAL_CONSUMED",
                        message="approval destination already exists",
                    )
                    is not None
                ):
                    raise ApprovalError("APPROVAL_CONSUMED", "approval destination already exists")
                if inject_crashes:
                    self._crash_point("after_destination_check")
                try:
                    self._rename_noreplace(
                        layout.directory(source),
                        name,
                        layout.directory(destination),
                        name,
                    )
                except OSError as exc:
                    code = (
                        "APPROVAL_CONSUMED"
                        if exc.errno in {errno.EEXIST, errno.ENOENT}
                        else "APPROVAL_IO"
                    )
                    raise ApprovalError(code, "approval state transition failed") from exc
                if inject_crashes:
                    self._crash_point("after_rename")
                os.fsync(layout.directory(source))
                os.fsync(layout.directory(destination))
                moved = self._read_artifact(layout, destination, digest)
                if moved.identity != source_record.identity:
                    raise ApprovalError(
                        "APPROVAL_UNSAFE_PATH", "approval source changed during rename"
                    )
            if inject_crashes:
                self._crash_point("after_destination")
            destination_record = self._read_artifact(layout, destination, digest)
            if self._checksum(destination_record.raw) != desired_checksum:
                raise ApprovalError("APPROVAL_MALFORMED", "approval destination was tampered")

        if source is not None and operation == "grant":
            source_record = (
                self._read_artifact(layout, str(source), digest)
                if self._entry_info(
                    layout.directory(str(source)),
                    name,
                    limit=_ARTIFACT_LIMIT,
                    code="APPROVAL_MALFORMED",
                    message="malformed approval artifact",
                )
                is not None
                else None
            )
            if source_record is not None:
                if self._checksum(source_record.raw) != source_checksum:
                    raise ApprovalError("APPROVAL_MALFORMED", "approval source was tampered")
                self._verify_identity(layout.directory(str(source)), name, source_record.identity)
                os.unlink(name, dir_fd=layout.directory(str(source)))
                if inject_crashes:
                    self._crash_point("after_source_unlink")
                os.fsync(layout.directory(str(source)))
        elif source is not None and source in state_records and destination in state_records:
            duplicate = state_records[str(source)]
            if self._checksum(duplicate.raw) != source_checksum:
                raise ApprovalError("APPROVAL_MALFORMED", "approval source was tampered")
            self._unlink_verified(layout.directory(str(source)), name, duplicate.identity)

        if source is not None:
            os.fsync(layout.directory(source))
        os.fsync(layout.directory(destination))
        self._append_event_record(layout, event, idempotent=True)
        if inject_crashes:
            self._crash_point("after_event")
        journal_name = self._name(digest) + ".json"
        self._verify_identity(layout.directory("transactions"), journal_name, journal_identity)
        os.unlink(journal_name, dir_fd=layout.directory("transactions"))
        if inject_crashes:
            self._crash_point("after_journal_unlink")
        os.fsync(layout.directory("transactions"))

    def _recover_locked(self, layout: _Layout, digest: str) -> None:
        record = self._read_transaction(layout, digest)
        if record is None:
            return
        transaction = self._validate_transaction(layout, record.value, digest)
        self._apply_transaction_locked(layout, transaction, record.identity, inject_crashes=False)

    def _run_transaction_locked(self, layout: _Layout, transaction: dict[str, object]) -> None:
        digest = str(transaction["challenge_digest"])
        self._validate_transaction(layout, transaction, digest)
        journal_name = self._name(digest) + ".json"
        identity = self._write_exclusive(
            layout.directory("transactions"),
            journal_name,
            transaction,
            exists_code="APPROVAL_MALFORMED",
            exists_message="approval transaction already exists",
        )
        self._crash_point("after_wal")
        self._apply_transaction_locked(layout, transaction, identity, inject_crashes=True)

    def _audit_rejection(
        self,
        layout: _Layout,
        challenge: ApprovalChallenge,
        error: ApprovalError,
        *,
        now: datetime,
    ) -> None:
        event = self._event(
            challenge,
            result="rejected",
            reason_code=error.code,
            now=now,
        )
        self._append_event_record(layout, event, idempotent=False)

    def _audit_prevalidation_rejection(
        self,
        challenge: object,
        error: ApprovalError,
        *,
        now: object,
    ) -> None:
        """Audit a tampered but safely projectable local challenge without recursion."""
        if (
            not isinstance(challenge, ApprovalChallenge)
            or challenge.engagement_id != self.engagement_id
            or challenge.engagement_path != self.engagement_path
            or _DIGEST_RE.fullmatch(challenge.challenge_digest) is None
            or _APPROVED_BY_RE.fullmatch(challenge.action_id) is None
            or challenge.effective_risk is not RiskLevel.L2
        ):
            return
        try:
            event_at = _utc(now, name="now")
            event = self._event(
                challenge,
                result="rejected",
                reason_code=error.code,
                now=event_at,
            )
            with self._layout() as layout:
                self._append_event_record(layout, event, idempotent=False)
        except ApprovalError as audit_error:
            if audit_error.code == "APPROVAL_INVALID_CLOCK":
                return
            raise

    def create_pending(
        self,
        definition: ActionDefinition | ApprovalChallenge,
        request: ActionRequest | None = None,
        context: PolicyContext | None = None,
        *,
        now: datetime | None = None,
        nonce: str | None = None,
    ) -> Path:
        """Issue a pending record only from current trusted policy inputs."""
        if (
            not isinstance(definition, ActionDefinition)
            or not isinstance(request, ActionRequest)
            or not isinstance(context, PolicyContext)
            or now is None
        ):
            raise ApprovalError(
                "APPROVAL_TRUSTED_INPUTS_REQUIRED",
                "trusted definition, request, context, and clock are required",
            )
        challenge = build_challenge(definition, request, context, now=now, nonce=nonce)
        self._assert_local(challenge)
        with self._layout() as layout:
            try:
                with self._digest_lock(layout, challenge.challenge_digest):
                    self._recover_locked(layout, challenge.challenge_digest)
                    if self._state_locked(layout, challenge.challenge_digest) is not None:
                        raise ApprovalError("APPROVAL_EXISTS", "approval record already exists")
                    artifact = self._artifact(challenge, kind="pending")
                    transaction = self._transaction(
                        challenge,
                        operation="create",
                        source=None,
                        destination="pending",
                        source_record=None,
                        artifact=artifact,
                        result="created",
                        reason_code="CREATED",
                        event_at=challenge.created_at,
                    )
                    self._run_transaction_locked(layout, transaction)
            except ApprovalError as error:
                self._audit_rejection(layout, challenge, error, now=challenge.created_at)
                raise
        return Path(self.root) / "pending" / self._name(challenge.challenge_digest)

    def grant(
        self, challenge: ApprovalChallenge, *, approved_by: str, now: datetime
    ) -> ApprovalGrant:
        try:
            self._assert_local(challenge)
        except ApprovalError as error:
            self._audit_prevalidation_rejection(challenge, error, now=now)
            raise
        granted_at = _utc(now, name="now")
        with self._layout() as layout:
            try:
                with self._digest_lock(layout, challenge.challenge_digest):
                    self._recover_locked(layout, challenge.challenge_digest)
                    if _APPROVED_BY_RE.fullmatch(approved_by) is None:
                        raise ApprovalError(
                            "APPROVAL_INVALID_OPERATOR", "operator label is invalid"
                        )
                    if granted_at < challenge.created_at:
                        raise ApprovalError(
                            "APPROVAL_INVALID_CLOCK",
                            "approval time is before challenge creation",
                        )
                    current = self._state_locked(layout, challenge.challenge_digest)
                    if current is None:
                        raise ApprovalError("APPROVAL_MISSING", "approval is unavailable")
                    state, pending = current
                    if state != "pending":
                        code = "APPROVAL_CONSUMED" if state == "consumed" else "APPROVAL_MISSING"
                        raise ApprovalError(code, "approval is unavailable")
                    if not self._matches(challenge, pending.value):
                        if pending.value.get("policy_digest") != challenge.policy_digest:
                            raise ApprovalError(
                                "APPROVAL_POLICY_MISMATCH",
                                "approval policy does not match",
                            )
                        raise ApprovalError(
                            "APPROVAL_MISMATCH",
                            "approval challenge does not match",
                        )
                    if granted_at >= challenge.expires_at:
                        transaction = self._transaction(
                            challenge,
                            operation="expire-pending",
                            source="pending",
                            destination="expired",
                            source_record=pending,
                            artifact=pending.value,
                            result="expired",
                            reason_code="EXPIRED",
                            event_at=challenge.expires_at,
                        )
                        self._run_transaction_locked(layout, transaction)
                        raise ApprovalError("APPROVAL_EXPIRED", "approval has expired")
                    grant = ApprovalGrant(
                        challenge_digest=challenge.challenge_digest,
                        policy_digest=challenge.policy_digest,
                        approved_by=approved_by,
                        approved_at=granted_at,
                        expires_at=challenge.expires_at,
                    )
                    artifact = self._artifact(challenge, kind="granted", grant=grant)
                    transaction = self._transaction(
                        challenge,
                        operation="grant",
                        source="pending",
                        destination="granted",
                        source_record=pending,
                        artifact=artifact,
                        result="granted",
                        reason_code="GRANTED",
                        event_at=granted_at,
                    )
                    self._run_transaction_locked(layout, transaction)
                    return grant
            except ApprovalError as error:
                self._audit_rejection(layout, challenge, error, now=granted_at)
                raise

    def consume(
        self, grant: ApprovalGrant, challenge: ApprovalChallenge, *, now: datetime
    ) -> ApprovalReceipt:
        try:
            self._assert_local(challenge)
        except ApprovalError as error:
            self._audit_prevalidation_rejection(challenge, error, now=now)
            raise
        consumed_at = _utc(now, name="now")
        with self._layout() as layout:
            try:
                with self._digest_lock(layout, challenge.challenge_digest):
                    self._recover_locked(layout, challenge.challenge_digest)
                    if not isinstance(grant, ApprovalGrant):
                        raise ApprovalError("APPROVAL_MISMATCH", "approval grant does not match")
                    if (
                        grant.challenge_digest != challenge.challenge_digest
                        or grant.policy_digest != challenge.policy_digest
                    ):
                        raise ApprovalError("APPROVAL_MISMATCH", "approval grant does not match")
                    if (
                        _utc(grant.approved_at, name="grant.approved_at") > consumed_at
                        or _utc(grant.expires_at, name="grant.expires_at") != challenge.expires_at
                    ):
                        raise ApprovalError("APPROVAL_MISMATCH", "approval grant does not match")
                    current = self._state_locked(layout, challenge.challenge_digest)
                    if current is None:
                        raise ApprovalError("APPROVAL_MISSING", "approval is unavailable")
                    state, artifact = current
                    if state == "consumed":
                        raise ApprovalError("APPROVAL_CONSUMED", "approval already consumed")
                    if state == "expired":
                        raise ApprovalError("APPROVAL_EXPIRED", "approval has expired")
                    if state != "granted":
                        raise ApprovalError("APPROVAL_MISSING", "approval is unavailable")
                    if not self._matches(challenge, artifact.value):
                        if artifact.value.get("policy_digest") != challenge.policy_digest:
                            raise ApprovalError(
                                "APPROVAL_POLICY_MISMATCH",
                                "approval policy does not match",
                            )
                        raise ApprovalError(
                            "APPROVAL_MISMATCH",
                            "approval challenge does not match",
                        )
                    if artifact.value.get("approved_by") != grant.approved_by or artifact.value.get(
                        "approved_at"
                    ) != _timestamp(grant.approved_at):
                        raise ApprovalError("APPROVAL_MISMATCH", "approval grant does not match")
                    if consumed_at >= challenge.expires_at:
                        transaction = self._transaction(
                            challenge,
                            operation="expire-granted",
                            source="granted",
                            destination="expired",
                            source_record=artifact,
                            artifact=artifact.value,
                            result="expired",
                            reason_code="EXPIRED",
                            event_at=challenge.expires_at,
                        )
                        self._run_transaction_locked(layout, transaction)
                        raise ApprovalError("APPROVAL_EXPIRED", "approval has expired")
                    transaction = self._transaction(
                        challenge,
                        operation="consume",
                        source="granted",
                        destination="consumed",
                        source_record=artifact,
                        artifact=artifact.value,
                        result="consumed",
                        reason_code="CONSUMED",
                        event_at=consumed_at,
                    )
                    self._run_transaction_locked(layout, transaction)
                    return ApprovalReceipt("consumed")
            except ApprovalError as error:
                self._audit_rejection(layout, challenge, error, now=consumed_at)
                raise

    def status(self, challenge_digest: str) -> str:
        digest = self._name(challenge_digest).removesuffix(".json")
        with self._layout() as layout:
            with self._digest_lock(layout, digest):
                self._recover_locked(layout, digest)
                current = self._state_locked(layout, digest)
                return "missing" if current is None else current[0]

    def append_event(
        self, challenge: ApprovalChallenge, *, result: str, reason_code: str, now: datetime
    ) -> None:
        """Append only the strict, secret-free audit projection under ``fcntl``."""
        self._assert_local(challenge)
        event = self._event(challenge, result=result, reason_code=reason_code, now=now)
        with self._layout() as layout:
            self._append_event_record(layout, event, idempotent=False)
