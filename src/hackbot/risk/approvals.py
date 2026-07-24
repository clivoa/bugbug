"""Canonical, local-only storage for exact five-minute L2 approvals.

The audit lock uses :mod:`fcntl`, so the locking guarantee currently applies to
the supported macOS/Linux runtime.  Windows is intentionally not claimed as a
supported approval-store platform until it has an equivalent lock primitive.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
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
_ARTIFACT_LIMIT = 65_536
_VERSION = 1
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
    except (OverflowError, TypeError, ValueError) as exc:
        raise ApprovalError(
            "APPROVAL_INVALID_CLOCK", f"{name} must be an aware UTC timestamp"
        ) from exc
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value, name="timestamp").isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, *, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ApprovalError("APPROVAL_MALFORMED", f"malformed {name}")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
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


def _validate_inputs(
    definition: object, request: object, context: object, now: object, nonce: object
) -> tuple[ActionDefinition, ActionRequest, PolicyContext, datetime, str]:
    if not isinstance(definition, ActionDefinition) or not isinstance(request, ActionRequest):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "invalid challenge input")
    if not isinstance(context, PolicyContext):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "invalid policy context")
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
    expires_at = created_at + timedelta(minutes=5)
    fields = _challenge_fields(
        definition,
        request,
        context,
        created_at=created_at,
        expires_at=expires_at,
        nonce=checked_nonce,
    )
    digest = hashlib.sha256(canonical_bytes(fields)).hexdigest()
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
        binding=canonical_bytes(fields),
    )


def _validate_challenge(challenge: object) -> ApprovalChallenge:
    if not isinstance(challenge, ApprovalChallenge):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "invalid approval challenge")
    if not challenge.engagement_path:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge lacks engagement path")
    if not _DIGEST_RE.fullmatch(challenge.challenge_digest):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge digest is malformed")
    if not _DIGEST_RE.fullmatch(challenge.policy_digest) or not _DIGEST_RE.fullmatch(
        challenge.scope_digest
    ):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge digest is malformed")
    if _NONCE_RE.fullmatch(challenge.nonce) is None:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge nonce is malformed")
    if not challenge.binding or len(challenge.binding) > _ARTIFACT_LIMIT:
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
    if not isinstance(binding, dict) or canonical_bytes(binding) != challenge.binding:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding is malformed")
    if hashlib.sha256(challenge.binding).hexdigest() != challenge.challenge_digest:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding digest is malformed")
    request = binding.get("request")
    engagement = binding.get("engagement")
    if binding.get("policy_digest") != challenge.policy_digest:
        raise ApprovalError("APPROVAL_POLICY_MISMATCH", "challenge policy binding does not match")
    if binding.get("scope_digest") != challenge.scope_digest:
        raise ApprovalError("APPROVAL_MISMATCH", "challenge scope binding does not match")
    if (
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
    ):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge binding does not match")
    created_at = _utc(challenge.created_at, name="challenge.created_at")
    expires_at = _utc(challenge.expires_at, name="challenge.expires_at")
    if expires_at != created_at + timedelta(minutes=5):
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge expiry is malformed")
    if challenge.effective_risk is not RiskLevel.L2:
        raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge risk is malformed")
    return challenge


class ApprovalStore:
    """Engagement-local, no-overwrite L2 approval persistence."""

    def __init__(self, engagement_dir: str | Path) -> None:
        try:
            self.engagement_path, self.engagement_id = canonical_engagement_identity(engagement_dir)
        except EngagementIdentityError as exc:
            raise ApprovalError(
                "APPROVAL_INVALID_ENGAGEMENT", "invalid engagement directory"
            ) from exc
        self.root = str(Path(self.engagement_path) / "approvals")

    def _ensure_layout(self) -> None:
        root = Path(self.root)
        try:
            if root.exists() and root.is_symlink():
                raise ApprovalError("APPROVAL_UNSAFE_PATH", "approval path is a symlink")
            root.mkdir(mode=0o700, exist_ok=True)
            if not root.is_dir() or root.is_symlink():
                raise ApprovalError("APPROVAL_UNSAFE_PATH", "approval path is unsafe")
            os.chmod(root, 0o700)
            for name in ("pending", "granted", "consumed", "expired"):
                directory = root / name
                if directory.exists() and directory.is_symlink():
                    raise ApprovalError("APPROVAL_UNSAFE_PATH", "approval path is a symlink")
                directory.mkdir(mode=0o700, exist_ok=True)
                if not directory.is_dir() or directory.is_symlink():
                    raise ApprovalError("APPROVAL_UNSAFE_PATH", "approval path is unsafe")
                os.chmod(directory, 0o700)
        except ApprovalError:
            raise
        except OSError as exc:
            raise ApprovalError("APPROVAL_IO", "unable to create approval directory") from exc

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
    def _name(digest: str) -> str:
        if _DIGEST_RE.fullmatch(digest) is None:
            raise ApprovalError("APPROVAL_INVALID_CHALLENGE", "challenge digest is malformed")
        return digest + ".json"

    def _path(self, state: str, digest: str) -> Path:
        return Path(self.root) / state / self._name(digest)

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
    def _write_exclusive(path: Path, value: Mapping[str, object]) -> None:
        payload = canonical_bytes(value)
        fd: int | None = None
        created = False
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            view = memoryview(payload)
            while view:
                wrote = os.write(fd, view)
                if wrote <= 0:
                    raise OSError("short approval artifact write")
                view = view[wrote:]
            os.fsync(fd)
        except FileExistsError as exc:
            raise ApprovalError("APPROVAL_EXISTS", "approval record already exists") from exc
        except OSError as exc:
            if created:
                try:
                    path.unlink()
                except OSError:
                    pass
            raise ApprovalError("APPROVAL_IO", "approval record write failed") from exc
        finally:
            if fd is not None:
                os.close(fd)
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            try:
                path.unlink()
            except OSError:
                pass
            raise ApprovalError("APPROVAL_IO", "approval record write failed") from exc

    @staticmethod
    def _read_artifact(path: Path, *, kind: str) -> dict[str, object]:
        fd: int | None = None
        try:
            no_follow = getattr(os, "O_NOFOLLOW", None)
            if no_follow is None:
                raise ApprovalError("APPROVAL_UNSAFE_PATH", "safe artifact reads are unavailable")
            fd = os.open(path, os.O_RDONLY | no_follow)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > _ARTIFACT_LIMIT:
                raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    raise OSError("short approval artifact read")
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            value = strict_json_loads(raw.decode("utf-8"))
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
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact") from exc
        finally:
            if fd is not None:
                os.close(fd)
        if not isinstance(value, dict) or set(value) != (
            _PENDING_KEYS if kind == "pending" else _GRANT_KEYS
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        if value.get("version") != _VERSION or value.get("kind") != kind:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        for key in ("challenge_digest", "policy_digest", "scope_digest"):
            if not isinstance(value.get(key), str) or _DIGEST_RE.fullmatch(value[key]) is None:
                raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        if not isinstance(value.get("engagement_id"), str) or not isinstance(
            value.get("engagement_path"), str
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        if not isinstance(value.get("action_id"), str) or value.get("effective_risk") != int(
            RiskLevel.L2
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        if not isinstance(value.get("nonce"), str) or _NONCE_RE.fullmatch(value["nonce"]) is None:
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        binding = value.get("challenge")
        if (
            not isinstance(binding, dict)
            or hashlib.sha256(canonical_bytes(binding)).hexdigest() != value["challenge_digest"]
        ):
            raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
        _parse_timestamp(value.get("created_at"), name="created_at")
        _parse_timestamp(value.get("expires_at"), name="expires_at")
        if kind == "granted":
            if (
                not isinstance(value.get("approved_by"), str)
                or _APPROVED_BY_RE.fullmatch(value["approved_by"]) is None
            ):
                raise ApprovalError("APPROVAL_MALFORMED", "malformed approval artifact")
            _parse_timestamp(value.get("approved_at"), name="approved_at")
        return value

    @staticmethod
    def _matches(challenge: ApprovalChallenge, artifact: Mapping[str, object]) -> bool:
        expected = ApprovalStore._artifact(challenge, kind=str(artifact["kind"]))
        for key, value in expected.items():
            if key in {"approved_at", "approved_by"}:
                continue
            if artifact.get(key) != value:
                return False
        return True

    def _state(self, digest: str) -> str | None:
        for state in ("consumed", "expired", "granted", "pending"):
            path = self._path(state, digest)
            if path.exists() or path.is_symlink():
                return state
        return None

    def create_pending(self, challenge: ApprovalChallenge) -> Path:
        self._assert_local(challenge)
        self._ensure_layout()
        if self._state(challenge.challenge_digest) is not None:
            raise ApprovalError("APPROVAL_EXISTS", "approval record already exists")
        path = self._path("pending", challenge.challenge_digest)
        try:
            self._write_exclusive(path, self._artifact(challenge, kind="pending"))
            self.append_event(
                challenge, result="created", reason_code="CREATED", now=challenge.created_at
            )
        except ApprovalError:
            try:
                path.unlink()
            except OSError:
                pass
            raise
        return path

    def grant(
        self, challenge: ApprovalChallenge, *, approved_by: str, now: datetime
    ) -> ApprovalGrant:
        self._assert_local(challenge)
        self._ensure_layout()
        granted_at = _utc(now, name="now")
        if _APPROVED_BY_RE.fullmatch(approved_by) is None:
            raise ApprovalError("APPROVAL_INVALID_OPERATOR", "operator label is invalid")
        if granted_at < challenge.created_at:
            raise ApprovalError(
                "APPROVAL_INVALID_CLOCK", "approval time is before challenge creation"
            )
        pending_path = self._path("pending", challenge.challenge_digest)
        state = self._state(challenge.challenge_digest)
        if state != "pending":
            raise ApprovalError(
                "APPROVAL_CONSUMED" if state == "consumed" else "APPROVAL_MISSING",
                "approval is unavailable",
            )
        pending = self._read_artifact(pending_path, kind="pending")
        if not self._matches(challenge, pending):
            if pending.get("policy_digest") != challenge.policy_digest:
                raise ApprovalError("APPROVAL_POLICY_MISMATCH", "approval policy does not match")
            raise ApprovalError("APPROVAL_MISMATCH", "approval challenge does not match")
        if granted_at >= challenge.expires_at:
            self._expire(challenge, pending_path)
            raise ApprovalError("APPROVAL_EXPIRED", "approval has expired")
        grant = ApprovalGrant(
            challenge_digest=challenge.challenge_digest,
            policy_digest=challenge.policy_digest,
            approved_by=approved_by,
            approved_at=granted_at,
            expires_at=challenge.expires_at,
        )
        grant_path = self._path("granted", challenge.challenge_digest)
        self._write_exclusive(grant_path, self._artifact(challenge, kind="granted", grant=grant))
        try:
            self.append_event(challenge, result="granted", reason_code="GRANTED", now=granted_at)
            pending_path.unlink()
        except (ApprovalError, OSError) as exc:
            try:
                grant_path.unlink()
            except OSError:
                pass
            if isinstance(exc, ApprovalError):
                raise
            raise ApprovalError("APPROVAL_IO", "approval grant write failed") from exc
        return grant

    def _claim(self, source: Path, destination: Path) -> None:
        """Claim ``destination`` without rename-overwrite semantics, then remove source."""
        try:
            os.link(source, destination)
        except FileExistsError as exc:
            raise ApprovalError("APPROVAL_CONSUMED", "approval already consumed") from exc
        except FileNotFoundError as exc:
            raise ApprovalError("APPROVAL_CONSUMED", "approval already consumed") from exc
        except OSError as exc:
            raise ApprovalError("APPROVAL_IO", "approval state transition failed") from exc
        try:
            os.unlink(source)
        except OSError as exc:
            raise ApprovalError("APPROVAL_IO", "approval state transition failed") from exc

    def _expire(self, challenge: ApprovalChallenge, source: Path) -> None:
        try:
            self._claim(source, self._path("expired", challenge.challenge_digest))
        except ApprovalError as exc:
            if exc.code != "APPROVAL_CONSUMED":
                raise
        self.append_event(
            challenge, result="expired", reason_code="EXPIRED", now=challenge.expires_at
        )

    def consume(
        self, grant: ApprovalGrant, challenge: ApprovalChallenge, *, now: datetime
    ) -> ApprovalReceipt:
        self._assert_local(challenge)
        self._ensure_layout()
        consumed_at = _utc(now, name="now")
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
        source = self._path("granted", challenge.challenge_digest)
        state = self._state(challenge.challenge_digest)
        if state == "consumed":
            self.append_event(challenge, result="replayed", reason_code="REPLAY", now=consumed_at)
            raise ApprovalError("APPROVAL_CONSUMED", "approval already consumed")
        if state == "expired":
            raise ApprovalError("APPROVAL_EXPIRED", "approval has expired")
        if state != "granted":
            raise ApprovalError("APPROVAL_MISSING", "approval is unavailable")
        artifact = self._read_artifact(source, kind="granted")
        if not self._matches(challenge, artifact):
            raise ApprovalError("APPROVAL_MISMATCH", "approval challenge does not match")
        if artifact.get("approved_by") != grant.approved_by or artifact.get(
            "approved_at"
        ) != _timestamp(grant.approved_at):
            raise ApprovalError("APPROVAL_MISMATCH", "approval grant does not match")
        if consumed_at >= challenge.expires_at:
            self._expire(challenge, source)
            raise ApprovalError("APPROVAL_EXPIRED", "approval has expired")
        self._claim(source, self._path("consumed", challenge.challenge_digest))
        self.append_event(challenge, result="consumed", reason_code="CONSUMED", now=consumed_at)
        return ApprovalReceipt("consumed")

    def status(self, challenge_digest: str) -> str:
        self._ensure_layout()
        state = self._state(challenge_digest)
        if state is None:
            return "missing"
        record_kind = "pending" if state == "pending" else "granted"
        self._read_artifact(self._path(state, challenge_digest), kind=record_kind)
        return state

    def append_event(
        self, challenge: ApprovalChallenge, *, result: str, reason_code: str, now: datetime
    ) -> None:
        """Append only the strict, secret-free audit projection under ``fcntl``."""
        self._assert_local(challenge)
        if (
            _EVENT_RESULT_RE.fullmatch(result) is None
            or _EVENT_REASON_RE.fullmatch(reason_code) is None
        ):
            raise ApprovalError("APPROVAL_INVALID_EVENT", "invalid approval event")
        self._ensure_layout()
        event = {
            "timestamp": _timestamp(_utc(now, name="now")),
            "engagement_id": challenge.engagement_id,
            "action_id": challenge.action_id,
            "challenge_digest": challenge.challenge_digest,
            "effective_risk": int(challenge.effective_risk),
            "result": result,
            "reason_code": reason_code,
        }
        payload = canonical_bytes(event) + b"\n"
        path = Path(self.root) / "events.jsonl"
        fd: int | None = None
        try:
            import fcntl  # macOS/Linux only; documented at module level.

            if path.exists() and path.is_symlink():
                raise ApprovalError("APPROVAL_UNSAFE_PATH", "approval audit path is unsafe")
            no_follow = getattr(os, "O_NOFOLLOW", None)
            if no_follow is None:
                raise ApprovalError("APPROVAL_UNSAFE_PATH", "safe audit writes are unavailable")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | no_follow, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ApprovalError("APPROVAL_UNSAFE_PATH", "approval audit path is unsafe")
            os.chmod(path, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            if os.write(fd, payload) != len(payload):
                raise OSError("short audit write")
            os.fsync(fd)
        except ApprovalError:
            raise
        except OSError as exc:
            raise ApprovalError("APPROVAL_IO", "approval audit write failed") from exc
        finally:
            if fd is not None:
                try:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(fd)
