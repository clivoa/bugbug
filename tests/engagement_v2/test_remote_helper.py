"""P4 helper identity and executable-digest verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.remote_helper import (
    verify_executable_digest,
    verify_helper_identity,
    verify_protocol_version,
)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_executable_digest_match_returns_path(tmp_path: Path) -> None:
    exe = tmp_path / "tool"
    exe.write_bytes(b"#!/bin/sh\necho ok\n")
    path = str(exe)
    assert verify_executable_digest(path, _digest(exe.read_bytes())) == path


def test_executable_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    exe = tmp_path / "tool"
    exe.write_bytes(b"real")
    with pytest.raises(ContractError) as excinfo:
        verify_executable_digest(str(exe), _digest(b"expected-something-else"))
    assert excinfo.value.reason_code is ReasonCode.EXEC_TRUST_MISMATCH


def test_non_regular_executable_rejected(tmp_path: Path) -> None:
    d = tmp_path / "dir"
    d.mkdir()
    with pytest.raises(ContractError):
        verify_executable_digest(str(d), _digest(b"x"))


def test_symlinked_executable_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"real")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(ContractError):
        verify_executable_digest(str(link), _digest(b"real"))


def test_helper_self_report_does_not_satisfy_identity() -> None:
    # A helper claiming a digest that does not match the pinned value is rejected.
    with pytest.raises(ContractError) as excinfo:
        verify_helper_identity("sha256:" + "a" * 64, "sha256:" + "b" * 64)
    assert excinfo.value.reason_code is ReasonCode.EXEC_TRUST_MISMATCH


def test_wrong_protocol_version_rejected() -> None:
    with pytest.raises(ContractError) as excinfo:
        verify_protocol_version(2, 1)
    assert excinfo.value.reason_code is ReasonCode.EXEC_PROTOCOL_INVALID
