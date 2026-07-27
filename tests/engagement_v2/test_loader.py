"""P1 loader: atomic snapshot, hardened decode, confirmation, and identity."""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

import pytest

from hackbot.engagement_v2 import loader as loader_mod
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.loader import EngagementSnapshot, load_engagement

from ._engagement_builders import (
    program_doc,
    scope_doc,
    stamp_digest,
    write_engagement,
)

yaml = pytest.importorskip("yaml")


def _reason(excinfo: pytest.ExceptionInfo[ContractError]) -> ReasonCode:
    return excinfo.value.reason_code


# --------------------------------------------------------------- happy path ---
def test_coherent_set_produces_one_confirmed_snapshot(tmp_path: Path) -> None:
    write_engagement(tmp_path, include_runner=True)
    snapshot = load_engagement(tmp_path)
    assert isinstance(snapshot, EngagementSnapshot)
    assert snapshot.profile == "bug-bounty"
    assert snapshot.authority_digest.startswith("sha256:")
    assert snapshot.identity.startswith("sha256:")


def test_snapshot_is_frozen(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    snapshot = load_engagement(tmp_path)
    with pytest.raises(dataclasses.FrozenInstanceError):
        snapshot.profile = "local-lab"  # type: ignore[misc]


# --------------------------------------------------------- descriptor safety ---
def test_symlinked_authority_file_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    write_engagement(real)
    link_dir = tmp_path / "link"
    link_dir.mkdir()
    for name in ("scope.json", "authorization.json"):
        (link_dir / name).write_text((real / name).read_text(), encoding="utf-8")
    (link_dir / "program.json").symlink_to(real / "program.json")
    with pytest.raises(ContractError) as excinfo:
        load_engagement(link_dir)
    assert _reason(excinfo) is ReasonCode.INVALID_DOCUMENT_STRUCTURE


def test_non_regular_file_is_refused(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    (tmp_path / "program.json").unlink()
    (tmp_path / "program.json").mkdir()
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_DOCUMENT_STRUCTURE


def test_mid_read_inode_change_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_engagement(tmp_path)
    real_fstat = os.fstat
    calls = {"n": 0}

    class _Stat:
        def __init__(self, base: os.stat_result, ino: int) -> None:
            self._base = base
            self.st_ino = ino

        def __getattr__(self, name: str) -> object:
            return getattr(self._base, name)

    def fake_fstat(fd: int) -> object:
        base = real_fstat(fd)
        calls["n"] += 1
        # Change the reported inode on the second fstat of the first document.
        if calls["n"] == 2:
            return _Stat(base, base.st_ino + 1)
        return base

    monkeypatch.setattr(loader_mod.os, "fstat", fake_fstat)
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_DOCUMENT_STRUCTURE


# ------------------------------------------------------------- hardening ---
def test_oversized_document_rejected_before_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_engagement(tmp_path)
    monkeypatch.setattr(loader_mod, "MAX_PROGRAM_DOCUMENT_BYTES", 8)
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_DOCUMENT_SIZE


def test_duplicate_key_rejected(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    (tmp_path / "scope.json").write_text(
        '{"schema_version": 2, "schema_version": 2, "in_scope": {}, "out_of_scope": {}}',
        encoding="utf-8",
    )
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_DUPLICATE_KEY


def test_unsupported_version_rejected(tmp_path: Path) -> None:
    program = program_doc()
    program["schema_version"] = 1
    write_engagement(tmp_path, program=program)
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_SCHEMA_VERSION


def test_boolean_version_rejected(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    (tmp_path / "scope.json").write_text(
        '{"schema_version": true, "in_scope": {}, "out_of_scope": {}}', encoding="utf-8"
    )
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_SCHEMA_VERSION


def test_unknown_top_level_field_rejected(tmp_path: Path) -> None:
    scope = scope_doc()
    scope["surprise"] = 1
    write_engagement(tmp_path, scope=scope)
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_UNKNOWN_FIELD


def test_unknown_scope_kind_rejected(tmp_path: Path) -> None:
    scope = scope_doc()
    scope["in_scope"]["subdomains"] = ["x.corp.example"]
    write_engagement(tmp_path, scope=scope)
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_UNKNOWN_FIELD


def test_unknown_testing_rules_field_rejected(tmp_path: Path) -> None:
    program = program_doc()
    program["testing_rules"]["bogus_rule"] = True
    write_engagement(tmp_path, program=program)
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_UNKNOWN_FIELD


def test_scalar_scope_kind_maps_to_contract_error(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    # A scalar where a scope kind expects a list must stay inside the closed
    # reason-code contract (not a bare TypeError).
    (tmp_path / "scope.json").write_text(
        '{"schema_version": 2, "in_scope": {"domains": "app.corp.example"}, "out_of_scope": {}}',
        encoding="utf-8",
    )
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_DOCUMENT_STRUCTURE


def test_non_mapping_scope_section_rejected(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    (tmp_path / "scope.json").write_text(
        '{"schema_version": 2, "in_scope": [], "out_of_scope": {}}', encoding="utf-8"
    )
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_DOCUMENT_STRUCTURE


def test_float_rejected(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    (tmp_path / "scope.json").write_text(
        '{"schema_version": 2, "in_scope": {"rate": 1.0}, "out_of_scope": {}}',
        encoding="utf-8",
    )
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_CANONICAL_VALUE


def test_yaml_alias_rejected(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    (tmp_path / "scope.json").unlink()
    (tmp_path / "scope.yaml").write_text(
        "schema_version: 2\nin_scope: &a {}\nout_of_scope: *a\n", encoding="utf-8"
    )
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_DOCUMENT_STRUCTURE


def test_yaml_merge_key_rejected(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    (tmp_path / "scope.json").unlink()
    (tmp_path / "scope.yaml").write_text(
        "base: &b {}\nschema_version: 2\nin_scope:\n  <<: *b\nout_of_scope: {}\n",
        encoding="utf-8",
    )
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_DOCUMENT_STRUCTURE


def test_yaml_explicit_python_tag_rejected(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    (tmp_path / "scope.json").unlink()
    (tmp_path / "scope.yaml").write_text(
        "schema_version: 2\nin_scope: !!python/object/apply:os.system []\nout_of_scope: {}\n",
        encoding="utf-8",
    )
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.INVALID_DOCUMENT_STRUCTURE


# ----------------------------------------------------------- confirmation ---
def test_matching_digest_confirms(tmp_path: Path) -> None:
    write_engagement(tmp_path, include_runner=True)
    snapshot = load_engagement(tmp_path)
    program = program_doc()
    scope = scope_doc()
    from ._engagement_builders import runner_doc

    assert snapshot.authority_digest == stamp_digest(program, scope, runner_doc())


def test_material_change_invalidates_confirmation(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    # Change a security-relevant scope rule without restamping the digest.
    scope = scope_doc()
    scope["in_scope"]["domains"] = ["attacker.example"]
    (tmp_path / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.DENY_AUTHORIZATION_STALE


def test_policy_limit_change_invalidates(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    program = program_doc()
    program["testing_rules"]["max_requests_per_second"] = 1000
    (tmp_path / "program.json").write_text(json.dumps(program), encoding="utf-8")
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.DENY_AUTHORIZATION_STALE


def test_unconfirmed_authorization_denies(tmp_path: Path) -> None:
    write_engagement(tmp_path, confirmed=False)
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.DENY_AUTHORIZATION_UNCONFIRMED


def test_missing_confirmation_field_denies(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    auth = json.loads((tmp_path / "authorization.json").read_text())
    auth["confirmed_by"] = ""
    (tmp_path / "authorization.json").write_text(json.dumps(auth), encoding="utf-8")
    with pytest.raises(ContractError) as excinfo:
        load_engagement(tmp_path)
    assert _reason(excinfo) is ReasonCode.DENY_AUTHORIZATION_UNCONFIRMED


def test_note_only_change_stays_confirmed(tmp_path: Path) -> None:
    write_engagement(tmp_path, include_runner=True)
    auth = json.loads((tmp_path / "authorization.json").read_text())
    auth["note"] = "A totally different note that is not security relevant"
    (tmp_path / "authorization.json").write_text(json.dumps(auth), encoding="utf-8")
    snapshot = load_engagement(tmp_path)
    assert snapshot.profile == "bug-bounty"


def test_scope_key_order_change_stays_confirmed(tmp_path: Path) -> None:
    write_engagement(tmp_path)
    scope = scope_doc()
    # Reverse ordering of a set-like list; the projection sorts it.
    scope["in_scope"]["hosts"] = list(reversed(scope["in_scope"]["hosts"]))
    (tmp_path / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    snapshot = load_engagement(tmp_path)
    assert snapshot.profile == "bug-bounty"


# --------------------------------------------------------------- identity ---
def test_identity_stable_across_identical_loads(tmp_path: Path) -> None:
    write_engagement(tmp_path, include_runner=True)
    first = load_engagement(tmp_path).identity
    second = load_engagement(tmp_path).identity
    assert first == second


def test_identity_changes_on_security_relevant_change(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    write_engagement(a)
    scope = scope_doc()
    scope["in_scope"]["hosts"] = ["dc02.corp.example"]
    write_engagement(b, scope=scope)
    assert load_engagement(a).identity != load_engagement(b).identity


def test_identity_has_no_path_or_secret(tmp_path: Path) -> None:
    write_engagement(tmp_path, include_runner=True)
    identity = load_engagement(tmp_path).identity
    assert "/" not in identity
    assert identity.startswith("sha256:")
    assert len(identity) == len("sha256:") + 64
