"""Loader wiring to the scope engine + atomic/no-overwrite engagement tests."""

from pathlib import Path

import pytest

from hackbot.programs import engagement, loader
from hackbot.programs.schema import ValidationError

FIX = Path(__file__).parent / "fixtures"


def test_loader_builds_working_scope():
    scope = loader.load_scope_file(FIX / "valid_scope.yaml")
    assert scope.check("https://api.example.com/").allowed  # apex+sub
    assert scope.check("https://v1.api.example.com/").allowed  # wildcard
    assert not scope.check("https://evil.com/").allowed  # default-deny
    assert not scope.check("https://internal.example.com/").allowed  # deny-wins


def test_loader_validation_failure_raises_not_open_scope():
    with pytest.raises(ValidationError):
        loader.load_scope_file(FIX / "invalid_malformed.yaml")


def test_loader_rejects_non_yaml_safe(tmp_path):
    # yaml.safe_load must not construct arbitrary objects
    bad = tmp_path / "danger.yaml"
    bad.write_text("!!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(loader.ProgramError):
        loader.load_scope_file(bad)


def test_program_load_returns_scope():
    doc, scope = loader.load_program_file(FIX / "valid_program.yaml")
    assert scope.check("https://acme-corp.example/app").allowed
    assert not scope.check("https://blog.acme-corp.example/").allowed


def test_loader_rejects_duplicate_yaml_keys_in_program_at_every_depth(tmp_path):
    program = tmp_path / "program.yaml"
    program.write_text(
        """schema_version: 1
program:
  name: first-name
  name: second-name
scope:
  in_scope:
    domains: [example.com]
    domains: [expanded.example]
testing_rules:
  max_requests_per_second: 1
  max_requests_per_second: 1000
  automated_scanning_allowed: false
  automated_scanning_allowed: true
""",
        encoding="utf-8",
    )
    with pytest.raises(loader.ProgramError, match="duplicate YAML key"):
        loader.load_program_file(program)


def test_loader_rejects_duplicate_yaml_keys_in_standalone_scope(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        """schema_version: 1
in_scope:
  domains: [example.com]
  domains: [expanded.example]
""",
        encoding="utf-8",
    )
    with pytest.raises(loader.ProgramError, match="duplicate YAML key"):
        loader.load_scope_file(scope)


def test_loader_rejects_duplicate_json_keys_in_program_at_every_depth(tmp_path):
    program = tmp_path / "program.json"
    program.write_text(
        '{"schema_version": 1, "program": {"name": "first", "name": "last"}, '
        '"scope": {"in_scope": {"domains": ["example.com"], '
        '"domains": ["expanded.example"]}}, "testing_rules": '
        '{"max_requests_per_second": 1, "max_requests_per_second": 1000}}',
        encoding="utf-8",
    )
    with pytest.raises(loader.ProgramError, match="duplicate JSON key"):
        loader.load_program_file(program)


def test_loader_rejects_duplicate_json_keys_in_standalone_scope(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(
        '{"schema_version": 1, "in_scope": {"domains": ["example.com"], '
        '"domains": ["expanded.example"]}}',
        encoding="utf-8",
    )
    with pytest.raises(loader.ProgramError, match="duplicate JSON key"):
        loader.load_scope_file(scope)


@pytest.mark.parametrize(
    "mapping_key",
    ["1: one", "? [sequence, key]\n: value"],
)
def test_loader_rejects_non_string_or_unhashable_yaml_mapping_keys(tmp_path, mapping_key):
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"schema_version: 1\n{mapping_key}\n", encoding="utf-8")
    with pytest.raises(loader.ProgramError, match="mapping key must be a string"):
        loader.load_scope_file(scope)


def test_loader_schema_version_unhashable_value_raises_validation_error(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text("schema_version: []\nin_scope:\n  domains: [example.com]\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="unsupported schema_version"):
        loader.load_scope_file(scope)


def test_loader_rejects_invalid_restricted_hours_zoneinfo_name(tmp_path):
    program = tmp_path / "program.yaml"
    program.write_text(
        """schema_version: 1
scope:
  in_scope:
    domains: [example.com]
testing_rules:
  restricted_hours:
    timezone: /etc/passwd
    windows: ["09:00-10:00"]
""",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="restricted_hours.timezone"):
        loader.load_program_file(program)


@pytest.mark.parametrize("filename", ["program.yaml", "scope.json"])
def test_loader_invalid_utf8_raises_program_error(tmp_path, filename):
    path = tmp_path / filename
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(loader.ProgramError, match=str(path)):
        if filename == "program.yaml":
            loader.load_program_file(path)
        else:
            loader.load_scope_file(path)


# --- engagement creation ---------------------------------------------------
def _doc():
    import yaml

    return yaml.safe_load((FIX / "valid_program.yaml").read_text())


def test_create_engagement_atomic(tmp_path):
    doc = _doc()
    path = engagement.create_engagement(
        tmp_path,
        platform="generic-vdp",
        program="acme-corp",
        program_doc=doc,
        scope_doc={"schema_version": 1, **doc["scope"]},
    )
    assert (path / "program.yaml").exists()
    assert (path / "scope.yaml").exists()
    assert (path / "authorization.json").exists()
    for sub in ("recon", "evidence", "findings", "reports"):
        assert (path / sub).is_dir()
    # scope.yaml is re-loadable and valid
    s = loader.load_scope_file(path / "scope.yaml")
    assert s.check("https://acme-corp.example/app").allowed


def test_create_engagement_no_overwrite(tmp_path):
    doc = _doc()
    kw = dict(
        platform="generic-vdp",
        program="acme-corp",
        program_doc=doc,
        scope_doc={"schema_version": 1, **doc["scope"]},
    )
    engagement.create_engagement(tmp_path, **kw)
    with pytest.raises(engagement.EngagementExists):
        engagement.create_engagement(tmp_path, **kw)


def test_no_partial_engagement_left_on_failure(tmp_path, monkeypatch):
    doc = _doc()
    import hackbot.programs.engagement as eng

    real_rename = eng.os.rename

    def _boom(src, dst):
        raise OSError("simulated failure during publish")

    monkeypatch.setattr(eng.os, "rename", _boom)
    with pytest.raises(OSError):
        eng.create_engagement(
            tmp_path,
            platform="p",
            program="prog",
            program_doc=doc,
            scope_doc={"schema_version": 1, **doc["scope"]},
        )
    monkeypatch.setattr(eng.os, "rename", real_rename)
    # target must NOT exist, and no leftover temp dirs
    assert not (tmp_path / "p" / "prog").exists() or not list((tmp_path / "p" / "prog").iterdir())
    leftovers = list(tmp_path.rglob(".engagement-tmp-*"))
    assert leftovers == [], f"partial engagement left behind: {leftovers}"
