"""CLI tests for `hackbot program validate/import` and `scope --scope-file`."""

from pathlib import Path

from hackbot.cli.main import app

FIX = Path(__file__).parent / "fixtures"


def test_program_validate_ok(capsys):
    assert app(["program", "validate", str(FIX / "valid_program.yaml")]) == 0
    assert "valid:" in capsys.readouterr().out


def test_program_validate_rejects(capsys):
    code = app(["program", "validate", str(FIX / "invalid_unknown_field.yaml")])
    assert code == 1
    assert "INVALID" in capsys.readouterr().err


def test_program_import_creates_engagement(tmp_path, capsys):
    code = app(
        ["program", "import", str(FIX / "valid_program.yaml"), "--engagements-dir", str(tmp_path)]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "created engagement" in out
    created = list(tmp_path.rglob("program.yaml"))
    assert len(created) == 1


def test_program_import_refuses_overwrite(tmp_path, capsys):
    args = [
        "program",
        "import",
        str(FIX / "valid_program.yaml"),
        "--engagements-dir",
        str(tmp_path),
    ]
    assert app(args) == 0
    assert app(args) == 3  # no-overwrite
    assert "already exists" in capsys.readouterr().err


def test_program_import_rejects_invalid(tmp_path, capsys):
    code = app(
        [
            "program",
            "import",
            str(FIX / "invalid_malformed.yaml"),
            "--platform",
            "x",
            "--program",
            "y",
            "--engagements-dir",
            str(tmp_path),
        ]
    )
    assert code == 1
    assert list(tmp_path.rglob("program.yaml")) == []  # default-deny: nothing created


def test_scope_check_with_scope_file(capsys):
    code = app(
        [
            "scope",
            "check",
            "https://api.example.com/",
            "--scope-file",
            str(FIX / "valid_scope.yaml"),
        ]
    )
    assert code == 0
    assert "ALLOW" in capsys.readouterr().out


def test_scope_file_invalid_is_denied(capsys):
    import pytest

    with pytest.raises(SystemExit):
        app(
            [
                "scope",
                "check",
                "https://api.example.com/",
                "--scope-file",
                str(FIX / "invalid_malformed.yaml"),
            ]
        )
