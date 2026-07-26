from pathlib import Path

import pytest

from hackbot.reporting.templates import TemplateError, load_report_templates

REPORT = """# {engagement_id} ({platform_label})
{finding_count} finding(s)
{findings}
"""

FINDING = """## {title}

Evidence
{evidence}

Plausible
{plausible_impact}

Demonstrated
{demonstrated_impact}
"""


def _pair(root: Path, *, report: str = REPORT, finding: str = FINDING) -> Path:
    platform_dir = root / "generic"
    platform_dir.mkdir(parents=True)
    (platform_dir / "report.md").write_text(report, encoding="utf-8")
    (platform_dir / "finding.md").write_text(finding, encoding="utf-8")
    return root


def test_load_report_templates_accepts_valid_pair_and_literal_braces(tmp_path):
    root = _pair(
        tmp_path,
        report=REPORT.replace("# ", "# {{draft}} "),
        finding=FINDING.replace("{title}", "{{{title}}}"),
    )
    pair = load_report_templates(root, platform="generic")
    assert "{{draft}}" in pair.report
    assert "{{{title}}}" in pair.finding


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"], ids=["lf", "crlf", "cr"])
def test_load_report_templates_accepts_markdown_line_boundaries(tmp_path, newline):
    root = _pair(
        tmp_path,
        report=REPORT.replace("\n", newline),
        finding=FINDING.replace("\n", newline),
    )
    pair = load_report_templates(root, platform="generic")
    assert pair.report == REPORT.replace("\n", newline)
    assert pair.finding == FINDING.replace("\n", newline)


@pytest.mark.parametrize(
    ("template_name", "field_name"),
    [
        ("report", "findings"),
        ("finding", "evidence"),
        ("finding", "demonstrated_impact"),
        ("finding", "plausible_impact"),
    ],
)
@pytest.mark.parametrize(
    "separator",
    ["\v", "\f", "\u0085", "\u2028", "\u2029"],
    ids=["vertical-tab", "form-feed", "nel", "line-separator", "paragraph-separator"],
)
def test_load_report_templates_rejects_non_markdown_line_separators(
    tmp_path,
    template_name,
    field_name,
    separator,
):
    template = REPORT if template_name == "report" else FINDING
    unsafe = template.replace(
        f"\n{{{field_name}}}\n",
        f"{separator}{{{field_name}}}{separator}",
    )
    _pair(tmp_path, **{template_name: unsafe})
    with pytest.raises(TemplateError, match=f"{field_name} must be alone on its line"):
        load_report_templates(tmp_path, platform="generic")


@pytest.mark.parametrize(
    ("template_name", "field_name"),
    [
        ("report", "findings"),
        ("finding", "evidence"),
        ("finding", "demonstrated_impact"),
        ("finding", "plausible_impact"),
    ],
)
@pytest.mark.parametrize(
    "separator",
    ["\v", "\f", "\u0085", "\u2028", "\u2029"],
    ids=["vertical-tab", "form-feed", "nel", "line-separator", "paragraph-separator"],
)
def test_load_report_templates_rejects_non_markdown_separators_adjacent_to_placeholder(
    tmp_path,
    template_name,
    field_name,
    separator,
):
    template = REPORT if template_name == "report" else FINDING
    unsafe = template.replace(
        f"\n{{{field_name}}}\n",
        f"\n{separator}{{{field_name}}}{separator}\n",
    )
    _pair(tmp_path, **{template_name: unsafe})
    with pytest.raises(TemplateError, match=f"{field_name} must be alone on its line"):
        load_report_templates(tmp_path, platform="generic")


def test_load_report_templates_rejects_empty_format_spec(tmp_path):
    _pair(tmp_path, finding=FINDING.replace("{title}", "{title:}"))
    with pytest.raises(TemplateError, match="format specs are not allowed"):
        load_report_templates(tmp_path, platform="generic")


@pytest.mark.parametrize(
    ("finding", "message"),
    [
        (FINDING + "\n{unknown}\n", "unknown placeholder"),
        (FINDING.replace("{title}", "{title!r}"), "conversions are not allowed"),
        (FINDING.replace("{title}", "{title:>20}"), "format specs are not allowed"),
        (FINDING.replace("{title}", "{finding.title}"), "unknown placeholder"),
        (FINDING.replace("{title}", "{finding[title]}"), "unknown placeholder"),
        (FINDING + "\n{\n", "malformed"),
        (FINDING.replace("{evidence}", ""), "evidence must occur exactly once"),
        (FINDING + "\n{evidence}\n", "evidence must occur exactly once"),
        (
            FINDING.replace("{evidence}", "Evidence: {evidence}"),
            "evidence must be alone on its line",
        ),
        (
            FINDING.replace(
                "{demonstrated_impact}",
                "{demonstrated_impact} {plausible_impact}",
            ).replace("\n{plausible_impact}\n", "\n"),
            "demonstrated_impact must be alone on its line",
        ),
    ],
)
def test_load_report_templates_rejects_invalid_finding_grammar(tmp_path, finding, message):
    _pair(tmp_path, finding=finding)
    with pytest.raises(TemplateError, match=message):
        load_report_templates(tmp_path, platform="generic")


@pytest.mark.parametrize(
    ("report", "message"),
    [
        (REPORT.replace("{findings}", ""), "findings must occur exactly once"),
        (REPORT + "\n{findings}\n", "findings must occur exactly once"),
        (
            REPORT.replace("{findings}", "Results: {findings}"),
            "findings must be alone on its line",
        ),
        (REPORT + "\n{title}\n", "unknown placeholder"),
    ],
)
def test_load_report_templates_rejects_invalid_report_grammar(tmp_path, report, message):
    _pair(tmp_path, report=report)
    with pytest.raises(TemplateError, match=message):
        load_report_templates(tmp_path, platform="generic")


def test_load_report_templates_rejects_missing_or_partial_pair(tmp_path):
    with pytest.raises(TemplateError, match="report.md"):
        load_report_templates(tmp_path, platform="generic")

    platform_dir = tmp_path / "generic"
    platform_dir.mkdir()
    (platform_dir / "report.md").write_text(REPORT, encoding="utf-8")
    with pytest.raises(TemplateError, match="finding.md"):
        load_report_templates(tmp_path, platform="generic")


def test_load_report_templates_rejects_symlink(tmp_path):
    root = _pair(tmp_path)
    report = root / "generic" / "report.md"
    source = root / "source.md"
    source.write_text(REPORT, encoding="utf-8")
    report.unlink()
    report.symlink_to(source)
    with pytest.raises(TemplateError, match="regular non-symlink file"):
        load_report_templates(root, platform="generic")


def test_load_report_templates_rejects_file_changed_between_lstat_and_open(
    tmp_path,
    monkeypatch,
):
    root = _pair(tmp_path)
    report = root / "generic" / "report.md"
    replacement = root / "replacement.md"
    replacement.write_text(REPORT.replace("# ", "# replacement "), encoding="utf-8")
    real_lstat = Path.lstat
    swapped = False

    def lstat_then_swap(path):
        nonlocal swapped
        result = real_lstat(path)
        if path == report and not swapped:
            replacement.replace(report)
            swapped = True
        return result

    monkeypatch.setattr(Path, "lstat", lstat_then_swap)

    with pytest.raises(TemplateError, match="changed while opening"):
        load_report_templates(root, platform="generic")
    assert swapped


def test_load_report_templates_rejects_directory_in_place_of_file(tmp_path):
    root = _pair(tmp_path)
    finding = root / "generic" / "finding.md"
    finding.unlink()
    finding.mkdir()
    with pytest.raises(TemplateError, match="regular non-symlink file"):
        load_report_templates(root, platform="generic")


def test_load_report_templates_rejects_oversized_file(tmp_path):
    root = _pair(tmp_path)
    (root / "generic" / "report.md").write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(TemplateError, match="exceeds 65536 bytes"):
        load_report_templates(root, platform="generic")


def test_load_report_templates_rejects_invalid_utf8(tmp_path):
    root = _pair(tmp_path)
    (root / "generic" / "finding.md").write_bytes(b"\xff")
    with pytest.raises(TemplateError, match="valid UTF-8"):
        load_report_templates(root, platform="generic")
