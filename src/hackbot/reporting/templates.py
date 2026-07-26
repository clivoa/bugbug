"""Load and validate inert operator-owned Markdown report templates."""

from __future__ import annotations

import os
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from string import Formatter

_MAX_TEMPLATE_BYTES = 64 * 1024
_REPORT_FIELDS = frozenset({"engagement_id", "platform_label", "finding_count", "findings"})
_FINDING_FIELDS = frozenset(
    {
        "finding_id",
        "title",
        "severity",
        "status",
        "vulnerability_type",
        "target",
        "action_id",
        "evidence",
        "summary",
        "reproduction_steps",
        "demonstrated_impact",
        "plausible_impact",
    }
)
_REPORT_REQUIRED = frozenset({"findings"})
_FINDING_REQUIRED = frozenset({"evidence", "demonstrated_impact", "plausible_impact"})


class TemplateError(ValueError):
    """A selected report template pair is missing, unsafe, or malformed."""


@dataclass(frozen=True, slots=True)
class ReportTemplates:
    report: str
    finding: str


def _validate_plain_replacement_fields(text: str, *, label: str) -> None:
    index = 0
    while index < len(text):
        brace = text[index]
        if brace not in "{}":
            index += 1
            continue
        if index + 1 < len(text) and text[index + 1] == brace:
            index += 2
            continue
        if brace == "}":
            index += 1
            continue
        field_end = text.find("}", index + 1)
        if field_end == -1:
            break
        field = text[index + 1 : field_end]
        if "!" in field:
            raise TemplateError(f"{label} template placeholder conversions are not allowed")
        if ":" in field:
            raise TemplateError(f"{label} template placeholder format specs are not allowed")
        index = field_end + 1


def _validate_template(
    text: str,
    *,
    label: str,
    allowed: frozenset[str],
    required: frozenset[str],
) -> None:
    _validate_plain_replacement_fields(text, label=label)
    try:
        parsed = list(Formatter().parse(text))
    except ValueError as exc:
        raise TemplateError(f"{label} template is malformed: {exc}") from exc

    names: list[str] = []
    for _literal, field_name, format_spec, conversion in parsed:
        if field_name is None:
            continue
        if field_name not in allowed:
            raise TemplateError(f"{label} template has unknown placeholder {field_name!r}")
        if conversion is not None:
            raise TemplateError(f"{label} template placeholder conversions are not allowed")
        if format_spec:
            raise TemplateError(f"{label} template placeholder format specs are not allowed")
        names.append(field_name)

    counts = Counter(names)
    stripped_lines = [
        line.strip(" \t") for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ]
    for field_name in sorted(required):
        if counts[field_name] != 1:
            raise TemplateError(f"{label} template: {field_name} must occur exactly once")
        if stripped_lines.count("{" + field_name + "}") != 1:
            raise TemplateError(f"{label} template: {field_name} must be alone on its line")


def _read_template(path: Path) -> str:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise TemplateError(f"template file unavailable: {path.name}: {exc}") from exc
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
        raise TemplateError(f"template file must be a regular non-symlink file: {path.name}")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
        try:
            opened_stat = os.fstat(descriptor)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise TemplateError(f"template file must open as a regular file: {path.name}")
            if (opened_stat.st_dev, opened_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
                raise TemplateError(f"template file changed while opening: {path.name}")

            raw = bytearray()
            read_limit = _MAX_TEMPLATE_BYTES + 1
            while len(raw) < read_limit:
                chunk = os.read(descriptor, read_limit - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise TemplateError(f"template file unreadable: {path.name}: {exc}") from exc
    if len(raw) > _MAX_TEMPLATE_BYTES:
        raise TemplateError(f"template file {path.name} exceeds {_MAX_TEMPLATE_BYTES} bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TemplateError(f"template file {path.name} is not valid UTF-8") from exc


def load_report_templates(root: str | Path, *, platform: str) -> ReportTemplates:
    platform_dir = Path(root) / platform
    report = _read_template(platform_dir / "report.md")
    finding = _read_template(platform_dir / "finding.md")
    _validate_template(
        report,
        label="report",
        allowed=_REPORT_FIELDS,
        required=_REPORT_REQUIRED,
    )
    _validate_template(
        finding,
        label="finding",
        allowed=_FINDING_FIELDS,
        required=_FINDING_REQUIRED,
    )
    return ReportTemplates(report=report, finding=finding)
