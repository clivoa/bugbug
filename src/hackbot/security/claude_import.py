"""
claude_import — migrate plaintext gateway tokens from Claude Code project settings
files into the OS keychain, secret-safely.

Rules honored:
  * Token VALUES are never returned, logged, or printed — only presence + length.
  * `--dry-run` reads nothing into storage; it reports the plan only.
  * Placeholder values (e.g. REPLACE_WITH_...) are skipped, not imported.
  * The caller decides WHICH directory/files to process. The original files are
    never modified or deleted by this module.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

# default filename -> canonical secret name mapping
DEFAULT_MAP: dict[str, str] = {
    "settings.deepseek.json": "DEEPSEEK_API_KEY",
    "settings.kimi.json": "MOONSHOT_API_KEY",
    "settings.moonshot.json": "MOONSHOT_API_KEY",
    "settings.anthropic.json": "ANTHROPIC_API_KEY",
}

_TOKEN_KEY = "ANTHROPIC_AUTH_TOKEN"
_PLACEHOLDER_HINTS = ("REPLACE_WITH", "YOUR_", "CHANGEME", "<", "xxxxx")


@dataclass
class ImportResult:
    source: str
    secret_name: str
    status: str  # would-import | imported | placeholder-skipped | no-token | missing-file
    token_len: int = 0  # length only — never the value

    def to_dict(self) -> dict:
        return asdict(self)


def _looks_placeholder(value: str) -> bool:
    v = value.strip()
    return (not v) or any(h in v.upper() for h in (h.upper() for h in _PLACEHOLDER_HINTS))


def _extract_token(path: Path) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return (data.get("env") or {}).get(_TOKEN_KEY)


def plan_imports(
    directory: str | Path, mapping: dict[str, str] | None = None
) -> list[ImportResult]:
    """Read matching settings files and return the plan (no storage, values hidden)."""
    d = Path(directory)
    m = mapping or DEFAULT_MAP
    results: list[ImportResult] = []
    for filename, secret_name in m.items():
        path = d / filename
        if not path.exists():
            continue  # only report files that exist
        token = _extract_token(path)
        if token is None:
            results.append(ImportResult(str(path), secret_name, "no-token"))
        elif _looks_placeholder(token):
            results.append(ImportResult(str(path), secret_name, "placeholder-skipped"))
        else:
            results.append(
                ImportResult(str(path), secret_name, "would-import", token_len=len(token))
            )
    return results


def apply_imports(
    directory: str | Path,
    manager,
    mapping: dict[str, str] | None = None,
    *,
    force: bool = False,
) -> list[ImportResult]:
    """Import real (non-placeholder) tokens into the keychain via the manager.

    Safety:
      * COLLISION: if a secret already exists it is SKIPPED (status
        "exists-skipped") unless ``force=True`` (then status "replaced").
        Never silently overwritten.
      * write/verify FAILURES are caught: status "write-failed" (name only, no
        value); the batch continues and reports partial completion.
      * Originals are NOT modified. Values are never printed.
    """
    d = Path(directory)
    m = mapping or DEFAULT_MAP
    out: list[ImportResult] = []
    for r in plan_imports(d, m):
        if r.status != "would-import":
            out.append(r)
            continue
        existed = manager.exists(r.secret_name)
        if existed and not force:
            out.append(
                ImportResult(r.source, r.secret_name, "exists-skipped", token_len=r.token_len)
            )
            continue
        token = _extract_token(d / Path(r.source).name)
        if token is None:  # defensive: file changed between plan and apply
            out.append(ImportResult(r.source, r.secret_name, "no-token"))
            continue
        try:
            manager.set(r.secret_name, token)
            if manager.get(r.secret_name) != token:  # verify round-trip
                raise RuntimeError("post-write verification mismatch")
            status = "replaced" if existed else "imported"
            out.append(ImportResult(r.source, r.secret_name, status, token_len=len(token)))
        except Exception:  # noqa: BLE001 — never surface the value/traceback
            out.append(ImportResult(r.source, r.secret_name, "write-failed", token_len=len(token)))
    return out


def summarize(results: list[ImportResult]) -> tuple[int, int, int]:
    """Return (succeeded, skipped, failed) counts for partial-completion reporting."""
    ok = sum(1 for r in results if r.status in ("imported", "replaced"))
    failed = sum(1 for r in results if r.status == "write-failed")
    skipped = sum(
        1 for r in results if r.status in ("exists-skipped", "placeholder-skipped", "no-token")
    )
    return ok, skipped, failed


def render_plan(results: list[ImportResult], applied: bool = False) -> str:
    if not results:
        return "no matching Claude settings files found (nothing to import)"
    verb = "IMPORTED" if applied else "WOULD IMPORT"
    lines = []
    for r in results:
        n, src = f"{r.secret_name:<18}", r.source
        if r.status in ("would-import", "imported", "replaced"):
            tag = {"would-import": verb, "imported": "IMPORTED", "replaced": "REPLACED"}[r.status]
            lines.append(f"  [{tag}] {n} <- {src}  (token length {r.token_len}, value not shown)")
        elif r.status == "exists-skipped":
            lines.append(f"  [skip]  {n} <- {src}  (already in keychain; use --force to replace)")
        elif r.status == "placeholder-skipped":
            lines.append(f"  [skip]  {n} <- {src}  (placeholder, not a real token)")
        elif r.status == "no-token":
            lines.append(f"  [skip]  {n} <- {src}  (no {_TOKEN_KEY} field)")
        elif r.status == "write-failed":
            lines.append(f"  [FAIL]  {n} <- {src}  (keychain write/verify failed; value not shown)")
    if applied:
        ok, skipped, failed = summarize(results)
        lines.append(f"  summary: {ok} imported, {skipped} skipped, {failed} failed")
    lines.append("  originals left untouched; verify with: hackbot secrets test <name>")
    return "\n".join(lines)
