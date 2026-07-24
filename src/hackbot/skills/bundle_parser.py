"""
bundle_parser — extract reconnaissance notes from the local Recon bundle as
INERT DATA.

Safety contract (tested in tests/recon_bundle/):
  * The bundle HTML is read as a text file and tokenized with the standard
    library ``html.parser`` only. No browser, no JS engine, no ``<script>``
    execution — HTMLParser never runs scripts, it only emits tokens.
  * Every command found in the bundle is captured as a STRING (data). Nothing
    here executes, shells out, or resolves any command. Downstream code must
    convert commands into validated argv adapters; this module never does.
  * The original file is opened read-only and never modified.

Bundle structure (observed):
  <div class="note" id="note-...">
    <div class="frontmatter-bar">
      <span class="fm-badge">recon</span>            # category
      <span class="fm-badge level">intermediario</span>
      <span class="fm-badge updated">↻ 2026-07-17</span>
      <span class="fm-badge">#tag</span> ...
    </div>
    <h1>title</h1>
    <p>explanatory text</p>
    <h2>section</h2> ...
    <div class="codehilite"><pre><code>...command text...</code></pre></div>
    <blockquote> / warning text
    <ul><li>checklist item</li></ul>
"""

from __future__ import annotations

import html
import re
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

# Heuristic markers for warnings inside explanatory prose (pt-BR + en).
_WARN_MARKERS = (
    "cuidado",
    "atencao",
    "atenção",
    "aviso",
    "warning",
    "⚠",
    "nunca",
    "so com autorizacao",
    "só com autorização",
    "com autorizacao",
    "autorizacao",
    "autorização",
    "ilegal",
    "barulho",
    "ruido",
    "ruído",
    "rate limit",
    "rate-limit",
    "bloqueio",
    "ban",
)
_CHECKLIST_HEADINGS = ("checklist",)


@dataclass
class ReconNote:
    note_id: str
    title: str = ""
    category: str = ""
    difficulty: str = ""
    updated: str = ""
    tags: list[str] = field(default_factory=list)
    intro: str = ""  # first explanatory paragraph
    sections: list[str] = field(default_factory=list)  # h2/h3 headings
    commands: list[str] = field(default_factory=list)  # code blocks, as DATA
    warnings: list[str] = field(default_factory=list)
    checklist: list[str] = field(default_factory=list)
    paragraphs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _NoteHTMLParser(HTMLParser):
    """Streaming, non-executing tokenizer that groups content per note div."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.notes: list[ReconNote] = []
        self._cur: ReconNote | None = None
        self._depth = 0  # div depth inside the current note
        # capture state
        self._cap: str | None = None  # what text we are currently capturing
        self._buf: list[str] = []
        self._badge_class = ""
        self._in_code = False
        self._code_depth = 0

    # -- helpers -----------------------------------------------------------
    def _flush(self) -> None:
        text = html.unescape("".join(self._buf)).strip()
        cap, self._cap, self._buf = self._cap, None, []
        if not self._cur or not text:
            return
        if cap == "badge":
            self._absorb_badge(text)
        elif cap == "h1":
            self._cur.title = text
        elif cap in ("h2", "h3"):
            self._cur.sections.append(text)
        elif cap == "p":
            self._cur.paragraphs.append(text)
            if not self._cur.intro:
                self._cur.intro = text
            low = text.lower()
            if any(m in low for m in _WARN_MARKERS):
                self._cur.warnings.append(text)
        elif cap == "li":
            # checklist items live under a "checklist" section; collect all <li>
            self._cur.checklist.append(text)
        elif cap == "code":
            # a full code block reconstructed from inner text nodes = one command
            self._cur.commands.append(text)

    def _absorb_badge(self, text: str) -> None:
        assert self._cur is not None
        cls = self._badge_class
        if "level" in cls:
            self._cur.difficulty = text
        elif "updated" in cls:
            self._cur.updated = text.lstrip("↻ ").strip()
        elif text.startswith("#"):
            self._cur.tags.append(text)
        else:
            if not self._cur.category:
                self._cur.category = text

    # -- token handlers ----------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        cls = a.get("class", "")
        if tag == "div" and "note" in cls.split() and a.get("id", "").startswith("note-"):
            # entering a new note
            self._flush()
            self._cur = ReconNote(note_id=a["id"])
            self._depth = 1
            return
        if self._cur is None:
            return
        # Inside a code block: count nested tags but never touch note depth.
        if self._in_code:
            if tag in ("pre", "code", "span", "div"):
                self._code_depth += 1
            return
        # A code block: consume it whole; do NOT count it in note depth.
        if tag == "div" and "codehilite" in cls:
            self._flush()
            self._in_code = True
            self._code_depth = 1
            self._cap = "code"
            return
        if tag == "div":
            self._depth += 1
        if tag == "span" and "fm-badge" in cls:
            self._flush()
            self._cap = "badge"
            self._badge_class = cls
        elif tag in ("h1", "h2", "h3"):
            self._flush()
            self._cap = tag
        elif tag == "p":
            self._flush()
            self._cap = "p"
        elif tag == "li":
            self._flush()
            self._cap = "li"

    def handle_endtag(self, tag: str) -> None:
        if self._cur is None:
            return
        if self._in_code:
            if tag in ("pre", "code", "span", "div"):
                self._code_depth -= 1
                if self._code_depth <= 0:
                    self._in_code = False
                    self._flush()
            return
        if tag in ("h1", "h2", "h3", "p", "li", "span"):
            self._flush()
        if tag == "div":
            self._depth -= 1
            if self._depth <= 0:
                self._flush()
                self.notes.append(self._cur)
                self._cur = None

    def handle_data(self, data: str) -> None:
        if self._cur is not None and self._cap is not None:
            self._buf.append(data)

    # HTMLParser never executes scripts; we additionally ignore their contents.
    def handle_startendtag(self, tag: str, attrs: Any) -> None:  # pragma: no cover
        pass


def parse_bundle(path: str | Path) -> list[ReconNote]:
    """Parse the bundle file and return the list of notes (as inert data)."""
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    p = _NoteHTMLParser()
    p.feed(raw)
    p.close()
    # post-process: keep only checklist items that belong to notes that HAVE a
    # checklist section; otherwise <li> items are generic and we drop them to
    # avoid noise (dedupe conservatively).
    for note in p.notes:
        has_checklist = any("checklist" in s.lower() for s in note.sections)
        if not has_checklist:
            note.checklist = []
        note.warnings = _dedupe(note.warnings)
        note.commands = [c for c in note.commands if c.strip()]
    return p.notes


def bundle_metadata(path: str | Path) -> dict[str, str]:
    """Extract bundle-level attribution WITHOUT executing anything."""
    raw = Path(path).read_text(encoding="utf-8", errors="replace")

    def _find(pattern: str) -> str:
        m = re.search(pattern, raw, re.I | re.S)
        return html.unescape(re.sub("<[^>]+>", "", m.group(1))).strip() if m else ""

    title = _find(r"<title[^>]*>(.*?)</title>")
    author_link = ""
    m = re.search(r'href="(https?://[^"]*(?:x\.com|twitter\.com)/[^"]+)"', raw, re.I)
    if m:
        author_link = m.group(1)
    credit = _find(r'class="credit">(.*?)</div>')
    has_license = bool(re.search(r"MIT License|Apache License|GPL|Creative Commons|BSD", raw))
    return {
        "title": title,
        "author": credit or "@reeshasx",
        "author_link": author_link,
        "license_declared": "yes" if has_license else "none-found",
    }


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        key = it.strip().lower()
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out
