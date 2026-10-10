"""Chunk freely available standards documents for the Compliance KB layer.

These chunks are NOT attack patterns and are stored in a separate table
(``standards_chunks``) so Threat Agent retrieval over ``threat_patterns`` is
unaffected.  Each chunk keeps a citable locator (PDF page or CRA article).
No standards mapping rules are encoded here; this is reference text only.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from pathlib import Path

from pypdf import PdfReader

MAX_CHARS = 900  # MiniLM truncates near 256 tokens; stay under to avoid silent loss


@dataclass(frozen=True)
class StandardsChunk:
    standard: str
    doc: str
    locator: str
    title: str
    text: str


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace(chr(0xA0), " ")).strip()


def _split(text: str) -> list[str]:
    """Split on sentence-ish boundaries into pieces of at most MAX_CHARS."""
    out: list[str] = []
    cur = ""
    for sent in re.split(r"(?<=[.;:])\s+", text):
        if cur and len(cur) + len(sent) + 1 > MAX_CHARS:
            out.append(cur)
            cur = ""
        cur = f"{cur} {sent}".strip()
        while len(cur) > MAX_CHARS:
            out.append(cur[:MAX_CHARS])
            cur = cur[MAX_CHARS:]
    if cur:
        out.append(cur)
    return out


def load_pdf(path: Path, standard: str, doc: str) -> list[StandardsChunk]:
    chunks: list[StandardsChunk] = []
    for page_no, page in enumerate(PdfReader(str(path)).pages, start=1):
        text = _norm(page.extract_text() or "")
        if len(text) < 80:
            continue
        for part_no, piece in enumerate(_split(text), start=1):
            chunks.append(StandardsChunk(standard, doc, f"p. {page_no}.{part_no}", "", piece))
    return chunks


def load_cra(path: Path) -> list[StandardsChunk]:
    raw = Path(path).read_text(encoding="utf-8")
    parts = raw.split('<div class="eli-subdivision" id="')[1:]
    chunks: list[StandardsChunk] = []
    for part in parts:
        sub_id = part.split('"', 1)[0]
        part = part.split(">", 1)[1] if ">" in part else part
        kind, _, num = sub_id.partition("_")
        if kind not in {"art", "anx", "rct"}:
            continue
        title_m = re.search(r'class="oj-sti-art">(.*?)</p>', part, re.S)
        title = _norm(html.unescape(re.sub(r"<[^>]+>", " ", title_m.group(1)))) if title_m else ""
        body = _norm(html.unescape(re.sub(r"<[^>]+>", " ", part)))
        label = {"art": f"Art. {num}", "anx": f"Annex {num}", "rct": f"Recital {num}"}[kind]
        for i, piece in enumerate(_split(body), start=1):
            if len(piece) >= 40:
                chunks.append(
                    StandardsChunk(
                        "EU CRA", "Regulation (EU) 2024/2847", f"{label}.{i}", title, piece
                    )
                )
    return chunks
