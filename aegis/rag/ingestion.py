"""Document loading, front-matter parsing, chunking and tokenization."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

STOPWORDS = set("""a an and are as at be by for from has have in is it its of on or that the this to was
were will with when what which who why how not no do does did if then than so we you your our they them
their can could should would may might must into over under after before about via per""".split())


@dataclass
class Chunk:
    id: str
    doc_path: str
    title: str
    section: str
    text: str
    meta: dict = field(default_factory=dict)


def split_camel(token: str) -> list[str]:
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", token)
    return [p.lower() for p in parts if p]


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for raw in re.findall(r"[A-Za-z][A-Za-z0-9_\-]*|\d+", text):
        low = raw.lower()
        if low in STOPWORDS or len(low) < 2:
            continue
        tokens.append(low)
        sub = [p for p in re.split(r"[_\-]", raw) if p]
        pieces = []
        for s in sub:
            pieces.extend(split_camel(s))
        if len(pieces) > 1:
            tokens.extend(p for p in pieces if p not in STOPWORDS and len(p) > 1)
    return tokens


def parse_front_matter(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    _, fm, body = text.split("---", 2)
    meta: dict = {}
    for line in fm.strip().splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        v = v.strip()
        if v.startswith("[") and v.endswith("]"):
            meta[k.strip()] = [x.strip() for x in v[1:-1].split(",") if x.strip()]
        else:
            meta[k.strip()] = v
    return meta, body.lstrip()


def chunk_document(path: str, text: str, max_chars: int = 900) -> list[Chunk]:
    meta, body = parse_front_matter(text)
    title = meta.get("title") or path
    sections = re.split(r"(?m)^(?=#{1,3} )", body)
    chunks: list[Chunk] = []
    for sec in sections:
        sec = sec.strip()
        if not sec:
            continue
        heading = sec.splitlines()[0].lstrip("# ").strip() if sec.startswith("#") else title
        buf = ""
        for para in re.split(r"\n\s*\n", sec):
            if len(buf) + len(para) > max_chars and buf:
                chunks.append(Chunk(f"{path}#{len(chunks)}", path, title, heading, buf.strip(), meta))
                buf = ""
            buf += para + "\n\n"
        if buf.strip():
            chunks.append(Chunk(f"{path}#{len(chunks)}", path, title, heading, buf.strip(), meta))
    return chunks


def load_corpus(root: str | Path) -> list[Chunk]:
    root = Path(root)
    chunks: list[Chunk] = []
    for p in sorted(root.rglob("*.md")):
        rel = str(p.relative_to(root))
        chunks.extend(chunk_document(rel, p.read_text()))
    return chunks
