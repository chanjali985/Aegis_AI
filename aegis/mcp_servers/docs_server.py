"""Documentation MCP server: hybrid (BM25 + dense + rerank) search over engineering docs.

Run standalone:  python -m aegis.mcp_servers.docs_server --workspace <ws>
"""
from __future__ import annotations

import argparse
from functools import lru_cache
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from aegis.rag.ingestion import load_corpus, parse_front_matter
from aegis.rag.retrieval import HybridRetriever


def retriever_for(docs_dir: str) -> HybridRetriever:
    stamp = max((p.stat().st_mtime_ns for p in Path(docs_dir).rglob("*.md")), default=0)
    return _retriever(docs_dir, stamp)


@lru_cache(maxsize=8)
def _retriever(docs_dir: str, _stamp: int) -> HybridRetriever:
    return HybridRetriever(load_corpus(docs_dir))


def build_server(workspace: str | Path) -> FastMCP:
    docs = Path(workspace) / "docs"
    mcp = FastMCP("docs", instructions="Engineering documentation: architecture, runbooks, postmortems.")

    @mcp.tool()
    def search_docs(query: str, k: int = 5, doc_type: str | None = None, service: str | None = None,
                    mode: str = "hybrid_rerank") -> dict:
        """Hybrid search. `doc_type` in architecture|runbook|postmortem|policy|guide.

        `mode` is one of bm25 | dense | hybrid | hybrid_rerank (default).
        """
        r = retriever_for(str(docs))
        hits = r.search(query, k=k, mode=mode, filters={"type": doc_type, "service": service})
        return {"query": query, "mode": mode, "embedder": r.embedder.name,
                "hits": [h.to_dict() for h in hits]}

    @mcp.tool()
    def search_runbook(symptom: str, k: int = 3) -> dict:
        """Search runbooks for a symptom or error signature."""
        return search_docs(symptom, k=k, doc_type="runbook")

    @mcp.tool()
    def get_document(path: str) -> dict:
        """Full document with its metadata."""
        p = (docs / path).resolve()
        if not str(p).startswith(str(docs.resolve())) or not p.exists():
            raise ValueError("document not found")
        meta, body = parse_front_matter(p.read_text())
        return {"path": path, "meta": meta, "content": body}

    @mcp.tool()
    def list_documents(doc_type: str | None = None) -> dict:
        """List documents with title, type and service."""
        out = []
        for p in sorted(docs.rglob("*.md")):
            meta, _ = parse_front_matter(p.read_text())
            if doc_type and meta.get("type") != doc_type:
                continue
            out.append({"path": str(p.relative_to(docs)), "title": meta.get("title"), "type": meta.get("type"),
                        "service": meta.get("service")})
        return {"documents": out}

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    build_server(ap.parse_args().workspace).run("stdio")


if __name__ == "__main__":
    main()
