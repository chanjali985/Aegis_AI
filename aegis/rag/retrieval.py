"""Hybrid retrieval: BM25 + dense vectors, fused with Reciprocal Rank Fusion, then reranked.

    query ──► BM25 (sparse) ─────┐
                                 ├─► RRF fusion ─► metadata filter ─► reranker ─► top-k
    query ──► embeddings (dense) ┘

Dense vectors default to LSA embeddings (TF-IDF + truncated SVD) so the system
runs offline; ``SentenceTransformerEmbedder`` is used automatically when the
``sentence-transformers`` package is installed.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

import numpy as np
from rank_bm25 import BM25Okapi

from aegis.rag.ingestion import Chunk, tokenize


class LSAEmbedder:
    name = "lsa-tfidf-svd"

    def __init__(self, dims: int = 64):
        self.dims = dims

    def fit(self, texts: list[str]) -> None:
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vec = TfidfVectorizer(tokenizer=tokenize, lowercase=False, token_pattern=None,
                                   sublinear_tf=True, ngram_range=(1, 2), min_df=1)
        tfidf = self.vec.fit_transform(texts)
        k = max(2, min(self.dims, tfidf.shape[0] - 1, tfidf.shape[1] - 1))
        self.svd = TruncatedSVD(n_components=k, random_state=0)
        self.doc_vectors = self._norm(self.svd.fit_transform(tfidf))

    @staticmethod
    def _norm(m: np.ndarray) -> np.ndarray:
        n = np.linalg.norm(m, axis=1, keepdims=True)
        n[n == 0] = 1
        return m / n

    def embed_query(self, text: str) -> np.ndarray:
        return self._norm(self.svd.transform(self.vec.transform([text])))[0]


class SentenceTransformerEmbedder:  # pragma: no cover - optional dependency
    name = "sentence-transformers"

    def __init__(self, model: str = "all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model)

    def fit(self, texts: list[str]) -> None:
        self.doc_vectors = self.model.encode(texts, normalize_embeddings=True)

    def embed_query(self, text: str) -> np.ndarray:
        return self.model.encode([text], normalize_embeddings=True)[0]


def default_embedder():
    try:
        import sentence_transformers  # noqa: F401
        return SentenceTransformerEmbedder()
    except Exception:  # noqa: BLE001
        return LSAEmbedder()


@dataclass
class Hit:
    chunk: Chunk
    score: float
    bm25_rank: int | None = None
    dense_rank: int | None = None
    fused: float = 0.0
    rerank: float = 0.0

    def to_dict(self) -> dict:
        return {"id": self.chunk.id, "path": self.chunk.doc_path, "title": self.chunk.title,
                "section": self.chunk.section, "text": self.chunk.text, "score": round(self.score, 4),
                "bm25_rank": self.bm25_rank, "dense_rank": self.dense_rank,
                "doc_type": self.chunk.meta.get("type"), "service": self.chunk.meta.get("service"),
                "patterns": self.chunk.meta.get("patterns", [])}


def rrf(rankings: list[list[int]], k: int = 60) -> dict[int, float]:
    scores: dict[int, float] = {}
    for ranking in rankings:
        for rank, idx in enumerate(ranking):
            scores[idx] = scores.get(idx, 0.0) + 1.0 / (k + rank + 1)
    return scores


class Reranker:
    """Feature-based second-stage reranker (a cross-encoder slot).

    Scores each (query, chunk) pair jointly on: query-term coverage, exact error
    signature matches (CamelCase identifiers such as ``DatabaseTimeoutError``),
    bigram overlap, and title match. With ``sentence-transformers`` installed a
    real cross-encoder can be dropped in behind the same ``score`` method.
    """

    SIGNATURE = re.compile(r"\b[A-Z][a-z]+(?:[A-Z][a-z]+)+\b|\b\w+\.\w+_\w+\b")

    def score(self, query: str, chunk: Chunk) -> float:
        q_tokens = set(tokenize(query))
        c_tokens = tokenize(chunk.text + " " + chunk.title)
        c_set = set(c_tokens)
        if not q_tokens:
            return 0.0
        coverage = len(q_tokens & c_set) / len(q_tokens)
        sigs = set(self.SIGNATURE.findall(query))
        sig_hits = sum(1 for s in sigs if s in chunk.text or s in chunk.title)
        sig_score = sig_hits / len(sigs) if sigs else 0.0
        q_bi = {a + " " + b for a, b in zip(tokenize(query), tokenize(query)[1:])}
        c_bi = {a + " " + b for a, b in zip(c_tokens, c_tokens[1:])}
        bigram = len(q_bi & c_bi) / len(q_bi) if q_bi else 0.0
        title = len(q_tokens & set(tokenize(chunk.title))) / len(q_tokens)
        return 0.40 * coverage + 0.35 * sig_score + 0.15 * bigram + 0.10 * title


class HybridRetriever:
    def __init__(self, chunks: list[Chunk], embedder=None, reranker: Reranker | None = None):
        self.chunks = chunks
        self.bm25 = BM25Okapi([tokenize(c.title + " " + c.section + " " + c.text) for c in chunks])
        self.embedder = embedder or default_embedder()
        self.embedder.fit([c.title + "\n" + c.text for c in chunks])
        self.reranker = reranker or Reranker()

    def _filter(self, idx: int, filters: dict | None) -> bool:
        if not filters:
            return True
        meta = self.chunks[idx].meta
        for key, want in filters.items():
            if want is None:
                continue
            have = meta.get(key)
            if isinstance(have, list):
                if want not in have:
                    return False
            elif have != want:
                return False
        return True

    def bm25_ranking(self, query: str) -> list[int]:
        scores = self.bm25.get_scores(tokenize(query))
        return [int(i) for i in np.argsort(-scores) if scores[i] > 0]

    def dense_ranking(self, query: str) -> list[int]:
        q = self.embedder.embed_query(query)
        sims = self.embedder.doc_vectors @ q
        return [int(i) for i in np.argsort(-sims)]

    def search(self, query: str, k: int = 5, mode: str = "hybrid_rerank", filters: dict | None = None,
               candidates: int = 20) -> list[Hit]:
        bm = self.bm25_ranking(query)
        dn = self.dense_ranking(query) if mode != "bm25" else []
        if mode == "bm25":
            order = {i: 1.0 / (r + 1) for r, i in enumerate(bm)}
        elif mode == "dense":
            order = {i: 1.0 / (r + 1) for r, i in enumerate(dn)}
        else:
            order = rrf([bm[:candidates * 2], dn[:candidates * 2]])
        ranked = sorted((i for i in order if self._filter(i, filters)), key=lambda i: -order[i])[:candidates]
        bm_pos = {i: r for r, i in enumerate(bm)}
        dn_pos = {i: r for r, i in enumerate(dn)}
        hits = [Hit(self.chunks[i], order[i], bm_pos.get(i), dn_pos.get(i), fused=order[i]) for i in ranked]
        if mode == "hybrid_rerank" and hits:
            max_f = max(h.fused for h in hits)
            for h in hits:
                h.rerank = self.reranker.score(query, h.chunk)
                h.score = 0.6 * h.rerank + 0.4 * (h.fused / max_f)
            hits.sort(key=lambda h: -h.score)
        # one hit per document keeps the context diverse
        seen, out = set(), []
        for h in hits:
            if h.chunk.doc_path in seen:
                continue
            seen.add(h.chunk.doc_path)
            out.append(h)
            if len(out) == k:
                break
        return out


def recall_at_k(hits: list[Hit], relevant: set[str], k: int) -> float:
    got = {h.chunk.doc_path for h in hits[:k]}
    return 1.0 if got & relevant else 0.0


def mrr(hits: list[Hit], relevant: set[str]) -> float:
    for i, h in enumerate(hits):
        if h.chunk.doc_path in relevant:
            return 1.0 / (i + 1)
    return 0.0


def ndcg_at_k(hits: list[Hit], relevant: set[str], k: int) -> float:
    dcg = sum(1.0 / math.log2(i + 2) for i, h in enumerate(hits[:k]) if h.chunk.doc_path in relevant)
    ideal = sum(1.0 / math.log2(i + 2) for i in range(min(k, len(relevant))))
    return dcg / ideal if ideal else 0.0
