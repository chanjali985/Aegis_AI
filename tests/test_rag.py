from aegis.rag.ingestion import chunk_document, load_corpus, tokenize
from aegis.rag.retrieval import HybridRetriever, mrr, ndcg_at_k, recall_at_k, rrf


def test_tokenizer_splits_identifiers():
    toks = tokenize("DatabaseTimeoutError on db.timeout_ms")
    assert "databasetimeouterror" in toks and "timeout" in toks and "database" in toks


def test_front_matter_and_chunking():
    text = "---\ntitle: T\ntype: runbook\npatterns: [a, b]\n---\n# H1\n\npara one\n\n## H2\n\npara two\n"
    chunks = chunk_document("x.md", text)
    assert chunks[0].meta["patterns"] == ["a", "b"] and chunks[0].title == "T"
    assert {c.section for c in chunks} == {"H1", "H2"}


def test_rrf_rewards_agreement():
    scores = rrf([[1, 2, 3], [2, 1, 3]])
    assert scores[1] == scores[2] > scores[3]


def test_hybrid_search_finds_runbook(demo_ws):
    r = HybridRetriever(load_corpus(demo_ws / "docs"))
    hits = r.search("ConnectionPoolExhausted: timed out waiting for a connection from pool", k=3,
                    filters={"type": "runbook"})
    assert hits[0].chunk.doc_path == "runbooks/pool_size_reduced.md"
    for mode in ("bm25", "dense", "hybrid", "hybrid_rerank"):
        assert r.search("certificate has expired SSLError", k=5, mode=mode)


def test_ir_metrics():
    class H:  # minimal hit stub
        def __init__(self, p):
            self.chunk = type("C", (), {"doc_path": p})
    hits = [H("a"), H("b"), H("c")]
    assert recall_at_k(hits, {"b"}, 1) == 0 and recall_at_k(hits, {"b"}, 2) == 1
    assert mrr(hits, {"c"}) == 1 / 3
    assert 0 < ndcg_at_k(hits, {"b"}, 3) < 1
