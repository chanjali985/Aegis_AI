from aegis.agents.rca import score_patterns


def ev(i, kind, **data):
    return {"id": i, "agent": "t", "kind": kind, "summary": kind, "data": data}


SPIKE = ev("s1", "error_spike", error_type="DatabaseTimeoutError", timeout_ms=1000, frame=None, onset="t")
TIMEOUT_CHANGE = ev("c1", "config_change", key="db.timeout_ms", old=5000, new=1000, direction="decreased",
                    minutes_before_onset=3, commit="abc", version="2.7.1", file="f", subject="s", author="a",
                    deployed_at="2026-01-01T00:00:00Z")
DROP_INDEX = ev("m1", "migration_change", dropped_indexes=["idx_payments_customer_id"], created_indexes=[],
                minutes_before_onset=4, commit="def", version="2.7.2", file="m", subject="s",
                deployed_at="2026-01-01T00:00:00Z")


def test_timeout_config_explains_timeouts_when_db_latency_is_flat():
    evidence = [SPIKE, TIMEOUT_CHANGE, ev("l1", "metric_shift", metric="db_latency_p95_ms", direction="flat")]
    top = score_patterns(evidence, {"service": "payment-service"})[0]
    assert top.pattern == "db_timeout_reduced"
    assert top.culprit["commit"] == "abc"
    assert top.confidence > 0.9


def test_same_signature_points_to_index_when_db_latency_rises():
    evidence = [SPIKE, DROP_INDEX, ev("l1", "metric_shift", metric="db_latency_p95_ms", direction="up"),
                ev("q1", "query_regression", fingerprint="SELECT", factor=12)]
    hyps = score_patterns(evidence, {"service": "payment-service"})
    assert hyps[0].pattern == "missing_index"
    timeout = next(h for h in hyps if h.pattern == "db_timeout_reduced")
    assert any(c["weight"] < 0 for c in timeout.contradicting)


def test_no_evidence_means_unknown():
    assert score_patterns([], {"service": "x"})[0].pattern == "unknown"


def test_rejected_patterns_are_excluded():
    evidence = [SPIKE, TIMEOUT_CHANGE]
    hyps = score_patterns(evidence, {}, rejected=["db_timeout_reduced"])
    assert all(h.pattern != "db_timeout_reduced" for h in hyps)


def test_confidences_are_a_distribution():
    hyps = score_patterns([SPIKE, TIMEOUT_CHANGE], {})
    assert abs(sum(h.confidence for h in hyps) - 1) < 0.01
