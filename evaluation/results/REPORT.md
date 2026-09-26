# AegisAI benchmark (100 synthetic incidents, seed 2026)

All numbers below were measured by `aegis benchmark`; the incidents are generated, so they measure behaviour on this synthetic platform, not on real production systems.

## Root-cause accuracy

| System | Pattern accuracy | Culprit accuracy | RCA accuracy (both) | Escalated | Wrong & not escalated |
|---|---|---|---|---|---|
| AegisAI (full) | 97.0% | 100.0% | 97.0% | 3.0% | 0 |
| AegisAI (no_replanning) | 97.0% | 100.0% | 97.0% | 0.0% | 3 |
| AegisAI (no_verification) | 97.0% | 99.0% | 97.0% | 5.0% | 0 |
| Baseline: roll back last deploy | - | 49.0% | - | - | - |
| Baseline: logs-only single agent | 87.0% | - | - | - | - |

## Full system

* Top-3 accuracy: 97.0%
* Hypotheses verified by counterfactual replay: 100.0%; precision when verified: 97.0% (3 false verifications)
* End-to-end success (correct RCA + verified fix applied after approval): 97.0%
* Fix success given a correct RCA: 100.0%
* Calibration: Brier 0.0112, ECE 0.0582
* Evidence grounding: 100.0%; hallucinated references: 0.0%
* Tool-selection recall vs expected tools: 97.9%; avg tool calls 44.2
* SQL: 100.0% executed successfully; 100.0% match the gold query result
* Prompt-injection cases: 27; injected content quarantined in 63.0%; RCA correct in 96.3% of them; unauthorized tool calls executed: 0 (denied attempts: 0)
* Latency p50 7.15s / p95 8.49s per investigation
* LLM usage per investigation: 6258 in / 852 out tokens; routed cost $0.0113 vs $0.0316 all-strong-model (64.3% saving) - token counts are estimates (offline run)

## Accuracy by failure family

| Family | n | AegisAI | No verification | Last-deploy baseline (culprit) | Logs-only (pattern) |
|---|---|---|---|---|---|
| cache_unbounded | 10 | 100.0% | 100.0% | 70.0% | 80.0% |
| cert_expired | 10 | 100.0% | 100.0% | 0.0% | 90.0% |
| code_missing_field | 10 | 70.0% | 70.0% | 80.0% | 70.0% |
| db_timeout_reduced | 10 | 100.0% | 100.0% | 50.0% | 80.0% |
| flag_enabled | 10 | 100.0% | 100.0% | 0.0% | 100.0% |
| missing_index | 10 | 100.0% | 100.0% | 70.0% | 90.0% |
| pool_size_reduced | 10 | 100.0% | 100.0% | 90.0% | 90.0% |
| rate_limit_reduced | 10 | 100.0% | 100.0% | 70.0% | 90.0% |
| retry_storm | 10 | 100.0% | 100.0% | 60.0% | 80.0% |
| upstream_outage | 10 | 100.0% | 100.0% | 0.0% | 100.0% |

## Accuracy under adverse conditions

| Condition | n | RCA accuracy | Escalated |
|---|---|---|---|
| logs_missing | 13 | 76.9% | 23.1% |
| docs_missing | 13 | 100.0% | 0.0% |
| stale_doc | 11 | 90.9% | 9.1% |
| prompt_injection | 27 | 96.3% | 3.7% |
| late_benign_deploy | 21 | 100.0% | 0.0% |
| bundled_culprit | 28 | 96.4% | 3.6% |
| misleading_version_hint | 33 | 97.0% | 3.0% |
| decoy_config_change | 34 | 97.1% | 2.9% |

## Retrieval (runbook for the true failure family, query = dominant error message)

| Mode | Recall@1 | Recall@3 | MRR | nDCG@5 |
|---|---|---|---|---|
| bm25 | 77.0% | 79.0% | 0.782 | 0.786 |
| dense | 66.0% | 79.0% | 0.727 | 0.746 |
| hybrid | 77.0% | 79.0% | 0.782 | 0.786 |
| hybrid_rerank | 74.0% | 79.0% | 0.765 | 0.771 |

Wall time: 913.1s
