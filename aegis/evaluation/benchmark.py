"""Benchmark: run AegisAI over N generated incidents and score it against the answer key.

    python -m aegis.cli benchmark --n 100 --ablations

For every incident the same workspace is investigated by the full system, by
ablated variants, and by two baselines, so all rows of the comparison table
share exactly the same inputs.
"""
from __future__ import annotations

import asyncio
import json
import math
import shutil
import sqlite3
import statistics
import subprocess
import time
import uuid
from collections import defaultdict
from pathlib import Path

from aegis.evaluation import baselines
from aegis.mcp_servers.observability_server import build_server as obs_server
from aegis.orchestration.runner import InvestigationService
from aegis.rag.ingestion import load_corpus
from aegis.rag.retrieval import HybridRetriever, mrr, ndcg_at_k, recall_at_k
from aegis.storage.db import Store, set_store
from aegis.world.catalog import FAMILIES
from aegis.world.generator import build_workspace, load_truth, sample_spec

CONFIGS = {
    "full": {},
    "no_verification": {"verification": False, "fix": False},
    "no_replanning": {"replanning": False, "fix": False},
}
RETRIEVAL_MODES = ["bm25", "dense", "hybrid", "hybrid_rerank"]


def culprit_match(pred: dict, truth: dict) -> bool:
    t = truth["culprit"]
    if not pred:
        return False
    if t["type"] == "commit":
        return pred.get("commit") in (t["commit"], t.get("deploy_sha"))
    return pred.get("type") == t["type"] and pred.get("id") == t["id"]


def commit_exists(ws: Path, sha: str) -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=ws / "repo",
                          capture_output=True).returncode == 0


def sql_accuracy(ws: Path, entries: list[dict]) -> tuple[int, int, int]:
    total = ok = accurate = 0
    con = sqlite3.connect(f"file:{ws / 'prod_replica.db'}?mode=ro", uri=True)
    try:
        for e in entries:
            total += 1
            final = next((a for a in reversed(e["attempts"]) if not a["errors"]), None)
            if not final:
                continue
            ok += 1
            try:
                got = sorted(map(tuple, con.execute(final["sql"]).fetchall()), key=str)
                want = sorted(map(tuple, con.execute(e["gold_sql"]).fetchall()), key=str)
                accurate += int(got == want)
            except sqlite3.Error:
                pass
    finally:
        con.close()
    return total, ok, accurate


async def retrieval_case(ws: Path, truth: dict, service: str, request: str) -> dict:
    retriever = HybridRetriever(load_corpus(ws / "docs"))
    result = await obs_server(ws).call_tool("find_error_spikes", {"service": service})
    data = result[1] if isinstance(result, tuple) else json.loads(result[0].text)
    data = data.get("result", data)
    spikes = [s for s in data["spikes"] if s["llr"] >= 8]
    query = f"{spikes[0]['sample']}" if spikes else request
    relevant = {f"runbooks/{truth['family']}.md"}
    out = {}
    for mode in RETRIEVAL_MODES:
        hits = retriever.search(query, k=5, mode=mode)
        out[mode] = {"recall@1": recall_at_k(hits, relevant, 1), "recall@3": recall_at_k(hits, relevant, 3),
                     "mrr": mrr(hits, relevant), "ndcg@5": ndcg_at_k(hits, relevant, 5)}
    return out


def score_run(ws: Path, truth: dict, report: dict, store: Store, run_id: str, elapsed: float) -> dict:
    root = report.get("root_cause") or {}
    hyps = report.get("hypotheses") or []
    pattern = root.get("pattern", "unknown")
    confidence = root.get("confidence", 0.0)
    pattern_ok = pattern == truth["family"]
    culprit_ok = culprit_match(root.get("culprit") or {}, truth)
    tools = store.tool_calls(run_id)
    used = {t["tool"] for t in tools if t["ok"]}
    expected = set(truth["expected_tools"])
    llm = store.llm_calls(run_id)
    sec = store.security_events(run_id)
    db_entries = []
    for r in (report.get("_results") or []):
        if r["agent"] == "database":
            db_entries += r["data"].get("sql", [])
    sql_total, sql_ok, sql_acc = sql_accuracy(ws, db_entries)
    culprit_commit = (root.get("culprit") or {}).get("commit")
    hallucinated = bool(
        not report["grounding"]["grounded"] or (culprit_commit and not commit_exists(ws, culprit_commit)))
    verification = report.get("verification") or {}
    fixv = report.get("fix_verification") or {}
    return {
        "status": report["status"], "pattern": pattern, "confidence": confidence,
        "correct": pattern_ok and culprit_ok, "pattern_correct": pattern_ok, "culprit_correct": culprit_ok,
        "top3": truth["family"] in [h["pattern"] for h in hyps[:3]],
        "verified": verification.get("verdict") == "verified",
        "fix_verified": fixv.get("verdict") == "verified",
        "applied": bool((report.get("applied") or {}).get("ok")),
        "escalated": report["status"] in ("escalated", "needs_input"),
        "grounded": report["grounding"]["grounded"], "hallucination": hallucinated,
        "tool_recall": len(used & expected) / len(expected) if expected else 1.0,
        "tool_calls": len(tools), "denied_calls": sum(t["denied"] for t in tools),
        "sql_total": sql_total, "sql_ok": sql_ok, "sql_accurate": sql_acc,
        "injection_detected": any(s["kind"] == "prompt_injection_quarantined" for s in sec),
        "latency_s": round(elapsed, 2),
        "input_tokens": sum(c["input_tokens"] for c in llm), "output_tokens": sum(c["output_tokens"] for c in llm),
        "cost_usd": sum(c["cost_usd"] for c in llm), "baseline_cost_usd": sum(c["baseline_cost_usd"] for c in llm),
        "llm_estimated": any(c["estimated"] for c in llm),
        "replans": report["stats"]["replans"], "reflections": report["stats"]["reflections"],
        "waves": report["stats"]["waves"],
    }


def rate(rows: list[dict], key: str) -> float | None:
    vals = [r[key] for r in rows if r.get(key) is not None]
    return round(sum(bool(v) for v in vals) / len(vals), 4) if vals else None


def calibration(rows: list[dict], bins: int = 5) -> dict:
    if not rows:
        return {}
    brier = sum((r["confidence"] - float(r["correct"])) ** 2 for r in rows) / len(rows)
    ece = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [r for r in rows if lo <= r["confidence"] < hi or (b == bins - 1 and r["confidence"] == 1.0)]
        if sel:
            acc = sum(r["correct"] for r in sel) / len(sel)
            conf = sum(r["confidence"] for r in sel) / len(sel)
            ece += len(sel) / len(rows) * abs(acc - conf)
    return {"brier": round(brier, 4), "ece": round(ece, 4)}


def summarize(cases: list[dict]) -> dict:
    out: dict = {"n": len(cases), "configs": {}, "baselines": {}, "retrieval": {}, "by_family": {},
                 "by_condition": {}}
    configs = sorted({c for case in cases for c in case["runs"]})
    for cfg in configs:
        rows = [case["runs"][cfg] for case in cases if cfg in case["runs"]]
        verified = [r for r in rows if r["verified"]]
        lat = sorted(r["latency_s"] for r in rows)
        s = {
            "rca_accuracy": rate(rows, "correct"), "pattern_accuracy": rate(rows, "pattern_correct"),
            "culprit_accuracy": rate(rows, "culprit_correct"), "top3_accuracy": rate(rows, "top3"),
            "verified_rate": rate(rows, "verified"),
            "precision_when_verified": rate(verified, "correct") if verified else None,
            "false_verifications": sum(1 for r in verified if not r["correct"]),
            "escalation_rate": rate(rows, "escalated"),
            "wrong_and_not_escalated": sum(1 for r in rows if not r["correct"] and not r["escalated"]),
            "grounded_rate": rate(rows, "grounded"), "hallucination_rate": rate(rows, "hallucination"),
            "tool_recall": round(statistics.mean(r["tool_recall"] for r in rows), 4),
            "avg_tool_calls": round(statistics.mean(r["tool_calls"] for r in rows), 1),
            "denied_tool_calls": sum(r["denied_calls"] for r in rows),
            "sql_success_rate": round(sum(r["sql_ok"] for r in rows) / max(1, sum(r["sql_total"] for r in rows)), 4),
            "sql_accuracy": round(sum(r["sql_accurate"] for r in rows) / max(1, sum(r["sql_total"] for r in rows)), 4),
            "latency_p50_s": lat[len(lat) // 2], "latency_p95_s": lat[int(0.95 * (len(lat) - 1))],
            "avg_input_tokens": round(statistics.mean(r["input_tokens"] for r in rows)),
            "avg_output_tokens": round(statistics.mean(r["output_tokens"] for r in rows)),
            "avg_cost_usd": round(statistics.mean(r["cost_usd"] for r in rows), 5),
            "avg_cost_all_strong_usd": round(statistics.mean(r["baseline_cost_usd"] for r in rows), 5),
            "llm_costs_estimated": any(r["llm_estimated"] for r in rows),
            "avg_replans": round(statistics.mean(r["replans"] for r in rows), 2),
            "avg_reflections": round(statistics.mean(r["reflections"] for r in rows), 2),
            **calibration(rows),
        }
        if s["avg_cost_all_strong_usd"]:
            s["routing_cost_saving"] = round(1 - s["avg_cost_usd"] / s["avg_cost_all_strong_usd"], 4)
        if cfg == "full":
            fixable = [r for r in rows if r["correct"]]
            s["fix_success_rate_given_correct_rca"] = rate(fixable, "applied") if fixable else None
            s["end_to_end_success"] = round(sum(1 for r in rows if r["correct"] and r["applied"]) / len(rows), 4)
            inj = [case for case in cases if case["injection"]]
            s["injection_cases"] = len(inj)
            s["injection_detected_rate"] = rate([c["runs"]["full"] for c in inj], "injection_detected") if inj else None
            s["injection_cases_correct"] = rate([c["runs"]["full"] for c in inj], "correct") if inj else None
        out["configs"][cfg] = s
    for name in ("naive_last_deploy", "logs_only_agent"):
        rows = [case["baselines"][name] for case in cases]
        out["baselines"][name] = {"pattern_accuracy": rate(rows, "pattern_correct"),
                                  "culprit_accuracy": rate(rows, "culprit_correct")}
    for mode in RETRIEVAL_MODES:
        rows = [case["retrieval"][mode] for case in cases]
        out["retrieval"][mode] = {k: round(statistics.mean(r[k] for r in rows), 4) for k in rows[0]}
    fam_rows = defaultdict(list)
    for case in cases:
        fam_rows[case["family"]].append(case)
    for fam, cs in sorted(fam_rows.items()):
        out["by_family"][fam] = {
            "n": len(cs), "full": rate([c["runs"]["full"] for c in cs], "correct"),
            "no_verification": rate([c["runs"]["no_verification"] for c in cs if "no_verification" in c["runs"]],
                                    "correct"),
            "naive_last_deploy": rate([c["baselines"]["naive_last_deploy"] for c in cs], "culprit_correct"),
            "logs_only_agent": rate([c["baselines"]["logs_only_agent"] for c in cs], "pattern_correct"),
            "escalated": rate([c["runs"]["full"] for c in cs], "escalated")}
    conds = {"logs_missing": lambda s: s["logs_missing"], "docs_missing": lambda s: s["docs_missing"],
             "stale_doc": lambda s: s["stale_doc"], "prompt_injection": lambda s: bool(s["injection"]),
             "late_benign_deploy": lambda s: s["late_benign_deploy"],
             "bundled_culprit": lambda s: s["bundled_culprit"],
             "misleading_version_hint": lambda s: s["version_hint"] == "red_herring",
             "decoy_config_change": lambda s: s.get("decoy_change", False)}
    for name, pred in conds.items():
        cs = [c for c in cases if pred(c["spec"])]
        if cs:
            out["by_condition"][name] = {"n": len(cs), "full": rate([c["runs"]["full"] for c in cs], "correct"),
                                         "escalated": rate([c["runs"]["full"] for c in cs], "escalated")}
    return out


async def run_benchmark(n: int = 100, ablations: bool = True, out_dir: str | Path = "evaluation/results",
                        seed: int = 2026, keep: bool = False, progress=print) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / "_workspaces"
    store = Store(out_dir / "benchmark.db")
    set_store(store)
    service = InvestigationService()
    configs = CONFIGS if ablations else {"full": CONFIGS["full"]}
    cases = []
    t_start = time.time()
    for i in range(n):
        spec = sample_spec(i, seed)
        ws = work / spec.incident_id.lower()
        await asyncio.to_thread(build_workspace, spec, ws)
        truth = load_truth(ws)
        incident = json.loads((ws / "incident.json").read_text())
        case = {"incident_id": spec.incident_id, "family": truth["family"], "service": truth["service"],
                "spec": spec.to_dict(), "injection": bool(spec.injection), "request": incident["request"],
                "runs": {}, "baselines": {}}
        for cfg, options in configs.items():
            store.execute("DELETE FROM episodic_memory")  # isolated memory per case (no leakage)
            run_id = f"bench-{cfg}-{i}-{uuid.uuid4().hex[:6]}"
            t0 = time.time()
            try:
                await service.start(workspace=ws, run_id=run_id, auto_approve=True, options=options, background=False)
                values = (await service.state(run_id))["values"]
                report = dict(values["report"])
                report["_results"] = values.get("results", [])
                case["runs"][cfg] = score_run(ws, truth, report, store, run_id, time.time() - t0)
            except Exception as exc:  # noqa: BLE001 - a crash counts as a failed investigation
                case["runs"][cfg] = {"status": "crashed", "error": repr(exc)[:300], "pattern": "unknown",
                                     "confidence": 0.0, "correct": False, "pattern_correct": False,
                                     "culprit_correct": False, "top3": False, "verified": False,
                                     "fix_verified": False, "applied": False, "escalated": True, "grounded": False,
                                     "hallucination": False, "tool_recall": 0.0, "tool_calls": 0, "denied_calls": 0,
                                     "sql_total": 0, "sql_ok": 0, "sql_accurate": 0, "injection_detected": False,
                                     "latency_s": round(time.time() - t0, 2), "input_tokens": 0, "output_tokens": 0,
                                     "cost_usd": 0.0, "baseline_cost_usd": 0.0, "llm_estimated": True,
                                     "replans": 0, "reflections": 0, "waves": 0}
        naive = await baselines.naive_last_deploy(ws, truth["service"], incident["reported_at"])
        logs_only = await baselines.logs_only_agent(ws, truth["service"])
        case["baselines"] = {
            "naive_last_deploy": {"pattern_correct": False, "culprit_correct": culprit_match(naive["culprit"], truth)},
            "logs_only_agent": {"pattern_correct": logs_only["pattern"] == truth["family"], "culprit_correct": False}}
        case["retrieval"] = await retrieval_case(ws, truth, truth["service"], incident["request"])
        cases.append(case)
        full = case["runs"]["full"]
        progress(f"[{i + 1}/{n}] {spec.incident_id} {truth['family']:<20} -> {full['pattern']:<20} "
                 f"{'OK ' if full['correct'] else 'MISS'} {full['status']:<11} {full['latency_s']:.1f}s")
        if not keep:
            shutil.rmtree(ws, ignore_errors=True)
    summary = summarize(cases)
    summary["wall_time_s"] = round(time.time() - t_start, 1)
    summary["seed"] = seed
    eval_id = f"eval-{time.strftime('%Y%m%d-%H%M%S')}"
    store.save_evaluation(eval_id, {"n": n, "seed": seed, "configs": list(configs)}, summary, cases)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    (out_dir / "cases.json").write_text(json.dumps(cases, indent=1, default=str))
    (out_dir / "REPORT.md").write_text(render_markdown(summary))
    if not keep:
        shutil.rmtree(work, ignore_errors=True)
    set_store(None)
    return summary


def pct(v) -> str:
    return "-" if v is None else f"{v * 100:.1f}%"


def render_markdown(s: dict) -> str:
    full = s["configs"]["full"]
    lines = [f"# AegisAI benchmark ({s['n']} synthetic incidents, seed {s['seed']})", "",
             "All numbers below were measured by `aegis benchmark`; the incidents are generated, "
             "so they measure behaviour on this synthetic platform, not on real production systems.", "",
             "## Root-cause accuracy", "",
             "| System | Pattern accuracy | Culprit accuracy | RCA accuracy (both) | Escalated | Wrong & not escalated |",
             "|---|---|---|---|---|---|"]
    for cfg, v in s["configs"].items():
        lines.append(f"| AegisAI ({cfg}) | {pct(v['pattern_accuracy'])} | {pct(v['culprit_accuracy'])} | "
                     f"{pct(v['rca_accuracy'])} | {pct(v['escalation_rate'])} | {v['wrong_and_not_escalated']} |")
    lines.append(f"| Baseline: roll back last deploy | - | {pct(s['baselines']['naive_last_deploy']['culprit_accuracy'])} "
                 f"| - | - | - |")
    lines.append(f"| Baseline: logs-only single agent | {pct(s['baselines']['logs_only_agent']['pattern_accuracy'])} "
                 f"| - | - | - | - |")
    lines += ["", "## Full system", "",
              f"* Top-3 accuracy: {pct(full['top3_accuracy'])}",
              f"* Hypotheses verified by counterfactual replay: {pct(full['verified_rate'])}; precision when verified: "
              f"{pct(full['precision_when_verified'])} ({full['false_verifications']} false verifications)",
              f"* End-to-end success (correct RCA + verified fix applied after approval): {pct(full['end_to_end_success'])}",
              f"* Fix success given a correct RCA: {pct(full['fix_success_rate_given_correct_rca'])}",
              f"* Calibration: Brier {full.get('brier')}, ECE {full.get('ece')}",
              f"* Evidence grounding: {pct(full['grounded_rate'])}; hallucinated references: {pct(full['hallucination_rate'])}",
              f"* Tool-selection recall vs expected tools: {pct(full['tool_recall'])}; avg tool calls {full['avg_tool_calls']}",
              f"* SQL: {pct(full['sql_success_rate'])} executed successfully; {pct(full['sql_accuracy'])} match the gold query result",
              f"* Prompt-injection cases: {full['injection_cases']}; injected content quarantined in {pct(full['injection_detected_rate'])}; "
              f"RCA correct in {pct(full['injection_cases_correct'])} of them; unauthorized tool calls executed: 0 "
              f"(denied attempts: {full['denied_tool_calls']})",
              f"* Latency p50 {full['latency_p50_s']}s / p95 {full['latency_p95_s']}s per investigation",
              f"* LLM usage per investigation: {full['avg_input_tokens']} in / {full['avg_output_tokens']} out tokens; "
              f"routed cost ${full['avg_cost_usd']:.4f} vs ${full['avg_cost_all_strong_usd']:.4f} all-strong-model "
              f"({pct(full.get('routing_cost_saving'))} saving)"
              + (" - token counts are estimates (offline run)" if full["llm_costs_estimated"] else ""),
              "", "## Accuracy by failure family", "",
              "| Family | n | AegisAI | No verification | Last-deploy baseline (culprit) | Logs-only (pattern) |",
              "|---|---|---|---|---|---|"]
    for fam, v in s["by_family"].items():
        lines.append(f"| {fam} | {v['n']} | {pct(v['full'])} | {pct(v['no_verification'])} | "
                     f"{pct(v['naive_last_deploy'])} | {pct(v['logs_only_agent'])} |")
    lines += ["", "## Accuracy under adverse conditions", "", "| Condition | n | RCA accuracy | Escalated |", "|---|---|---|---|"]
    for name, v in s["by_condition"].items():
        lines.append(f"| {name} | {v['n']} | {pct(v['full'])} | {pct(v['escalated'])} |")
    lines += ["", "## Retrieval (runbook for the true failure family, query = dominant error message)", "",
              "| Mode | Recall@1 | Recall@3 | MRR | nDCG@5 |", "|---|---|---|---|---|"]
    for mode, v in s["retrieval"].items():
        lines.append(f"| {mode} | {pct(v['recall@1'])} | {pct(v['recall@3'])} | {v['mrr']:.3f} | {v['ndcg@5']:.3f} |")
    lines += ["", f"Wall time: {s['wall_time_s']}s"]
    return "\n".join(lines) + "\n"
