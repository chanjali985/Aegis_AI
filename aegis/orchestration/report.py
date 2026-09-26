"""Final report: auditable root cause, evidence, verification, fix and run statistics."""
from __future__ import annotations

import json
from collections import Counter

from pydantic import BaseModel

from aegis.llm.router import get_llm
from aegis.security.pii import redact
from aegis.security.prompt_injection import wrap_untrusted
from aegis.storage.db import get_store


class Summary(BaseModel):
    summary: str


def _status(state) -> str:
    if not (state.get("brief") or {}).get("service"):
        return "needs_input"
    applied = state.get("applied")
    if applied:
        return "completed" if applied.get("ok") else "apply_failed"
    approval = state.get("approval")
    if approval:
        return {"reject": "rejected", "request_changes": "changes_requested"}.get(approval["decision"], "approved")
    if state.get("fix_verification") and state["fix_verification"]["verdict"] != "verified":
        return "escalated"
    if not state.get("verification") or state["verification"]["verdict"] != "verified":
        return "escalated"
    return "diagnosed"  # verified root cause, remediation stage disabled


def _timeline(evidence: list[dict], onset: str | None) -> list[dict]:
    items = []
    for e in evidence:
        d = e["data"]
        if e["kind"] == "deploy":
            items.append((d["deployed_at"], f"Deploy {d['service']} v{d['version']}", e["id"]))
        elif e["kind"] == "config_change":
            items.append((d["deployed_at"], f"Config {d['key']}: {d['old']} -> {d['new']} ({d['commit'][:8]})", e["id"]))
        elif e["kind"] == "migration_change":
            items.append((d["deployed_at"], f"Migration dropped {d['dropped_indexes']}", e["id"]))
        elif e["kind"] == "flag_change":
            items.append((d["changed_at"], f"Flag {d['flag']} {d['old_value']} -> {d['new_value']}", e["id"]))
        elif e["kind"] == "dependency_status" and not d.get("healthy", True):
            items.append((d["first_bad_at"], f"{d['dependency']} {d['status']}", e["id"]))
        elif e["kind"] == "certificate" and d.get("expired_at_onset"):
            items.append((d["expires_at"], f"Certificate for {d['host']} expired", e["id"]))
        elif e["kind"] == "error_spike":
            items.append((d["onset"], f"{d['error_type']} spike x{d['factor']}", e["id"]))
    if onset:
        items.append((onset, "Incident onset", None))
    seen, out = set(), []
    for t, label, eid in sorted(items, key=lambda x: x[0]):
        if (t, label) in seen:
            continue
        seen.add((t, label))
        out.append({"time": t, "event": label, "evidence": eid})
    return out[-25:]


def grounding(top: dict | None, evidence: list[dict], text: str) -> dict:
    ids = {e["id"] for e in evidence}
    cited = [eid for s in (top or {}).get("supporting", []) for eid in s["evidence"]]
    missing = [c for c in cited if c not in ids]
    blob = json.dumps([e["data"] for e in evidence])
    commit = ((top or {}).get("culprit") or {}).get("commit")
    commit_ok = commit is None or commit in blob
    import re
    shas = set(re.findall(r"\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*[0-9])[0-9a-f]{7,40}\b", text))
    unknown_shas = [s for s in shas if s not in blob]
    return {"cited": len(cited), "missing_citations": missing, "culprit_commit_grounded": commit_ok,
            "unknown_commit_refs": unknown_shas,
            "grounded": not missing and commit_ok and not unknown_shas}


async def build_report(state) -> dict:
    store = get_store()
    run_id = state["run_id"]
    evidence = state.get("evidence", [])
    hyps = state.get("hypotheses") or []
    top = hyps[0] if hyps else None
    verification = state.get("verification") or {}
    by_id = {e["id"]: e for e in evidence}
    status = _status(state)
    root = None
    if top and top["pattern"] != "unknown":
        root = {"pattern": top["pattern"], "title": top["title"], "confidence": top["confidence"],
                "category": top["category"], "culprit": top["culprit"], "explanation": top.get("explanation", ""),
                "verified": verification.get("verdict") == "verified",
                "supporting": [{"rule": s["rule"], "weight": s["weight"],
                                "evidence": [{"id": i, "summary": by_id.get(i, {}).get("summary", "")}
                                             for i in s["evidence"][:3]]} for s in top["supporting"]],
                "contradicting": top["contradicting"]}
    fix = state.get("fix")
    fix_out = None
    if fix:
        fix_out = {k: fix.get(k) for k in ("kind", "summary", "description", "checks", "files", "actions", "branch",
                                            "pr", "replay", "ok", "error")}
        fix_out["diff"] = (fix.get("code_patch") or "")[:8000]
    tools = store.tool_calls(run_id)
    llm_calls = store.llm_calls(run_id)
    sec = store.security_events(run_id)
    spans = store.spans(run_id)
    agent_ms = Counter()
    for s in spans:
        if s["kind"] == "agent" and s["end"]:
            agent_ms[s["agent"]] += (s["end"] - s["start"]) * 1000
    stats = {
        "agents": sorted({r["agent"] for r in state.get("results", [])}),
        "agent_latency_ms": {k: round(v, 1) for k, v in agent_ms.items()},
        "tool_calls": len(tools), "tools_used": sorted({f"{t['server']}.{t['tool']}" for t in tools if t["ok"]}),
        "denied_tool_calls": sum(t["denied"] for t in tools),
        "llm_calls": len(llm_calls), "llm_estimated": any(c["estimated"] for c in llm_calls),
        "input_tokens": sum(c["input_tokens"] for c in llm_calls),
        "output_tokens": sum(c["output_tokens"] for c in llm_calls),
        "cost_usd": round(sum(c["cost_usd"] for c in llm_calls), 5),
        "baseline_cost_usd": round(sum(c["baseline_cost_usd"] for c in llm_calls), 5),
        "evidence_items": len(evidence), "waves": state.get("wave", 0), "replans": state.get("replans", 0),
        "reflections": state.get("reflections", 0),
    }
    security = {"prompt_injections_quarantined": sum(1 for s in sec if s["kind"] == "prompt_injection_quarantined"),
                "pii_masked": sum(sum(s["detail"].get("counts", {}).values()) for s in sec if s["kind"] == "pii_masked"),
                "permission_denied": sum(1 for s in sec if s["kind"] == "permission_denied"),
                "events": [{"agent": s["agent"], "kind": s["kind"], "detail": s["detail"]} for s in sec
                           if s["kind"] != "pii_masked"][:20]}
    if root:
        c = root["culprit"]
        what = (f"commit {c['commit'][:8]} (v{c.get('version')}) '{c.get('subject', '')}'" if c.get("type") == "commit"
                else f"{c.get('type')} {c.get('id', c.get('version', ''))}")
        headline = f"{root['title']} - {what}" + (" [verified]" if root["verified"] else " [unverified]")
    else:
        headline = "Root cause not determined; escalated to on-call with collected evidence"
    if root:
        rules = sorted(root["supporting"], key=lambda s: -s["weight"])[:3]
        replay = next((c["detail"] for c in verification.get("checks", []) if c["name"] == "counterfactual_replay"), "")
        template = (f"{root['title']} (confidence {root['confidence']:.0%}), first errors at {state.get('onset')}. "
                    f"Strongest evidence: " + "; ".join(r["rule"] for r in rules) + ". "
                    + (f"Counterfactual check: {replay}. " if replay else "")
                    + (f"Remediation: {fix_out['summary']}." if fix_out and fix_out.get("summary") else ""))
    else:
        template = headline + "."
    summary_text = template
    llm = get_llm()
    if root:
        ev = "\n".join(f"[{e['id']}] {e['summary']}" for e in evidence[:40])
        s, source = await llm.structured(
            task="report", system="Write a 4-6 sentence executive incident summary for engineers. Cite evidence ids.",
            prompt=f"Headline: {headline}\nFix: {(fix_out or {}).get('summary')}\nStatus: {status}\n"
                   + wrap_untrusted("evidence", ev), schema=Summary, fallback=lambda: Summary(summary=template))
        summary_text = s.summary
    signatures = [e["data"]["error_type"] for e in evidence if e["kind"] == "error_spike"]
    report = {
        "incident_id": state["incident_id"], "request": state["request"], "status": status, "headline": headline,
        "summary": summary_text, "brief": state.get("brief"), "onset": state.get("onset"),
        "root_cause": root, "hypotheses": [{k: h[k] for k in ("title", "pattern", "confidence", "score")}
                                           for h in hyps[:5]],
        "verification": verification, "verification_history": state.get("verifications", []),
        "fix": fix_out, "fix_verification": state.get("fix_verification"), "approval": state.get("approval"),
        "applied": state.get("applied"), "timeline": _timeline(evidence, state.get("onset")),
        "plan": state.get("plan", []), "plan_rationale": state.get("plan_rationale", []),
        "signatures": signatures, "stats": stats, "security": security,
        "grounding": grounding(top, evidence, summary_text + " " + headline),
        "evidence": [{"id": e["id"], "agent": e["agent"], "kind": e["kind"], "summary": e["summary"]}
                     for e in evidence],
    }
    report, _ = redact(report)
    return report
