"""The investigation workflow as a LangGraph state machine.

    triage ─► recall ─► plan ─► ⟨fan-out specialists in parallel⟩ ─► collect ─┐
                                   ▲                                          │ wave 1 → plan wave 2
                                   └────────────── replan ◄───────────┐       ▼
                                                   (inconclusive)     │      rca ◄── reflect (refuted)
                                                                      └──── verify ──► fix ─► verify_fix
                                                                                              │
                                              report ◄── apply ◄── approval (human interrupt) ◄┘

Every node is checkpointed, so an investigation paused for approval survives restarts.
"""
from __future__ import annotations

import time

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send, interrupt

from aegis.a2a.client import A2AError, get_registry
from aegis.agents import planner
from aegis.agents.models import AgentTask, IncidentBrief, PlanStep
from aegis.agents.supervisor import default_onset, keywords, triage
from aegis.config import get_settings
from aegis.observability import metrics
from aegis.observability.tracing import agent_span, bind_run, emit
from aegis.orchestration.report import build_report
from aegis.orchestration.state import InvestigationState
from aegis.security.permissions import approval_tokens
from aegis.storage.db import get_store

BULKY = {"fix", "report"}


def _brief(state) -> IncidentBrief:
    return IncidentBrief.model_validate(state["brief"])


def _opt(state, key: str, default=True):
    return (state.get("options") or {}).get(key, default)


async def _delegate(state, agent: str, goal: str, params: dict, wave: int = 0) -> dict:
    task = AgentTask(agent=agent, goal=goal, workspace=state["workspace"], run_id=state["run_id"],
                     incident=_brief(state), params=params, wave=wave)
    emit("delegation", {"to": agent, "goal": goal, "protocol": "A2A message/send"}, agent="supervisor")
    return (await get_registry().send(agent, task)).model_dump()


def _slim(result: dict) -> dict:
    out = {k: v for k, v in result.items() if k != "evidence"}
    out["evidence_ids"] = [e["id"] for e in result.get("evidence", [])]
    if result["agent"] in ("fix", "verification", "rca"):
        out["data"] = {}
    return out


# -- nodes ------------------------------------------------------------------------------
async def triage_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    brief = await triage(state["incident_id"], state["request"], state["reported_at"])
    if not brief.service:
        try:
            res = await _delegate(state | {"brief": brief.model_dump()}, "code", "Resolve which service owns the "
                                  "reported endpoint", {"mode": "resolve_service", "endpoint": brief.endpoint,
                                                        "keywords": keywords(brief.request)})
            brief.service = res["data"].get("service")
        except A2AError as exc:
            emit("warning", {"message": f"service resolution failed: {exc}"}, agent="supervisor")
    emit("brief", brief.model_dump(), agent="supervisor")
    return {"brief": brief.model_dump(), "wave": 0, "replans": 0, "reflections": 0, "rejected": [],
            "status": "investigating" if brief.service else "needs_input"}


async def recall_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    if not _opt(state, "memory"):
        return {"priors": {}}
    try:
        res = await _delegate(state, "memory", "Recall similar incidents", {"service": state["brief"]["service"]})
    except A2AError as exc:
        emit("warning", {"message": str(exc)}, agent="supervisor")
        return {"priors": {}}
    return {"evidence": res["evidence"], "results": [_slim(res)], "priors": res["data"].get("priors", {})}


async def plan_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    cards = await get_registry().discover()
    steps, rationale = await planner.plan_wave("initial", _brief(state), state.get("evidence", []), cards, wave=1)
    emit("plan", {"wave": 1, "steps": [s.model_dump() for s in steps], "rationale": rationale}, agent="planner")
    return {"plan": [s.model_dump() for s in steps], "wave": 1, "plan_rationale": [rationale]}


def fan_out(state: InvestigationState):
    pending = [s for s in state.get("plan", []) if s["status"] == "pending" and s["wave"] == state["wave"]]
    if not pending:
        return "rca"
    return [Send("specialist", {"step": s, "run_id": state["run_id"], "workspace": state["workspace"],
                                "brief": state["brief"]}) for s in pending]


async def specialist_node(payload: dict) -> dict:
    bind_run(payload["run_id"])
    step = PlanStep.model_validate(payload["step"])
    try:
        res = await _delegate(payload, step.agent, step.goal, step.params, wave=step.wave)
        status = "done" if res["status"] != "failed" else "failed"
    except A2AError as exc:
        emit("agent_failed", {"task": step.goal, "error": str(exc)[:400]}, agent=step.agent)
        return {"plan": [{"id": step.id, "status": "failed", "summary": str(exc)[:200]}]}
    return {"evidence": res["evidence"], "results": [_slim(res)],
            "plan": [{"id": step.id, "status": status, "summary": res["summary"]}]}


async def collect_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    brief = _brief(state)
    onset = state.get("onset")
    if not onset:
        obs = [r for r in state.get("results", []) if r["agent"] == "observability" and r["data"].get("onset")]
        onset = obs[-1]["data"]["onset"] if obs else default_onset(brief)
        emit("onset", {"onset": onset, "source": "observability" if obs else "report time"}, agent="supervisor")
    if state["wave"] == 1:
        cards = await get_registry().discover()
        steps, rationale = await planner.plan_wave("follow_up", brief, state.get("evidence", []), cards, wave=2,
                                                   onset=onset)
        emit("plan", {"wave": 2, "steps": [s.model_dump() for s in steps], "rationale": rationale}, agent="planner")
        return {"onset": onset, "wave": 2, "plan": [s.model_dump() for s in steps], "plan_rationale": [rationale]}
    return {"onset": onset}


async def rca_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    res = await _delegate(state, "rca", "Rank root-cause hypotheses", {
        "evidence": state.get("evidence", []), "priors": state.get("priors", {}),
        "rejected": state.get("rejected", []), "onset": state["onset"]})
    hyps = res["data"]["hypotheses"]
    emit("hypotheses", {"hypotheses": [{k: h[k] for k in ("id", "title", "confidence", "score", "culprit")}
                                       for h in hyps[:4]], "margin": res["data"]["margin"]}, agent="rca")
    return {"hypotheses": hyps, "margin": res["data"]["margin"], "results": [_slim(res)]}


async def verify_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    top = state["hypotheses"][0]
    if not _opt(state, "verification"):
        verdict = "verified" if top["confidence"] >= get_settings().confidence_threshold else "inconclusive"
        report = {"target": top["id"], "verdict": verdict, "checks": [], "summary": "verification disabled"}
    else:
        res = await _delegate(state, "verification", f"Try to refute: {top['title']}", {
            "mode": "hypothesis", "hypothesis": top, "evidence": state.get("evidence", []),
            "onset": state["onset"], "margin": state.get("margin", 0.0)})
        report = res["data"]["report"]
    emit("verification", report, agent="verification")
    return {"verification": report, "verifications": [report]}


def after_verify(state: InvestigationState) -> str:
    s = get_settings()
    verdict = state["verification"]["verdict"]
    if verdict == "verified":
        return "fix" if _opt(state, "fix") else "report"
    if verdict == "refuted" and state.get("reflections", 0) < s.max_reflections:
        return "reflect"
    if verdict == "inconclusive" and state.get("replans", 0) < s.max_replans and _opt(state, "replanning"):
        return "replan"
    return "report"


async def reflect_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    top = state["hypotheses"][0]
    emit("reflection", {"rejected": top["pattern"], "reason": state["verification"]["summary"]}, agent="supervisor")
    return {"rejected": state.get("rejected", []) + [top["pattern"]], "reflections": state.get("reflections", 0) + 1}


async def replan_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    asked = {q for s in state.get("plan", []) if s["agent"] == "database" for q in s["params"].get("questions", [])}
    wave = state["wave"] + 1
    cards = await get_registry().discover()
    steps, rationale = await planner.plan_wave(
        "replan", _brief(state), state.get("evidence", []), cards, wave=wave, onset=state["onset"], asked=asked,
        reason=f"verification inconclusive: {state['verification']['summary'][:160]}",
        replan_round=state.get("replans", 0) + 1)
    emit("replan", {"wave": wave, "steps": [s.model_dump() for s in steps], "rationale": rationale}, agent="planner")
    replans = state.get("replans", 0) + 1 if steps else get_settings().max_replans
    return {"plan": [s.model_dump() for s in steps], "wave": wave, "replans": replans, "plan_rationale": [rationale]}


def after_replan(state: InvestigationState):
    pending = [s for s in state.get("plan", []) if s["status"] == "pending" and s["wave"] == state["wave"]]
    return fan_out(state) if pending else "report"


async def fix_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    top = state["hypotheses"][0]
    res = await _delegate(state, "fix", f"Prepare a remediation for: {top['title']}", {
        "hypothesis": top, "evidence": state.get("evidence", []), "onset": state["onset"]})
    fix = res["data"]["fix"]
    emit("fix", {k: fix.get(k) for k in ("kind", "summary", "checks", "files", "actions", "branch")}, agent="fix")
    return {"fix": fix, "results": [_slim(res)]}


async def verify_fix_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    fix = state["fix"]
    if not fix.get("ok"):
        report = {"target": "fix", "verdict": "refuted", "checks": [], "summary": fix.get("summary", "no fix")}
    else:
        res = await _delegate(state, "verification", "Independently verify the proposed fix",
                              {"mode": "fix", "fix": fix})
        report = res["data"]["report"]
    emit("verification", report, agent="verification")
    return {"fix_verification": report}


async def approval_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    fix, top = state["fix"], state["hypotheses"][0]
    approval_id = f"{state['run_id']}-approval"
    payload = {"approval_id": approval_id, "agent": "fix", "tool": fix["approval_tool"],
               "action": fix.get("description") or fix.get("summary"), "reason": top["title"],
               "confidence": top["confidence"], "checks": state["fix_verification"]["checks"],
               "branch": fix.get("branch"), "actions": fix.get("actions"),
               "diff": (fix.get("code_patch") or "")[:6000], "pr": fix.get("pr")}
    store = get_store()
    if not store.approvals(run_id=state["run_id"], status="pending"):  # node re-runs on resume
        store.create_approval(approval_id, state["run_id"], payload["action"], payload)
        emit("approval_required", {k: v for k, v in payload.items() if k != "diff"}, agent="supervisor")
    if state.get("auto_approve"):
        decision = {"decision": "approve", "by": "auto-approver (benchmark policy)", "comment": ""}
    else:
        decision = interrupt(payload)
    store.decide_approval(approval_id, {"approve": "approved", "reject": "rejected"}.get(
        decision["decision"], "changes_requested"), decision.get("by", "unknown"), decision.get("comment", ""))
    emit("approval_decision", decision, agent="human")
    return {"approval": {**decision, "approval_id": approval_id, "decided_at": time.time()}}


def after_approval(state: InvestigationState) -> str:
    return "apply" if state["approval"]["decision"] == "approve" else "report"


async def apply_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    fix = state["fix"]
    token = approval_tokens.mint(fix["approval_tool"], state["run_id"])
    try:
        res = await _delegate(state, "fix", "Apply the approved remediation",
                              {"action": "apply", "fix": fix, "approval_token": token})
        applied = {"ok": res["status"] != "failed", "detail": res["data"].get("applied"), "summary": res["summary"]}
    except A2AError as exc:
        applied = {"ok": False, "detail": str(exc)[:400]}
    emit("applied", applied, agent="fix")
    return {"applied": applied}


async def report_node(state: InvestigationState) -> dict:
    bind_run(state["run_id"])
    async with agent_span("supervisor", "final report"):
        report = await build_report(state)
    if report["root_cause"] and report["root_cause"].get("verified") and _opt(state, "memory"):
        try:
            await _delegate(state, "memory", "Record the outcome", {"action": "remember", "record": {
                "id": state["incident_id"], "service": state["brief"]["service"],
                "root_cause": report["root_cause"]["pattern"], "summary": report["root_cause"]["title"],
                "resolution": (report.get("fix") or {}).get("summary", ""),
                "signature": " ".join(report.get("signatures", [])), "source": "investigation"}})
        except A2AError:
            pass
    emit("report", {"status": report["status"], "headline": report["headline"]}, agent="supervisor")
    get_store().update_investigation(state["run_id"], report["status"], report)
    metrics.INVESTIGATIONS.inc(status=report["status"])
    return {"report": report, "status": report["status"]}


def after_triage(state: InvestigationState) -> str:
    return "recall" if state["brief"].get("service") else "report"


def build_graph():
    g = StateGraph(InvestigationState)
    for name, fn in [("triage", triage_node), ("recall", recall_node), ("plan", plan_node),
                     ("specialist", specialist_node), ("collect", collect_node), ("rca", rca_node),
                     ("verify", verify_node), ("reflect", reflect_node), ("replan", replan_node),
                     ("fix", fix_node), ("verify_fix", verify_fix_node), ("approval", approval_node),
                     ("apply", apply_node), ("report", report_node)]:
        g.add_node(name, fn)
    g.add_edge(START, "triage")
    g.add_conditional_edges("triage", after_triage, ["recall", "report"])
    g.add_edge("recall", "plan")
    g.add_conditional_edges("plan", fan_out, ["specialist", "rca"])
    g.add_edge("specialist", "collect")
    g.add_conditional_edges("collect", fan_out, ["specialist", "rca"])
    g.add_edge("rca", "verify")
    g.add_conditional_edges("verify", after_verify, ["fix", "reflect", "replan", "report"])
    g.add_edge("reflect", "rca")
    g.add_conditional_edges("replan", after_replan, ["specialist", "report"])
    g.add_edge("fix", "verify_fix")
    g.add_conditional_edges("verify_fix", lambda s: "approval" if s["fix_verification"]["verdict"] == "verified"
                            else "report", ["approval", "report"])
    g.add_conditional_edges("approval", after_approval, ["apply", "report"])
    g.add_edge("apply", "report")
    g.add_edge("report", END)
    return g
