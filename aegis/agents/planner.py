"""Planner: turns the brief and the evidence so far into the next wave of agent tasks.

Planning is evidence-driven rather than a fixed pipeline:

* wave 1 - broad, parallel: observability (onset + signatures), research (architecture invariants)
* wave 2 - targeted by wave-1 evidence: code (deploy diffs + blame of the exact stack frames),
  database (only the questions the signatures call for), research (runbooks for those signatures)
* replan - when verification is inconclusive or evidence is missing: the questions and agents
  that can discriminate between the leading hypotheses

With a live LLM, the planner may add steps; they are validated against the agent registry
and parameter schema before execution. The deterministic plan is always the floor.
"""
from __future__ import annotations

import uuid
from collections import Counter

from pydantic import BaseModel, Field

from aegis.agents.models import IncidentBrief, PlanStep
from aegis.llm.router import get_llm
from aegis.observability.tracing import agent_span

UPSTREAM_SIGNATURES = {"UpstreamError", "UpstreamTimeout", "SSLError"}
DB_SIGNATURES = {"DatabaseTimeoutError", "SlowQuery"}
ALL_QUESTIONS = ["recent_deployments", "flag_changes", "dependency_status", "certificates", "query_stats",
                 "pool_stats"]


class LLMStep(BaseModel):
    agent: str
    goal: str
    questions: list[str] = Field(default_factory=list)


class LLMPlan(BaseModel):
    extra_steps: list[LLMStep] = Field(default_factory=list)
    rationale: str = ""


def _step(agent: str, goal: str, wave: int, reason: str, **params) -> PlanStep:
    return PlanStep(id=f"S{wave}-{agent}-{uuid.uuid4().hex[:4]}", agent=agent, goal=goal, params=params,
                    wave=wave, reason=reason)


def initial_plan(brief: IncidentBrief) -> list[PlanStep]:
    return [
        _step("observability", f"Find when {brief.service} started failing and how", 1,
              "every investigation needs the onset time and failure signature", service=brief.service),
        _step("research", f"Retrieve {brief.service} architecture invariants", 1,
              "expected configuration values let us judge whether a change was dangerous",
              service=brief.service, focus="architecture"),
    ]


def summarize_signals(evidence: list[dict]) -> dict:
    spikes = [e for e in evidence if e["kind"] == "error_spike"]
    shifts = {e["data"]["metric"]: e["data"]["direction"] for e in evidence if e["kind"] == "metric_shift"}
    frames, samples, upstream, hosts = [], {}, None, []
    for s in spikes:
        d = s["data"]
        samples[d["error_type"]] = d.get("sample", "")[:160]
        upstream = upstream or d.get("upstream")
        if d.get("host"):
            hosts.append(d["host"])
        if d.get("frame"):
            version = Counter(d.get("versions") or {}).most_common(1)
            for fr in (d.get("stack") or [])[-2:]:
                item = {"file": fr["file"], "line": fr["line"], "version": version[0][0] if version else None}
                if item not in frames:
                    frames.append(item)
    return {"signatures": [s["data"]["error_type"] for s in spikes], "samples": samples, "shifts": shifts,
            "frames": frames, "upstream": upstream, "hosts": hosts,
            "logs_missing": any(e["kind"] == "telemetry_gap" for e in evidence) and not spikes,
            "feature_path": any(s["data"].get("feature_path") for s in spikes)}


def follow_up_plan(brief: IncidentBrief, onset: str, evidence: list[dict], wave: int) -> list[PlanStep]:
    sig = summarize_signals(evidence)
    sigs = set(sig["signatures"])
    steps = [_step("code", f"Diff every {brief.service} deploy before {onset}"
                   + (" and blame the failing stack frames" if sig["frames"] else ""), wave,
                   "correlate the onset with configuration, code and schema changes",
                   service=brief.service, onset=onset, frames=sig["frames"])]
    questions, reasons = ["recent_deployments"], ["cross-check deploy records"]
    if sigs & UPSTREAM_SIGNATURES or sig["shifts"].get("upstream_error_rate") == "up":
        questions.append("dependency_status")
        reasons.append("upstream failures -> check dependency health")
    if "SSLError" in sigs:
        questions.append("certificates")
        reasons.append("TLS failures -> check certificate expiry")
    if sigs & DB_SIGNATURES or sig["shifts"].get("db_latency_p95_ms") == "up":
        questions.append("query_stats")
        reasons.append("database timeouts -> check query latency history")
    if "ConnectionPoolExhausted" in sigs:
        questions.append("pool_stats")
        reasons.append("pool exhaustion -> check pool utilisation")
    if sig["feature_path"] or sig["frames"]:
        questions.append("flag_changes")
        reasons.append("exception in application code -> check feature flag changes")
    if sig["logs_missing"] or not sigs:
        questions = ALL_QUESTIONS
        reasons = ["logs unavailable -> sweep every structured data source"]
    steps.append(_step("database", "Query the production replica: " + ", ".join(questions), wave,
                       "; ".join(reasons), service=brief.service, onset=onset, questions=questions,
                       upstream=sig["upstream"] or ""))
    if sigs:
        steps.append(_step("research", "Find runbooks and postmortems for " + ", ".join(sorted(sigs)), wave,
                           "runbooks encode known failure patterns for these signatures",
                           service=brief.service, focus="runbooks", signatures=sorted(sigs)[:3],
                           samples=sig["samples"]))
    return steps


def replan(brief: IncidentBrief, onset: str, evidence: list[dict], asked: set[str], wave: int,
           reason: str) -> list[PlanStep]:
    sig = summarize_signals(evidence)
    remaining = [q for q in ALL_QUESTIONS if q not in asked]
    steps = []
    if remaining:
        steps.append(_step("database", "Discriminating queries: " + ", ".join(remaining), wave, reason,
                           service=brief.service, onset=onset, questions=remaining, upstream=sig["upstream"] or ""))
    if not any(e["kind"] == "doc_expectation" for e in evidence) or not any(e["kind"] == "runbook" for e in evidence):
        steps.append(_step("research", "Broader documentation search", wave, reason, service=brief.service,
                           focus="all", signatures=sig["signatures"][:3], samples=sig["samples"]))
    return steps


async def refine_with_llm(brief: IncidentBrief, steps: list[PlanStep], evidence: list[dict], cards: dict,
                          wave: int, replan_round: int = 0) -> tuple[list[PlanStep], str]:
    llm = get_llm()
    rationale = "; ".join(f"{s.agent}: {s.reason}" for s in steps)
    agents = "\n".join(f"- {n}: {c.description} skills={[s.id for s in c.skills]}" for n, c in cards.items())
    ev = "\n".join(f"- ({e['kind']}) {e['summary']}" for e in evidence[:40])
    current = "\n".join(f"- {s.agent}: {s.goal}" for s in steps)
    plan, source = await llm.structured(
        task="plan", signals={"replan_round": replan_round},
        system="You plan incident investigations by delegating to specialist agents.",
        prompt=f"Incident: {brief.request}\nAgents:\n{agents}\n\nEvidence so far:\n{ev}\n\nPlanned steps:\n{current}\n"
               f"Suggest at most 2 extra steps only if they would gather missing evidence. For the database "
               f"agent, questions must come from {ALL_QUESTIONS}.",
        schema=LLMPlan, fallback=lambda: LLMPlan())
    for extra in plan.extra_steps[:2]:
        if extra.agent not in cards or extra.agent in ("rca", "fix", "verification", "memory"):
            continue
        params = {"service": brief.service}
        if extra.agent == "database":
            qs = [q for q in extra.questions if q in ALL_QUESTIONS]
            if not qs:
                continue
            params.update(questions=qs, onset=steps[0].params.get("onset"))
        steps.append(_step(extra.agent, extra.goal[:120], wave, "suggested by LLM planner", **params))
    return steps, plan.rationale or rationale


async def plan_wave(kind: str, brief: IncidentBrief, evidence: list[dict], cards: dict, wave: int,
                    onset: str | None = None, asked: set[str] | None = None, reason: str = "",
                    replan_round: int = 0) -> tuple[list[PlanStep], str]:
    async with agent_span("planner", f"{kind} plan (wave {wave})") as sp:
        if kind == "initial":
            steps = initial_plan(brief)
        elif kind == "follow_up":
            steps = follow_up_plan(brief, onset, evidence, wave)
        else:
            steps = replan(brief, onset, evidence, asked or set(), wave, reason)
        steps, rationale = await refine_with_llm(brief, steps, evidence, cards, wave, replan_round)
        sp["attrs"]["result_summary"] = {"summary": f"{len(steps)} steps: " + ", ".join(s.agent for s in steps)}
        return steps, rationale
