"""Root-cause analysis agent: evidence model over the failure-pattern catalogue.

Scores every known pattern by summing weighted evidence rules (see
``aegis.memory.semantic``), adds a small episodic-memory prior and normalises
with a softmax that includes an explicit "insufficient evidence" hypothesis.
The LLM (when available) writes the explanation and may *propose* an
alternative, but it cannot change scores; its citations are grounding-checked.
"""
from __future__ import annotations

import math

from pydantic import BaseModel, Field

from aegis.agents.base import Agent
from aegis.agents.models import AgentResult, AgentTask, Hypothesis
from aegis.llm.router import get_llm
from aegis.memory.semantic import NULL_SCORE, PATTERNS, EvidenceIndex
from aegis.security.prompt_injection import wrap_untrusted
from aegis.tools.gateway import ToolGateway

TEMPERATURE = 1.0


class RCANarrative(BaseModel):
    explanation: str = Field(description="3-5 sentence causal explanation citing evidence ids in [brackets]")
    agrees_with_top: bool = True
    alternative: str | None = Field(default=None, description="an alternative root cause if you disagree")
    alternative_evidence: list[str] = Field(default_factory=list)


def score_patterns(evidence: list[dict], ctx: dict, priors: dict[str, int] | None = None,
                   rejected: list[str] | None = None) -> list[Hypothesis]:
    E = EvidenceIndex(evidence)
    priors = priors or {}
    rejected = set(rejected or [])
    raw = []
    for p in PATTERNS:
        if p.id in rejected:
            continue
        score = p.prior + 0.25 * math.log1p(priors.get(p.id, 0))
        supporting, contradicting, matched = [], [], {}
        for rule in p.rules:
            hit = list(dict.fromkeys(rule.fn(E, ctx)))
            if not hit:
                continue
            score += rule.weight
            matched[rule.name] = hit
            (supporting if rule.weight > 0 else contradicting).append(
                {"rule": rule.name, "weight": rule.weight, "evidence": hit})
        raw.append((p, score, supporting, contradicting, matched))
    scores = [s for _, s, *_ in raw] + [NULL_SCORE]
    m = max(scores)
    z = sum(math.exp((s - m) / TEMPERATURE) for s in scores)
    hyps = []
    for p, score, sup, con, matched in raw:
        conf = math.exp((score - m) / TEMPERATURE) / z
        hyps.append(Hypothesis(
            id=f"H-{p.id}", pattern=p.id, title=p.title, category=p.category, score=round(score, 2),
            confidence=round(conf, 4), supporting=sup, contradicting=con, culprit=p.culprit(E, ctx, matched),
            fix_kind=p.fix_kind, verification_plan=p.verification))
    hyps.sort(key=lambda h: -h.score)
    null_conf = math.exp((NULL_SCORE - m) / TEMPERATURE) / z
    hyps.append(Hypothesis(id="H-unknown", pattern="unknown", title="Insufficient evidence for a known pattern",
                           category="unknown", score=NULL_SCORE, confidence=round(null_conf, 4)))
    hyps.sort(key=lambda h: -h.confidence)
    return hyps


def template_explanation(h: Hypothesis, evidence_by_id: dict[str, dict]) -> str:
    if h.pattern == "unknown":
        return "No known failure pattern is supported strongly enough by the evidence collected."
    parts = [f"{h.title} (confidence {h.confidence:.0%})."]
    for s in sorted(h.supporting, key=lambda s: -s["weight"])[:4]:
        first = evidence_by_id.get(s["evidence"][0], {})
        parts.append(f"{s['rule'].capitalize()} [{s['evidence'][0]}]: {first.get('summary', '')[:140]}")
    if h.contradicting:
        parts.append("Contradicting: " + "; ".join(c["rule"] for c in h.contradicting) + ".")
    return " ".join(parts)


class RCAAgent(Agent):
    name = "rca"
    title = "Root Cause Analysis Agent"
    description = "Builds and ranks root-cause hypotheses with an explicit, auditable evidence model."
    skills = [{"id": "rank-hypotheses", "name": "Rank hypotheses",
               "description": "Weighted evidence rules over a catalogue of failure patterns; softmax confidence.",
               "tags": ["rca", "hypotheses", "evidence"]}]

    async def execute(self, task: AgentTask, gw: ToolGateway) -> AgentResult:
        evidence = task.params["evidence"]
        ctx = {"service": task.incident.service, "onset": task.params.get("onset")}
        hyps = score_patterns(evidence, ctx, task.params.get("priors"), task.params.get("rejected"))
        by_id = {e["id"]: e for e in evidence}
        top = hyps[0]
        top.explanation = template_explanation(top, by_id)
        second = next((h for h in hyps[1:] if h.pattern != "unknown"), None)
        margin = top.confidence - (second.confidence if second else 0.0)
        llm = get_llm()
        notes = []
        if top.pattern != "unknown":
            ev_txt = "\n".join(f"[{e['id']}] ({e['kind']}) {e['summary']}" for e in evidence[:60])
            ranking = "\n".join(f"- {h.title}: confidence {h.confidence:.2f}" for h in hyps[:4])
            narrative, source = await llm.structured(
                task="rca", signals={"margin": margin, "candidates": sum(h.confidence > 0.05 for h in hyps)},
                system="You are a senior SRE writing a root-cause analysis. Cite evidence ids in brackets. "
                       "Only use the evidence provided.",
                prompt=f"Incident: {task.incident.request}\nRanked hypotheses (from an evidence model):\n{ranking}\n\n"
                       + wrap_untrusted("evidence", ev_txt)
                       + "\nExplain the most likely root cause. If the evidence contradicts the top hypothesis, "
                         "say so and propose an alternative with evidence ids.",
                schema=RCANarrative, fallback=lambda: RCANarrative(explanation=top.explanation))
            cited = [c for c in narrative.alternative_evidence if c not in by_id]
            if source == "llm":
                top.explanation = narrative.explanation
                if not narrative.agrees_with_top and narrative.alternative and not cited:
                    notes.append(f"LLM proposed alternative: {narrative.alternative}")
                if cited:
                    notes.append(f"discarded LLM alternative citing unknown evidence {cited}")
        summary = f"Top hypothesis: {top.title} ({top.confidence:.0%}); margin {margin:.2f}"
        return AgentResult(task_id=task.task_id, agent=self.name, summary=summary, notes=notes,
                           data={"hypotheses": [h.model_dump() for h in hyps[:6]], "margin": round(margin, 4)})
