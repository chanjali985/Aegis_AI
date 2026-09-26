"""Research agent: hybrid RAG over architecture docs, runbooks and postmortems."""
from __future__ import annotations

import re

from pydantic import BaseModel, Field

from aegis.agents.base import Agent
from aegis.agents.models import AgentResult, AgentTask
from aegis.llm.router import get_llm
from aegis.security.prompt_injection import wrap_untrusted
from aegis.tools.gateway import ToolGateway

INVARIANT_ROW = re.compile(r"^\|\s*([a-z_]+\.[a-z_]+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|", re.M)


def parse_invariants(markdown: str) -> list[dict]:
    rows = []
    for key, expected, rationale in INVARIANT_ROW.findall(markdown):
        if key == "key":
            continue
        value: object = expected.strip()
        if re.fullmatch(r"\d+", str(value)):
            value = int(value)
        rows.append({"key": key, "expected": value, "rationale": rationale.strip()})
    return rows


class DocFacts(BaseModel):
    facts: list[str] = Field(default_factory=list, description="Short factual statements relevant to the incident")


class ResearchAgent(Agent):
    name = "research"
    title = "Research Agent"
    description = "Retrieves architecture invariants, runbooks and past postmortems with hybrid search."
    skills = [
        {"id": "architecture-invariants", "name": "Architecture invariants",
         "description": "Expected configuration values and design constraints for a service.",
         "tags": ["docs", "architecture", "configuration"]},
        {"id": "runbook-search", "name": "Runbook search",
         "description": "Hybrid BM25 + vector retrieval with RRF fusion and reranking over runbooks.",
         "tags": ["docs", "runbook", "rag"]},
        {"id": "postmortem-search", "name": "Postmortem search",
         "description": "Similar historical incidents from postmortems.", "tags": ["docs", "history"]},
    ]

    async def execute(self, task: AgentTask, gw: ToolGateway) -> AgentResult:
        service = task.params.get("service") or task.incident.service
        focus = task.params.get("focus", "architecture")
        evidence, notes = [], []

        if focus in ("architecture", "all"):
            res = await gw.call("docs.search_docs", query=f"{service} architecture configuration invariants",
                                k=3, doc_type="architecture", service=service)
            src = {"tool": "docs.search_docs", "args": {"doc_type": "architecture", "service": service}}
            if res["hits"]:
                doc = await gw.call("docs.get_document", path=res["hits"][0]["path"])
                for row in parse_invariants(doc["content"]):
                    evidence.append(self.evidence(
                        task, "doc_expectation", f"{doc['path']}: {row['key']} expected {row['expected']} "
                                                 f"({row['rationale'][:80]})",
                        {"service": service, **row, "doc": doc["path"],
                         "stale": "out of date" in doc["content"]},
                        {"tool": "docs.get_document", "args": {"path": doc["path"]}}))
            else:
                notes.append(f"no architecture document found for {service}")
            other = await gw.call("docs.search_docs", query=f"{service} notes operations", k=3, service=service)
            for hit in other["hits"]:
                if hit["doc_type"] == "architecture":
                    continue
                evidence.append(self.evidence(
                    task, "service_doc", f"{hit['title']}: {hit['text'][:140]}",
                    {"title": hit["title"], "path": hit["path"], "doc_type": hit["doc_type"]},
                    {"tool": "docs.search_docs", "args": {"service": service}}))

        signatures = task.params.get("signatures") or []
        queries = [f"{sig} {task.params.get('samples', {}).get(sig, '')}".strip() for sig in signatures]
        if not queries:
            queries = [task.incident.request]
        if focus in ("runbooks", "all") or not signatures:
            for q in queries[:3]:
                res = await gw.call("docs.search_runbook", symptom=q, k=2)
                for rank, hit in enumerate(res["hits"]):
                    evidence.append(self.evidence(
                        task, "runbook", f"Runbook '{hit['title']}' (rank {rank + 1}, score {hit['score']})",
                        {"title": hit["title"], "path": hit["path"], "patterns": hit["patterns"],
                         "score": hit["score"], "rank": rank + 1, "query": q[:120]},
                        {"tool": "docs.search_runbook", "args": {"symptom": q[:120]}}))
            res = await gw.call("docs.search_docs", query=" ".join(queries)[:300], k=3, doc_type="postmortem")
            for hit in res["hits"]:
                evidence.append(self.evidence(
                    task, "past_incident", f"Postmortem '{hit['title']}'",
                    {"title": hit["title"], "path": hit["path"], "patterns": hit["patterns"],
                     "service": hit["service"], "score": hit["score"]},
                    {"tool": "docs.search_docs", "args": {"doc_type": "postmortem"}}))

        llm = get_llm()
        if evidence:
            context = "\n".join(e.summary for e in evidence[:12])
            facts, _ = await llm.structured(
                task="doc_summary", system="You extract facts from engineering documentation.",
                prompt=f"Incident: {task.incident.request}\n" + wrap_untrusted("docs", context) +
                       "\nList up to 5 facts that matter for diagnosing this incident.",
                schema=DocFacts, fallback=lambda: DocFacts())
            notes.extend(facts.facts)
        summary = (f"{sum(e.kind == 'doc_expectation' for e in evidence)} invariants, "
                   f"{sum(e.kind == 'runbook' for e in evidence)} runbook hits, "
                   f"{sum(e.kind == 'past_incident' for e in evidence)} postmortems")
        return AgentResult(task_id=task.task_id, agent=self.name, summary=summary, evidence=evidence, notes=notes,
                           status="completed" if evidence else "no_data")
