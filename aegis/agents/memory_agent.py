"""Memory agent: recalls similar past incidents and root-cause priors; records outcomes."""
from __future__ import annotations

from aegis.agents.base import Agent
from aegis.agents.models import AgentResult, AgentTask
from aegis.memory.episodic import EpisodicMemory
from aegis.storage.db import get_store
from aegis.tools.gateway import ToolGateway


class MemoryAgent(Agent):
    name = "memory"
    title = "Memory Agent"
    description = "Episodic recall of similar incidents and per-service root-cause priors."
    skills = [
        {"id": "recall", "name": "Incident recall", "description": "Similar past incidents and their fixes.",
         "tags": ["memory", "history", "priors"]},
        {"id": "remember", "name": "Record outcome", "description": "Store a finished investigation.",
         "tags": ["memory"]},
    ]

    async def execute(self, task: AgentTask, gw: ToolGateway) -> AgentResult:
        mem = EpisodicMemory(get_store())
        if task.params.get("action") == "remember":
            mem.remember(task.params["record"])
            return AgentResult(task_id=task.task_id, agent=self.name, summary="outcome stored in episodic memory")
        imported = mem.import_history(task.workspace)
        service = task.params.get("service") or task.incident.service
        query = " ".join([task.incident.request, *task.params.get("signatures", [])])
        hits = mem.recall(query, service, k=3)
        priors = mem.priors(service)
        evidence = [self.evidence(task, "memory_recall",
                                  f"Similar past incident {h['id']} ({h['service']}): {h['summary']} "
                                  f"-> {h['resolution'][:60]} (sim {h['similarity']})",
                                  {"incident_id": h["id"], "service": h["service"], "root_cause": h["root_cause"],
                                   "similarity": h["similarity"], "resolution": h["resolution"]},
                                  {"tool": "memory.recall", "args": {"service": service}}) for h in hits]
        return AgentResult(task_id=task.task_id, agent=self.name,
                           summary=f"{len(hits)} similar incidents; priors for {service}: {priors or 'none'}",
                           evidence=evidence, data={"priors": priors, "imported": imported})
