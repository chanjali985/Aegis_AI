"""Base class for specialist agents."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from aegis.agents.models import AgentResult, AgentTask, Evidence
from aegis.observability.tracing import agent_span, emit
from aegis.tools.gateway import ToolGateway


class Agent(ABC):
    name: str = "agent"
    title: str = "Agent"
    description: str = ""
    skills: list[dict[str, Any]] = []

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}

    def evidence(self, task: AgentTask, kind: str, summary: str, data: dict | None = None,
                 source: dict | None = None, time: str | None = None) -> Evidence:
        n = self._counters[task.task_id] = self._counters.get(task.task_id, 0) + 1
        return Evidence(id=f"E-{self.name[:3]}-{task.task_id[:6]}-{n}", agent=self.name,
                        kind=kind, summary=summary, data=data or {}, source=source or {}, time=time)

    async def run(self, task: AgentTask) -> AgentResult:
        async with agent_span(self.name, task.goal, wave=task.wave) as sp:
            async with ToolGateway(task.workspace, self.name, run_id=task.run_id) as gw:
                result = await self.execute(task, gw)
                result.tools_called = gw.tools_called
                result.security_findings = [f for f in gw.security_findings if f["kind"] != "pii_masked"]
            sp["attrs"]["result_summary"] = {"summary": result.summary, "evidence": len(result.evidence),
                                             "tools": len(result.tools_called), "status": result.status}
        self._counters.pop(task.task_id, None)
        for ev in result.evidence:
            emit("evidence", {"id": ev.id, "kind": ev.kind, "summary": ev.summary}, agent=self.name)
        return result

    @abstractmethod
    async def execute(self, task: AgentTask, gw: ToolGateway) -> AgentResult: ...
