"""A2A client + registry: discovery by Agent Card and delegation via ``message/send``."""
from __future__ import annotations

import httpx

from aegis.a2a.protocol import AgentCard, DataPart, JSONRPCRequest, JSONRPCResponse, Message, Task
from aegis.a2a.server import A2AAgentServer
from aegis.agents.code import CodeAgent
from aegis.agents.database import DatabaseAgent
from aegis.agents.fix import FixAgent
from aegis.agents.memory_agent import MemoryAgent
from aegis.agents.models import AgentResult, AgentTask
from aegis.agents.observability import ObservabilityAgent
from aegis.agents.rca import RCAAgent
from aegis.agents.research import ResearchAgent
from aegis.agents.verification import VerificationAgent
from aegis.config import get_settings

SPECIALISTS = [ResearchAgent, ObservabilityAgent, CodeAgent, DatabaseAgent, MemoryAgent, RCAAgent,
               VerificationAgent, FixAgent]


class A2AError(Exception):
    pass


class AgentRegistry:
    """Knows where each agent lives; hides whether it is local or remote."""

    def __init__(self, remote: dict[str, str] | None = None, http_client: httpx.AsyncClient | None = None):
        self.local = {cls.name: A2AAgentServer(cls()) for cls in SPECIALISTS}
        self.remote = remote if remote is not None else get_settings().remote_agent_map()
        self._http = http_client
        self._cards: dict[str, AgentCard] = {}

    async def discover(self) -> dict[str, AgentCard]:
        cards = {name: server.card() for name, server in self.local.items() if name not in self.remote}
        for name, url in self.remote.items():
            async with self._client() as client:
                r = await client.get(f"{url}/a2a/{name}/.well-known/agent-card.json")
                r.raise_for_status()
                cards[name] = AgentCard.model_validate(r.json())
        self._cards = cards
        return cards

    def _client(self):
        if self._http is not None:
            class _Borrowed:
                def __init__(s, c): s.c = c
                async def __aenter__(s): return s.c
                async def __aexit__(s, *a): return None
            return _Borrowed(self._http)
        return httpx.AsyncClient(timeout=600)

    async def send(self, agent: str, task: AgentTask) -> AgentResult:
        msg = Message(contextId=task.run_id, parts=[DataPart(data=task.model_dump())])
        req = JSONRPCRequest(method="message/send", params={"message": msg.model_dump()})
        if agent in self.remote:
            async with self._client() as client:
                r = await client.post(f"{self.remote[agent]}/a2a/{agent}", json=req.model_dump())
                r.raise_for_status()
                resp = JSONRPCResponse.model_validate(r.json())
        elif agent in self.local:
            resp = await self.local[agent].handle(req)
        else:
            raise A2AError(f"no agent named '{agent}' is registered")
        if resp.error:
            raise A2AError(f"{agent}: {resp.error.message}")
        a2a_task = Task.model_validate(resp.result)
        for art in a2a_task.artifacts:
            if art.name == "agent_result":
                return AgentResult.model_validate(art.parts[0].data)
        err = a2a_task.artifacts[0].parts[0].data if a2a_task.artifacts else {}
        raise A2AError(f"{agent} failed: {a2a_task.status.message} {err.get('trace', '')[-600:]}")


_registry: AgentRegistry | None = None


def get_registry() -> AgentRegistry:
    global _registry
    if _registry is None:
        _registry = AgentRegistry()
    return _registry


def set_registry(reg: AgentRegistry | None) -> None:
    global _registry
    _registry = reg
