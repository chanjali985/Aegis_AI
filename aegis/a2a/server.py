"""A2A server side: wraps an ``Agent`` behind JSON-RPC and publishes its Agent Card."""
from __future__ import annotations

import traceback

from fastapi import APIRouter, Request

from aegis.a2a.protocol import (AgentCard, AgentSkill, Artifact, DataPart, JSONRPCError, JSONRPCRequest,
                                JSONRPCResponse, Message, Task, TaskStatus)
from aegis.agents.base import Agent
from aegis.agents.models import AgentTask
from aegis.observability.tracing import bind_run
from aegis.security.permissions import ACCESS_LEVEL, POLICY


class A2AAgentServer:
    """Protocol adapter around one agent. Used both in-process and over HTTP."""

    def __init__(self, agent: Agent, base_url: str = "local://"):
        self.agent = agent
        self.base_url = base_url
        self.tasks: dict[str, Task] = {}

    def card(self) -> AgentCard:
        return AgentCard(
            name=self.agent.name, description=self.agent.description,
            url=f"{self.base_url.rstrip('/')}/a2a/{self.agent.name}",
            skills=[AgentSkill(**s) for s in self.agent.skills],
            metadata={"title": self.agent.title, "tools": POLICY.get(self.agent.name, []),
                      "access": ACCESS_LEVEL.get(self.agent.name, "")})

    async def handle(self, req: JSONRPCRequest) -> JSONRPCResponse:
        if req.method == "tasks/get":
            task = self.tasks.get(req.params.get("id", ""))
            if not task:
                return JSONRPCResponse(id=req.id, error=JSONRPCError(code=-32001, message="Task not found"))
            return JSONRPCResponse(id=req.id, result=task.model_dump())
        if req.method != "message/send":
            return JSONRPCResponse(id=req.id, error=JSONRPCError(code=-32601, message="Method not found"))
        try:
            message = Message.model_validate(req.params["message"])
            data = next(p.data for p in message.parts if isinstance(p, DataPart))
            agent_task = AgentTask.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            return JSONRPCResponse(id=req.id, error=JSONRPCError(code=-32602, message=f"Invalid params: {exc}"))
        if agent_task.run_id:
            bind_run(agent_task.run_id)
        task = Task(contextId=message.contextId or agent_task.run_id or agent_task.task_id,
                    status=TaskStatus(state="working"), history=[message])
        self.tasks[task.id] = task
        try:
            result = await self.agent.run(agent_task)
            task.status = TaskStatus(state="completed" if result.status != "failed" else "failed",
                                     message=result.summary)
            task.artifacts.append(Artifact(name="agent_result", parts=[DataPart(data=result.model_dump())]))
        except Exception as exc:  # noqa: BLE001
            task.status = TaskStatus(state="failed", message=f"{type(exc).__name__}: {exc}")
            task.artifacts.append(Artifact(name="error", parts=[DataPart(data={
                "error": repr(exc), "trace": traceback.format_exc()[-1500:]})]))
        if len(self.tasks) > 500:
            self.tasks.pop(next(iter(self.tasks)))
        return JSONRPCResponse(id=req.id, result=task.model_dump())


def build_router(servers: dict[str, A2AAgentServer]) -> APIRouter:
    router = APIRouter()

    @router.get("/a2a/agents")
    async def list_cards():
        return [s.card().model_dump() for s in servers.values()]

    @router.get("/a2a/{agent}/.well-known/agent-card.json")
    async def card(agent: str, request: Request):
        server = servers[agent]
        server.base_url = str(request.base_url)
        return server.card().model_dump()

    @router.post("/a2a/{agent}")
    async def rpc(agent: str, body: dict):
        if agent not in servers:
            return JSONRPCResponse(id=body.get("id"), error=JSONRPCError(code=-32004, message="Unknown agent")).model_dump()
        resp = await servers[agent].handle(JSONRPCRequest.model_validate(body))
        return resp.model_dump()

    return router
