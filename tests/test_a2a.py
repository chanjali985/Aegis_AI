import httpx
import pytest
from fastapi import FastAPI

from aegis.a2a.client import A2AError, AgentRegistry
from aegis.a2a.protocol import JSONRPCRequest
from aegis.a2a.server import A2AAgentServer, build_router
from aegis.agents.models import AgentTask, IncidentBrief
from aegis.agents.observability import ObservabilityAgent


def _task(ws, agent="observability"):
    brief = IncidentBrief(incident_id="INC-T", request="payment-service 500s", service="payment-service",
                          reported_at="2026-09-25T14:30:00Z")
    return AgentTask(agent=agent, goal="find onset", workspace=str(ws), incident=brief,
                     params={"service": "payment-service"})


def test_agent_card_shape():
    card = A2AAgentServer(ObservabilityAgent(), "http://x").card()
    assert card.name == "observability" and card.url == "http://x/a2a/observability"
    assert card.skills and card.metadata["tools"] == ["observability.*"]


async def test_unknown_method_is_jsonrpc_error():
    server = A2AAgentServer(ObservabilityAgent())
    resp = await server.handle(JSONRPCRequest(method="tasks/cancel"))
    assert resp.error.code == -32601


async def test_local_delegation(demo_ws):
    reg = AgentRegistry(remote={})
    result = await reg.send("observability", _task(demo_ws))
    assert result.data["onset"].startswith("2026-09-25T09:5")
    with pytest.raises(A2AError):
        await reg.send("nonexistent", _task(demo_ws))


async def test_remote_delegation_over_http(demo_ws):
    """The observability agent runs as a separate A2A service; the registry discovers and calls it over HTTP."""
    app = FastAPI()
    app.include_router(build_router({"observability": A2AAgentServer(ObservabilityAgent(), "http://remote")}))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://remote")
    reg = AgentRegistry(remote={"observability": "http://remote"}, http_client=client)
    cards = await reg.discover()
    assert cards["observability"].url.endswith("/a2a/observability")
    result = await reg.send("observability", _task(demo_ws))
    assert any(e.kind == "error_spike" for e in result.evidence)
    await client.aclose()
