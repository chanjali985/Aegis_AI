"""FastAPI application: REST + SSE API, dashboard, A2A endpoints and Prometheus metrics."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from aegis.a2a.client import get_registry
from aegis.a2a.server import build_router
from aegis.config import get_settings
from aegis.llm.router import get_llm
from aegis.observability.metrics import render_all
from aegis.observability.tracing import bus
from aegis.orchestration.runner import persistent_service
from aegis.security.permissions import ACCESS_LEVEL, APPROVAL_REQUIRED, POLICY
from aegis.storage.db import get_store
from aegis.world.generator import DEMO_SCENARIOS

STATIC = Path(__file__).parent / "static"
state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_settings()
    service, closer = await persistent_service()
    state["service"] = service
    yield
    for t in service.tasks.values():
        t.cancel()
    await closer.__aexit__(None, None, None)


app = FastAPI(title="AegisAI", version="0.1.0", lifespan=lifespan,
              description="Multi-agent incident investigation: LangGraph + MCP + A2A.")
app.include_router(build_router(get_registry().local))


class StartRequest(BaseModel):
    scenario: str = "payment-db-timeout"
    request: str | None = None


class Decision(BaseModel):
    decision: str
    comment: str = ""
    by: str = "on-call engineer"


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/healthz")
async def healthz():
    return {"ok": True, "llm_provider": get_llm().provider.name, "llm_live": get_llm().live,
            "mcp_transport": get_settings().mcp_transport}


@app.get("/api/scenarios")
async def scenarios():
    return [{"id": k, "family": v["family"], "service": v["service"], "request": v["request"]}
            for k, v in DEMO_SCENARIOS.items()]


@app.post("/api/investigations")
async def start(body: StartRequest):
    if body.scenario not in DEMO_SCENARIOS:
        raise HTTPException(400, "unknown scenario")
    run_id = await state["service"].start(request=body.request, scenario=body.scenario)
    return {"run_id": run_id}


@app.get("/api/investigations")
async def list_investigations():
    return get_store().list_investigations()


@app.get("/api/investigations/{run_id}")
async def get_investigation(run_id: str):
    inv = get_store().get_investigation(run_id)
    if not inv:
        raise HTTPException(404, "not found")
    pending = None
    try:
        snap = await state["service"].state(run_id)
        pending = snap["interrupts"][0] if snap["interrupts"] else None
        values = snap["values"]
        inv["live"] = {"brief": values.get("brief"), "plan": values.get("plan"), "onset": values.get("onset"),
                       "hypotheses": values.get("hypotheses"), "verifications": values.get("verifications"),
                       "fix": {k: (values.get("fix") or {}).get(k) for k in ("kind", "summary", "checks", "branch",
                                                                             "actions", "description")}
                       if values.get("fix") else None,
                       "evidence": [{"id": e["id"], "agent": e["agent"], "kind": e["kind"], "summary": e["summary"]}
                                    for e in values.get("evidence", [])]}
    except Exception:  # noqa: BLE001 - state may not exist yet
        pass
    inv["pending_approval"] = pending
    return inv


@app.get("/api/investigations/{run_id}/events")
async def events(run_id: str, after: int = 0):
    return get_store().events(run_id, after)


@app.get("/api/investigations/{run_id}/stream")
async def stream(run_id: str):
    async def gen():
        q = bus.subscribe(run_id)
        try:
            last = 0
            for e in get_store().events(run_id):
                last = e["id"]
                yield f"data: {json.dumps(e, default=str)}\n\n"
            while True:
                try:
                    e = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                if e["id"] <= last:
                    continue
                yield f"data: {json.dumps(e, default=str)}\n\n"
        finally:
            bus.unsubscribe(run_id, q)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/investigations/{run_id}/approval")
async def approve(run_id: str, body: Decision):
    try:
        await state["service"].decide(run_id, body.decision, body.comment, body.by)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@app.get("/api/investigations/{run_id}/trace")
async def trace(run_id: str):
    store = get_store()
    return {"spans": store.spans(run_id), "tool_calls": store.tool_calls(run_id), "llm_calls": store.llm_calls(run_id),
            "security_events": store.security_events(run_id)}


@app.get("/api/overview")
async def overview():
    store = get_store()
    return {**store.summary(), "security_events": store.security_events()[:30],
            "pending_approvals": store.approvals(status="pending"), "llm_provider": get_llm().provider.name,
            "llm_live": get_llm().live}


@app.get("/api/evaluation")
async def evaluation():
    latest = get_store().latest_evaluation()
    if latest:
        return {"source": "store", "summary": latest["summary"]}
    path = Path("evaluation/results/summary.json")
    if path.exists():
        return {"source": str(path), "summary": json.loads(path.read_text())}
    return {"source": None, "summary": None}


@app.get("/api/agents")
async def agents():
    cards = await get_registry().discover()
    return {"agents": [c.model_dump() for c in cards.values()],
            "orchestrator": [{"name": "supervisor", "description": "Triage, delegation, sufficiency and routing",
                              "access": ACCESS_LEVEL["supervisor"]},
                             {"name": "planner", "description": "Evidence-driven wave planning and re-planning",
                              "access": ACCESS_LEVEL["planner"]}],
            "policy": POLICY, "approval_required": sorted(APPROVAL_REQUIRED)}


@app.get("/metrics")
async def prometheus():
    return PlainTextResponse(render_all(), media_type="text/plain; version=0.0.4")
