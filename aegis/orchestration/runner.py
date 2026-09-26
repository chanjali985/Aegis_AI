"""Runs investigations: workspace setup, graph execution, pause/resume for human approval."""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from aegis.config import get_settings
from aegis.observability.tracing import bind_run, emit
from aegis.orchestration.graph import build_graph
from aegis.storage.db import get_store
from aegis.world.generator import DEMO_SCENARIOS, build_workspace, demo_spec, sample_spec


class InvestigationService:
    def __init__(self, checkpointer=None):
        self.checkpointer = checkpointer or InMemorySaver()
        self.graph = build_graph().compile(checkpointer=self.checkpointer)
        self.tasks: dict[str, asyncio.Task] = {}

    # -- workspaces ---------------------------------------------------------------------
    @staticmethod
    def prepare_workspace(scenario: str | None = None, sample_index: int | None = None,
                          root: Path | None = None) -> Path:
        root = root or get_settings().workspaces_dir
        if sample_index is not None:
            spec = sample_spec(sample_index)
        else:
            spec = demo_spec(scenario or "payment-db-timeout")
        ws = root / f"{spec.incident_id.lower()}-{uuid.uuid4().hex[:6]}"
        build_workspace(spec, ws)
        return ws

    # -- lifecycle ----------------------------------------------------------------------------
    async def start(self, request: str | None = None, scenario: str | None = None, workspace: str | Path | None = None,
                    sample_index: int | None = None, auto_approve: bool = False, options: dict | None = None,
                    background: bool = True, run_id: str | None = None) -> str:
        if scenario and scenario not in DEMO_SCENARIOS:
            raise ValueError(f"unknown scenario {scenario}")
        ws = Path(workspace) if workspace else await asyncio.to_thread(self.prepare_workspace, scenario, sample_index)
        incident = json.loads((ws / "incident.json").read_text())
        run_id = run_id or uuid.uuid4().hex[:12]
        request = (request or incident["request"]).strip()
        get_store().create_investigation(run_id, incident["incident_id"], str(ws), request)
        state = {"run_id": run_id, "workspace": str(ws), "incident_id": incident["incident_id"], "request": request,
                 "reported_at": incident["reported_at"], "auto_approve": auto_approve, "options": options or {}}
        coro = self._drive(run_id, state)
        if background:
            self.tasks[run_id] = asyncio.create_task(coro)
        else:
            await coro
        return run_id

    async def decide(self, run_id: str, decision: str, comment: str = "", by: str = "on-call engineer",
                     background: bool = True) -> None:
        if decision not in ("approve", "reject", "request_changes"):
            raise ValueError("decision must be approve | reject | request_changes")
        snapshot = await self.graph.aget_state(self._config(run_id))
        if not snapshot.next:
            raise ValueError("investigation is not waiting for approval")
        coro = self._drive(run_id, Command(resume={"decision": decision, "comment": comment, "by": by}))
        if background:
            self.tasks[run_id] = asyncio.create_task(coro)
        else:
            await coro

    async def state(self, run_id: str) -> dict:
        snapshot = await self.graph.aget_state(self._config(run_id))
        return {"values": snapshot.values, "next": list(snapshot.next),
                "interrupts": [i.value for t in snapshot.tasks for i in t.interrupts]}

    @staticmethod
    def _config(run_id: str) -> dict:
        return {"configurable": {"thread_id": run_id}, "recursion_limit": 80}

    async def _drive(self, run_id: str, graph_input) -> None:
        bind_run(run_id)
        store = get_store()
        try:
            store.update_investigation(run_id, "running")
            await self.graph.ainvoke(graph_input, self._config(run_id))
            snapshot = await self.graph.aget_state(self._config(run_id))
            if snapshot.next:
                store.update_investigation(run_id, "awaiting_approval")
                emit("status", {"status": "awaiting_approval"}, agent="supervisor")
            else:
                emit("status", {"status": snapshot.values.get("status")}, agent="supervisor")
        except Exception as exc:  # noqa: BLE001
            import traceback
            store.update_investigation(run_id, "failed", {"error": repr(exc), "trace": traceback.format_exc()[-3000:]})
            emit("status", {"status": "failed", "error": repr(exc)}, agent="supervisor")
            raise


async def persistent_service() -> tuple[InvestigationService, object]:
    """Service backed by a SQLite checkpointer (survives restarts). Returns (service, closer)."""
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
    cm = AsyncSqliteSaver.from_conn_string(str(get_settings().checkpoint_path))
    saver = await cm.__aenter__()
    return InvestigationService(saver), cm
