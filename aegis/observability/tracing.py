"""Span tracing and live event streaming for agent runs.

Every agent step, tool call and LLM call becomes a span (persisted to the
store, exported to OpenTelemetry when the SDK is installed) and every
user-visible milestone becomes an event pushed to subscribers (the dashboard
reads them over Server-Sent Events).
"""
from __future__ import annotations

import asyncio
import contextvars
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from typing import Any

from aegis.observability import metrics
from aegis.storage.db import get_store

current_run: contextvars.ContextVar[str | None] = contextvars.ContextVar("current_run", default=None)
current_agent: contextvars.ContextVar[str] = contextvars.ContextVar("current_agent", default="system")
current_span: contextvars.ContextVar[str | None] = contextvars.ContextVar("current_span", default=None)

try:  # optional OpenTelemetry export
    from opentelemetry import trace as _otel_trace  # type: ignore

    _otel_tracer = _otel_trace.get_tracer("aegis")
except Exception:  # noqa: BLE001
    _otel_tracer = None


class EventBus:
    """In-process pub/sub keyed by run id (fan-out to SSE subscribers)."""

    def __init__(self) -> None:
        self._subs: dict[str, list[asyncio.Queue]] = {}

    def subscribe(self, run_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subs.setdefault(run_id, []).append(q)
        return q

    def unsubscribe(self, run_id: str, q: asyncio.Queue) -> None:
        if q in self._subs.get(run_id, []):
            self._subs[run_id].remove(q)

    def publish(self, run_id: str, event: dict) -> None:
        for q in list(self._subs.get(run_id, [])):
            q.put_nowait(event)


bus = EventBus()


def emit(type_: str, data: dict[str, Any] | None = None, agent: str | None = None,
         run_id: str | None = None) -> None:
    run_id = run_id or current_run.get()
    if not run_id:
        return
    agent = agent or current_agent.get()
    data = data or {}
    event_id = get_store().add_event(run_id, agent, type_, data)
    bus.publish(run_id, {"id": event_id, "ts": time.time(), "agent": agent, "type": type_, "data": data})


def _record(span: dict) -> None:
    if span["run_id"]:
        get_store().add_span(span)


@contextmanager
def span(name: str, kind: str = "internal", agent: str | None = None, **attrs: Any):
    agent = agent or current_agent.get()
    s = {"span_id": uuid.uuid4().hex[:16], "run_id": current_run.get(), "parent_id": current_span.get(),
         "name": name, "kind": kind, "agent": agent, "start": time.time(), "attrs": dict(attrs)}
    token = current_span.set(s["span_id"])
    agent_token = current_agent.set(agent)
    otel_cm = _otel_tracer.start_as_current_span(name) if _otel_tracer else None
    if otel_cm:
        otel_cm.__enter__()
    try:
        yield s
        s["status"] = "ok"
    except Exception as exc:
        s["status"] = "error"
        s["attrs"]["error"] = repr(exc)
        raise
    finally:
        s["end"] = time.time()
        current_span.reset(token)
        current_agent.reset(agent_token)
        if otel_cm:
            otel_cm.__exit__(None, None, None)
        _record(s)
        if kind == "agent":
            metrics.AGENT_LATENCY.observe((s["end"] - s["start"]), agent=agent)
            metrics.AGENT_RUNS.inc(agent=agent, status=s["status"])


@asynccontextmanager
async def agent_span(agent: str, task: str, **attrs: Any):
    emit("agent_started", {"task": task, **attrs}, agent=agent)
    t0 = time.time()
    with span(f"{agent}:{task}", kind="agent", agent=agent, task=task, **attrs) as s:
        try:
            yield s
        except Exception as exc:
            emit("agent_failed", {"task": task, "error": repr(exc)}, agent=agent)
            raise
    emit("agent_finished", {"task": task, "latency_ms": round((time.time() - t0) * 1000, 1),
                            **s["attrs"].get("result_summary", {})}, agent=agent)


def bind_run(run_id: str):
    return current_run.set(run_id)
