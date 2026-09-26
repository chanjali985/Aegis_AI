"""MCP client gateway: the only path from agents to tools.

For every call the gateway (1) checks the agent's permission and any approval
token, (2) invokes the tool over the MCP protocol - in-memory streams by
default, or stdio subprocesses with ``AEGIS_MCP_TRANSPORT=stdio`` - (3) masks
PII/secrets, (4) quarantines prompt-injection attempts, and (5) records an
audit trail, metrics and a trace span.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import ClientSession

from aegis.config import get_settings
from aegis.observability import metrics
from aegis.observability.tracing import current_run, emit, span
from aegis.security.permissions import PermissionDenied, authorize
from aegis.security.pii import redact
from aegis.security.prompt_injection import quarantine
from aegis.storage.db import get_store

SERVER_MODULES = {
    "git": "aegis.mcp_servers.git_server",
    "observability": "aegis.mcp_servers.observability_server",
    "database": "aegis.mcp_servers.database_server",
    "docs": "aegis.mcp_servers.docs_server",
    "ops": "aegis.mcp_servers.ops_server",
}


for _name in ("mcp", "mcp.server", "mcp.server.lowlevel.server", "mcp.server.fastmcp"):
    logging.getLogger(_name).setLevel(logging.WARNING)


class ToolError(Exception):
    pass


def _build(server: str, workspace: str):
    import importlib
    return importlib.import_module(SERVER_MODULES[server]).build_server(workspace)


class ToolGateway:
    def __init__(self, workspace: str | Path, agent: str, run_id: str | None = None,
                 transport: str | None = None):
        self.workspace = str(workspace)
        self.agent = agent
        self.run_id = run_id or current_run.get()
        self.transport = transport or get_settings().mcp_transport
        self._stack = AsyncExitStack()
        self._sessions: dict[str, ClientSession] = {}
        self.calls: list[dict] = []
        self.security_findings: list[dict] = []

    async def __aenter__(self) -> "ToolGateway":
        await self._stack.__aenter__()
        return self

    async def __aexit__(self, *exc) -> None:
        await self._stack.__aexit__(*exc)

    async def _session(self, server: str) -> ClientSession:
        if server in self._sessions:
            return self._sessions[server]
        if server not in SERVER_MODULES:
            raise ToolError(f"unknown MCP server '{server}'")
        if self.transport == "stdio":
            from mcp.client.stdio import StdioServerParameters, stdio_client
            params = StdioServerParameters(command=sys.executable,
                                           args=["-m", SERVER_MODULES[server], "--workspace", self.workspace])
            read, write = await self._stack.enter_async_context(stdio_client(params))
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        else:
            from mcp.shared.memory import create_connected_server_and_client_session
            session = await self._stack.enter_async_context(
                create_connected_server_and_client_session(_build(server, self.workspace)))
        self._sessions[server] = session
        return session

    async def list_tools(self, server: str) -> list[dict]:
        session = await self._session(server)
        result = await session.list_tools()
        return [{"name": f"{server}.{t.name}", "description": t.description,
                 "input_schema": t.inputSchema} for t in result.tools]

    async def call(self, tool: str, approval_token: str | None = None, **args: Any) -> dict:
        server, name = tool.split(".", 1)
        t0 = time.perf_counter()
        record = {"run_id": self.run_id, "agent": self.agent, "server": server, "tool": name, "args": args,
                  "ok": False, "denied": False, "latency_ms": 0.0, "redactions": 0, "injections": 0}
        with span(f"tool:{tool}", kind="tool", agent=self.agent, tool=tool) as sp:
            try:
                authorize(self.agent, tool, self.run_id, approval_token)
            except PermissionDenied as exc:
                record["denied"] = True
                self._audit(record, t0)
                self._security("permission_denied", {"tool": tool, "reason": str(exc)})
                metrics.TOOL_CALLS.inc(tool=tool, outcome="denied")
                raise
            session = await self._session(server)
            result = await session.call_tool(name, args)
            text = "".join(getattr(c, "text", "") for c in result.content)
            if result.isError:
                self._audit(record, t0)
                metrics.TOOL_CALLS.inc(tool=tool, outcome="error")
                raise ToolError(text[:500])
            data = result.structuredContent if result.structuredContent is not None else json.loads(text or "{}")
            if isinstance(data, dict) and set(data) == {"result"} and isinstance(data["result"], dict):
                data = data["result"]
            data, redactions = redact(data)
            data, injections = quarantine(data)
            record.update(ok=True, redactions=sum(redactions.values()), injections=len(injections))
            sp["attrs"].update(redactions=record["redactions"], injections=record["injections"])
            if redactions:
                self._security("pii_masked", {"tool": tool, "counts": redactions})
            for f in injections:
                self._security("prompt_injection_quarantined", {"tool": tool, "rule": f.rule,
                                                                "excerpt": f.excerpt[:160]})
            self._audit(record, t0)
            metrics.TOOL_CALLS.inc(tool=tool, outcome="ok")
            metrics.TOOL_LATENCY.observe(time.perf_counter() - t0, tool=tool)
            return data

    def _audit(self, record: dict, t0: float) -> None:
        record["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        self.calls.append({k: record[k] for k in ("server", "tool", "ok", "denied", "latency_ms")})
        if self.run_id:
            get_store().add_tool_call(record)

    def _security(self, kind: str, detail: dict) -> None:
        self.security_findings.append({"kind": kind, **detail})
        metrics.SECURITY_EVENTS.inc(kind=kind)
        if self.run_id:
            get_store().add_security_event(self.run_id, self.agent, kind, detail)
            if kind != "pii_masked":
                emit("security_event", {"kind": kind, **detail}, agent=self.agent)

    @property
    def tools_called(self) -> list[str]:
        return [c["tool"] for c in self.calls if c["ok"]]
