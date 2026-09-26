"""Baselines the multi-agent system is compared against.

* ``naive_last_deploy``  - what a tired on-call engineer does first: blame the most recent
  deploy of the affected service before the report and roll it back.
* ``logs_only_agent``    - a single agent that looks only at logs: maps the dominant error
  signature straight to a failure pattern, with no cross-source correlation or verification.
"""
from __future__ import annotations

import json
from pathlib import Path

from aegis.mcp_servers.git_server import build_server as git_server
from aegis.mcp_servers.observability_server import build_server as obs_server

SIGNATURE_TO_PATTERN = {
    "DatabaseTimeoutError": "db_timeout_reduced", "SlowQuery": "missing_index",
    "ConnectionPoolExhausted": "pool_size_reduced", "KeyError": "code_missing_field",
    "RateLimitExceeded": "rate_limit_reduced", "OOMKilled": "cache_unbounded",
    "ServiceUnavailable": "cache_unbounded", "UpstreamError": "upstream_outage",
    "ValueError": "flag_enabled", "SSLError": "cert_expired", "UpstreamTimeout": "retry_storm",
}


async def _call(server, tool: str, **args) -> dict:
    result = await server.call_tool(tool, args)
    # FastMCP.call_tool returns (content, structured) in recent SDKs
    if isinstance(result, tuple):
        structured = result[1]
        if isinstance(structured, dict):
            return structured.get("result", structured) if set(structured) == {"result"} else structured
        return json.loads(result[0][0].text)
    return json.loads(result[0].text)


async def naive_last_deploy(ws: Path, service: str, reported_at: str) -> dict:
    deploys = (await _call(git_server(ws), "list_deploys", service=service))["deploys"]
    before = [d for d in deploys if d["deployed_at"] <= reported_at]
    last = before[-1]
    return {"pattern": "bad_deploy_generic", "culprit": {"type": "deploy", "commit": last["commit"],
                                                         "version": last["version"]}}


async def logs_only_agent(ws: Path, service: str) -> dict:
    spikes = (await _call(obs_server(ws), "find_error_spikes", service=service))["spikes"]
    spikes = [s for s in spikes if s["llr"] >= 8 and s["factor"] >= 3]
    if not spikes:
        return {"pattern": "unknown", "culprit": {}}
    return {"pattern": SIGNATURE_TO_PATTERN.get(spikes[0]["error_type"], "unknown"), "culprit": {}}
