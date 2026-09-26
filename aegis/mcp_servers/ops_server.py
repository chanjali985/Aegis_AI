"""Ops MCP server: production control-plane actions. Every tool requires human approval.

The gateway refuses to forward calls without a valid single-use approval token;
this server additionally records every executed action to an append-only log.

Run standalone:  python -m aegis.mcp_servers.ops_server --workspace <ws>
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP


def build_server(workspace: str | Path) -> FastMCP:
    log = Path(workspace) / "control_plane_actions.jsonl"
    mcp = FastMCP("ops", instructions="Production control plane. Actions require human approval.")

    def record(action: str, **params) -> dict:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "action": action, **params,
                 "status": "applied"}
        with open(log, "a") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    @mcp.tool()
    def set_feature_flag(flag: str, enabled: bool, reason: str) -> dict:
        """[approval required] Enable or disable a feature flag."""
        return record("set_feature_flag", flag=flag, enabled=enabled, reason=reason)

    @mcp.tool()
    def rotate_certificate(host: str, reason: str) -> dict:
        """[approval required] Trigger certificate rotation for a host via cert-manager."""
        return record("rotate_certificate", host=host, reason=reason)

    @mcp.tool()
    def list_actions() -> dict:
        """Actions applied so far."""
        if not log.exists():
            return {"actions": []}
        return {"actions": [json.loads(l) for l in log.read_text().splitlines() if l]}

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    build_server(ap.parse_args().workspace).run("stdio")


if __name__ == "__main__":
    main()
