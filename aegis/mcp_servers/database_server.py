"""Database MCP server: schema discovery and guarded read-only SQL on the prod replica.

Run standalone:  python -m aegis.mcp_servers.database_server --workspace <ws>
"""
from __future__ import annotations

import argparse
import sqlite3
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from aegis.security.sql_guard import validate_sql

QUERY_TIMEOUT_S = 5.0


def _connect(db: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)  # read-only at the driver level
    con.execute("PRAGMA query_only = ON")
    deadline = time.monotonic() + QUERY_TIMEOUT_S
    con.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
    return con


def build_server(workspace: str | Path) -> FastMCP:
    db = Path(workspace) / "prod_replica.db"
    mcp = FastMCP("database", instructions="Read-only production replica (SQLite dialect).")

    def tables() -> dict[str, list[dict]]:
        con = _connect(db)
        try:
            out = {}
            for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
                cols = [{"name": r[1], "type": r[2]} for r in con.execute(f"PRAGMA table_info({name})")]
                count = con.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                out[name] = {"columns": cols, "rows": count}
            return out
        finally:
            con.close()

    @mcp.tool()
    def get_schema() -> dict:
        """Tables, columns and row counts of the replica."""
        return {"dialect": "sqlite", "tables": tables()}

    @mcp.tool()
    def execute_readonly_sql(sql: str) -> dict:
        """Run one validated SELECT statement (max 200 rows, 5s timeout)."""
        check = validate_sql(sql, set(tables().keys()))
        if not check.ok:
            return {"ok": False, "errors": check.errors, "sql": sql}
        con = _connect(db)
        try:
            cur = con.execute(check.sql)
            cols = [d[0] for d in cur.description or []]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        except sqlite3.Error as exc:
            return {"ok": False, "errors": [f"{type(exc).__name__}: {exc}"], "sql": check.sql}
        finally:
            con.close()
        return {"ok": True, "sql": check.sql, "columns": cols, "rows": rows, "row_count": len(rows),
                "warnings": check.warnings}

    @mcp.tool()
    def explain_query(sql: str) -> dict:
        """EXPLAIN QUERY PLAN for a validated SELECT."""
        check = validate_sql(sql, set(tables().keys()))
        if not check.ok:
            return {"ok": False, "errors": check.errors}
        con = _connect(db)
        try:
            plan = [r[3] for r in con.execute("EXPLAIN QUERY PLAN " + check.sql)]
        except sqlite3.Error as exc:
            return {"ok": False, "errors": [str(exc)]}
        finally:
            con.close()
        return {"ok": True, "plan": plan}

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    build_server(ap.parse_args().workspace).run("stdio")


if __name__ == "__main__":
    main()
