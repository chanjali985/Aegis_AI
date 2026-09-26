"""SQLite persistence for investigations, traces, approvals, memory and evaluations.

SQLite keeps the project zero-setup. Every query goes through this module, so
swapping in PostgreSQL means re-implementing one class.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY, incident_id TEXT, workspace TEXT, request TEXT, status TEXT,
    created_at REAL, updated_at REAL, result TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, ts REAL, agent TEXT, type TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, id);
CREATE TABLE IF NOT EXISTS spans (
    span_id TEXT PRIMARY KEY, run_id TEXT, parent_id TEXT, name TEXT, kind TEXT, agent TEXT,
    start REAL, end REAL, status TEXT, attrs TEXT
);
CREATE INDEX IF NOT EXISTS idx_spans_run ON spans(run_id);
CREATE TABLE IF NOT EXISTS llm_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, agent TEXT, task TEXT, provider TEXT,
    model TEXT, tier TEXT, input_tokens INTEGER, output_tokens INTEGER, cost_usd REAL,
    baseline_cost_usd REAL, latency_ms REAL, estimated INTEGER, ts REAL
);
CREATE TABLE IF NOT EXISTS tool_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, agent TEXT, server TEXT, tool TEXT,
    args TEXT, ok INTEGER, denied INTEGER, latency_ms REAL, redactions INTEGER,
    injections INTEGER, ts REAL
);
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, agent TEXT, kind TEXT, detail TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY, run_id TEXT, action TEXT, payload TEXT, status TEXT, decided_by TEXT,
    comment TEXT, created_at REAL, decided_at REAL
);
CREATE TABLE IF NOT EXISTS episodic_memory (
    id TEXT PRIMARY KEY, service TEXT, root_cause TEXT, summary TEXT, resolution TEXT,
    signature TEXT, source TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS evaluations (
    id TEXT PRIMARY KEY, created_at REAL, config TEXT, summary TEXT, cases TEXT
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._con.row_factory = sqlite3.Row
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.executescript(SCHEMA)

    # -- generic helpers ------------------------------------------------------
    def execute(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            self._con.execute(sql, params)

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._con.execute(sql, params).fetchall()]

    # -- investigations --------------------------------------------------------
    def create_investigation(self, run_id: str, incident_id: str, workspace: str, request: str) -> None:
        now = time.time()
        self.execute("INSERT OR REPLACE INTO investigations VALUES (?,?,?,?,?,?,?,?)",
                     (run_id, incident_id, workspace, request, "running", now, now, None))

    def update_investigation(self, run_id: str, status: str, result: dict | None = None) -> None:
        if result is None:
            self.execute("UPDATE investigations SET status=?, updated_at=? WHERE id=?",
                         (status, time.time(), run_id))
        else:
            self.execute("UPDATE investigations SET status=?, updated_at=?, result=? WHERE id=?",
                         (status, time.time(), json.dumps(result, default=str), run_id))

    def get_investigation(self, run_id: str) -> dict | None:
        rows = self.query("SELECT * FROM investigations WHERE id=?", (run_id,))
        if not rows:
            return None
        row = rows[0]
        row["result"] = json.loads(row["result"]) if row["result"] else None
        return row

    def list_investigations(self, limit: int = 50) -> list[dict]:
        return self.query("SELECT id, incident_id, request, status, created_at, updated_at "
                          "FROM investigations ORDER BY created_at DESC LIMIT ?", (limit,))

    # -- events ------------------------------------------------------------------
    def add_event(self, run_id: str, agent: str, type_: str, data: dict) -> int:
        with self._lock:
            cur = self._con.execute("INSERT INTO events (run_id, ts, agent, type, data) VALUES (?,?,?,?,?)",
                                    (run_id, time.time(), agent, type_, json.dumps(data, default=str)))
            return cur.lastrowid

    def events(self, run_id: str, after: int = 0) -> list[dict]:
        rows = self.query("SELECT * FROM events WHERE run_id=? AND id>? ORDER BY id", (run_id, after))
        for r in rows:
            r["data"] = json.loads(r["data"])
        return rows

    # -- telemetry -----------------------------------------------------------------
    def add_span(self, span: dict) -> None:
        self.execute("INSERT OR REPLACE INTO spans VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (span["span_id"], span["run_id"], span.get("parent_id"), span["name"], span["kind"],
                      span.get("agent"), span["start"], span.get("end"), span.get("status"),
                      json.dumps(span.get("attrs", {}), default=str)))

    def spans(self, run_id: str) -> list[dict]:
        rows = self.query("SELECT * FROM spans WHERE run_id=? ORDER BY start", (run_id,))
        for r in rows:
            r["attrs"] = json.loads(r["attrs"] or "{}")
        return rows

    def add_llm_call(self, rec: dict) -> None:
        self.execute("INSERT INTO llm_calls (run_id, agent, task, provider, model, tier, input_tokens, "
                     "output_tokens, cost_usd, baseline_cost_usd, latency_ms, estimated, ts) "
                     "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (rec["run_id"], rec["agent"], rec["task"], rec["provider"], rec["model"], rec["tier"],
                      rec["input_tokens"], rec["output_tokens"], rec["cost_usd"], rec["baseline_cost_usd"],
                      rec["latency_ms"], int(rec["estimated"]), time.time()))

    def add_tool_call(self, rec: dict) -> None:
        self.execute("INSERT INTO tool_calls (run_id, agent, server, tool, args, ok, denied, latency_ms, "
                     "redactions, injections, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (rec["run_id"], rec["agent"], rec["server"], rec["tool"],
                      json.dumps(rec.get("args", {}), default=str), int(rec["ok"]), int(rec["denied"]),
                      rec["latency_ms"], rec.get("redactions", 0), rec.get("injections", 0), time.time()))

    def tool_calls(self, run_id: str) -> list[dict]:
        return self.query("SELECT * FROM tool_calls WHERE run_id=? ORDER BY id", (run_id,))

    def llm_calls(self, run_id: str) -> list[dict]:
        return self.query("SELECT * FROM llm_calls WHERE run_id=? ORDER BY id", (run_id,))

    def add_security_event(self, run_id: str, agent: str, kind: str, detail: dict) -> None:
        self.execute("INSERT INTO security_events (run_id, agent, kind, detail, ts) VALUES (?,?,?,?,?)",
                     (run_id, agent, kind, json.dumps(detail, default=str), time.time()))

    def security_events(self, run_id: str | None = None) -> list[dict]:
        if run_id:
            rows = self.query("SELECT * FROM security_events WHERE run_id=? ORDER BY id", (run_id,))
        else:
            rows = self.query("SELECT * FROM security_events ORDER BY id DESC LIMIT 200")
        for r in rows:
            r["detail"] = json.loads(r["detail"])
        return rows

    # -- approvals -------------------------------------------------------------------
    def create_approval(self, approval_id: str, run_id: str, action: str, payload: dict) -> None:
        self.execute("INSERT OR REPLACE INTO approvals VALUES (?,?,?,?,?,?,?,?,?)",
                     (approval_id, run_id, action, json.dumps(payload, default=str), "pending", None, None,
                      time.time(), None))

    def decide_approval(self, approval_id: str, status: str, decided_by: str, comment: str) -> None:
        self.execute("UPDATE approvals SET status=?, decided_by=?, comment=?, decided_at=? WHERE id=?",
                     (status, decided_by, comment, time.time(), approval_id))

    def approvals(self, run_id: str | None = None, status: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM approvals WHERE 1=1", []
        if run_id:
            sql += " AND run_id=?"
            params.append(run_id)
        if status:
            sql += " AND status=?"
            params.append(status)
        rows = self.query(sql + " ORDER BY created_at DESC", tuple(params))
        for r in rows:
            r["payload"] = json.loads(r["payload"])
        return rows

    # -- episodic memory ---------------------------------------------------------------
    def add_memory(self, rec: dict) -> None:
        self.execute("INSERT OR REPLACE INTO episodic_memory VALUES (?,?,?,?,?,?,?,?)",
                     (rec["id"], rec["service"], rec["root_cause"], rec["summary"], rec.get("resolution", ""),
                      rec.get("signature", ""), rec.get("source", "investigation"), time.time()))

    def memories(self) -> list[dict]:
        return self.query("SELECT * FROM episodic_memory ORDER BY created_at DESC")

    # -- evaluations ---------------------------------------------------------------------
    def save_evaluation(self, eval_id: str, config: dict, summary: dict, cases: list[dict]) -> None:
        self.execute("INSERT OR REPLACE INTO evaluations VALUES (?,?,?,?,?)",
                     (eval_id, time.time(), json.dumps(config), json.dumps(summary, default=str),
                      json.dumps(cases, default=str)))

    def latest_evaluation(self) -> dict | None:
        rows = self.query("SELECT * FROM evaluations ORDER BY created_at DESC LIMIT 1")
        if not rows:
            return None
        r = rows[0]
        return {"id": r["id"], "created_at": r["created_at"], "config": json.loads(r["config"]),
                "summary": json.loads(r["summary"]), "cases": json.loads(r["cases"])}

    # -- dashboard aggregates -----------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        inv = self.query("SELECT status, COUNT(*) n FROM investigations GROUP BY status")
        per_agent = self.query(
            "SELECT agent, COUNT(*) n, AVG((end-start)*1000) avg_ms FROM spans "
            "WHERE kind='agent' AND end IS NOT NULL GROUP BY agent ORDER BY agent")
        llm = self.query("SELECT COUNT(*) calls, COALESCE(SUM(input_tokens),0) inp, "
                         "COALESCE(SUM(output_tokens),0) outp, COALESCE(SUM(cost_usd),0) cost, "
                         "COALESCE(SUM(baseline_cost_usd),0) base, MAX(estimated) est FROM llm_calls")[0]
        tools = self.query("SELECT COUNT(*) n, COALESCE(SUM(denied),0) denied, "
                           "COALESCE(SUM(redactions),0) red, COALESCE(SUM(injections),0) inj FROM tool_calls")[0]
        durations = self.query("SELECT AVG(updated_at-created_at) d FROM investigations "
                               "WHERE status IN ('completed','awaiting_approval')")[0]
        approvals = self.query("SELECT status, COUNT(*) n FROM approvals GROUP BY status")
        return {"investigations": {r["status"]: r["n"] for r in inv}, "per_agent": per_agent, "llm": llm,
                "tools": tools, "avg_duration_s": durations["d"],
                "approvals": {r["status"]: r["n"] for r in approvals}}


_store: Store | None = None


def get_store() -> Store:
    global _store
    if _store is None:
        from aegis.config import get_settings
        _store = Store(get_settings().db_path)
    return _store


def set_store(store: Store | None) -> None:
    global _store
    _store = store
