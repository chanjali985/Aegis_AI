"""Database agent: agentic text-to-SQL over the production read replica.

Pipeline per question:  schema discovery -> SQL generation (LLM, or a vetted
template offline) -> static validation -> read-only execution -> on error,
feed the error back and retry -> result verification -> interpretation into
typed evidence.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from aegis.agents.base import Agent
from aegis.agents.models import AgentResult, AgentTask
from aegis.llm.router import get_llm
from aegis.security.sql_guard import validate_sql
from aegis.tools.gateway import ToolGateway
from aegis.util import minutes_between, shift

QUESTIONS = {
    "recent_deployments": "Which deployments of {service} happened in the 24 hours before {onset}?",
    "flag_changes": "Which feature flags changed between {start6h} and {onset_plus}?",
    "dependency_status": "Which upstream dependencies{dep_text} reported a non-operational status since {start2h}?",
    "certificates": "When do the certificates used by {service} expire?",
    "query_stats": "How did hourly query latency for {service} change around {onset}?",
    "pool_stats": "How did connection pool usage for {service} change around {onset}?",
}

TEMPLATES = {
    "recent_deployments": "SELECT service, version, commit_sha, deployed_at FROM deployments "
                          "WHERE service = '{service}' AND deployed_at BETWEEN '{start24h}' AND '{onset_plus}' "
                          "ORDER BY deployed_at",
    "flag_changes": "SELECT flag, service, old_value, new_value, changed_at, changed_by, reason "
                    "FROM feature_flag_audit WHERE changed_at BETWEEN '{start6h}' AND '{onset_plus}' "
                    "ORDER BY changed_at",
    "dependency_status": "SELECT dependency, MIN(checked_at) AS first_bad_at, MAX(checked_at) AS last_bad_at, "
                         "status, COUNT(*) AS checks, MAX(detail) AS detail FROM dependency_status "
                         "WHERE {dep_filter} status != 'OPERATIONAL' AND checked_at >= '{start2h}' "
                         "GROUP BY dependency, status",
    "certificates": "SELECT service, host, expires_at FROM certificates WHERE service = '{service}'",
    "query_stats": "SELECT fingerprint, hour, calls, mean_ms, p95_ms FROM query_stats "
                   "WHERE service = '{service}' AND hour BETWEEN '{start3h}' AND '{onset_plus2h}' ORDER BY hour",
    "pool_stats": "SELECT ts, pool_size, active, waiting FROM db_pool_stats WHERE service = '{service}' "
                  "AND ts BETWEEN '{start1h}' AND '{onset_plus1h}' ORDER BY ts",
}


class SQLDraft(BaseModel):
    tables: list[str] = Field(description="tables needed")
    sql: str = Field(description="a single SQLite SELECT statement")


class DatabaseAgent(Agent):
    name = "database"
    title = "Database Agent"
    description = "Answers questions from the production read replica with validated, read-only SQL."
    skills = [
        {"id": "text-to-sql", "name": "Agentic text-to-SQL",
         "description": "Schema discovery, SQL generation, validation, read-only execution and retry.",
         "tags": ["sql", "database", "deployments", "feature-flags", "dependencies", "certificates",
                  "query-stats", "connection-pool"]},
    ]

    async def execute(self, task: AgentTask, gw: ToolGateway) -> AgentResult:
        p = task.params
        service = p.get("service") or task.incident.service
        onset = p.get("onset") or task.incident.reported_at
        slots = {"service": service, "onset": onset, "upstream": p.get("upstream", ""),
                 "start24h": shift(onset, -1440), "start6h": shift(onset, -360), "start3h": shift(onset, -180),
                 "start2h": shift(onset, -120), "start1h": shift(onset, -60), "onset_plus": shift(onset, 15),
                 "onset_plus1h": shift(onset, 60), "onset_plus2h": shift(onset, 120)}
        up = slots["upstream"]
        slots["dep_filter"] = f"dependency = '{up}' AND" if up else ""
        slots["dep_text"] = f" ({up})" if up else ""
        schema = await gw.call("database.get_schema")
        tables = schema["tables"]
        evidence, notes, sql_log = [], [], []
        llm = get_llm()
        for intent in p.get("questions", ["recent_deployments"]):
            if intent not in TEMPLATES:
                continue
            question = QUESTIONS[intent].format(**slots)
            template = TEMPLATES[intent].format(**slots)
            rows, attempts = None, []
            for attempt in range(3):
                if attempt < 2:
                    schema_txt = "\n".join(f"{t}({', '.join(c['name'] for c in v['columns'])})"
                                           for t, v in tables.items())
                    feedback = f"\nPrevious attempt failed: {attempts[-1]['errors']}" if attempts else ""
                    draft, source = await llm.structured(
                        task="sql", signals={"retry": attempt},
                        system="You write SQLite SELECT queries for incident investigation. Timestamps are "
                               "ISO-8601 strings like 2026-09-25T09:50:00Z.",
                        prompt=f"Schema:\n{schema_txt}\n\nQuestion: {question}{feedback}",
                        schema=SQLDraft, fallback=lambda: SQLDraft(tables=[], sql=template))
                    sql = draft.sql
                    source = "llm" if source == "llm" else "template"
                else:
                    sql, source = template, "template"
                check = validate_sql(sql, set(tables))
                if not check.ok:
                    attempts.append({"sql": sql, "source": source, "errors": check.errors})
                    continue
                res = await gw.call("database.execute_readonly_sql", sql=sql)
                if not res["ok"]:
                    attempts.append({"sql": sql, "source": source, "errors": res["errors"]})
                    continue
                attempts.append({"sql": res["sql"], "source": source, "errors": [], "rows": res["row_count"]})
                rows = res["rows"]
                break
            sql_log.append({"intent": intent, "question": question, "attempts": attempts,
                            "gold_sql": template, "ok": rows is not None})
            if rows is None:
                notes.append(f"could not answer '{intent}' after {len(attempts)} attempts")
                continue
            evidence.extend(self._interpret(task, intent, rows, slots, attempts[-1]["sql"]))
        summary = f"{len(sql_log)} questions answered with SQL, {len(evidence)} findings"
        return AgentResult(task_id=task.task_id, agent=self.name, summary=summary, evidence=evidence,
                           notes=notes, data={"sql": sql_log})

    def _interpret(self, task, intent, rows, slots, sql):
        src = {"tool": "database.execute_readonly_sql", "args": {"sql": sql}}
        onset = slots["onset"]
        out = []
        if intent == "recent_deployments":
            for r in rows:
                out.append(self.evidence(task, "deploy_record",
                                         f"deployments table: {r['service']} v{r['version']} at {r['deployed_at']}",
                                         {**r, "minutes_before_onset": round(minutes_between(r["deployed_at"], onset), 1)},
                                         src, r["deployed_at"]))
        elif intent == "flag_changes":
            for r in rows:
                mins = round(minutes_between(r["changed_at"], onset), 1)
                out.append(self.evidence(
                    task, "flag_change",
                    f"flag {r['flag']} ({r['service']}) {r['old_value']}->{r['new_value']} at {r['changed_at']} "
                    f"by {r['changed_by']} ({mins:.0f} min before onset)",
                    {**r, "minutes_before_onset": mins}, src, r["changed_at"]))
            if not rows:
                out.append(self.evidence(task, "no_flag_change", "No feature flag changes near the onset",
                                         {"window": [slots["start6h"], slots["onset_plus"]]}, src))
        elif intent == "dependency_status":
            bad = [r for r in rows if r.get("status") != "OPERATIONAL"]
            if bad:
                r = min(bad, key=lambda r: r["first_bad_at"])
                mins = round(minutes_between(r["first_bad_at"], onset), 1)
                out.append(self.evidence(
                    task, "dependency_status",
                    f"{r['dependency']} reported {r['status']} from {r['first_bad_at']} ({r['checks']} checks): "
                    f"{r['detail']}", {**r, "minutes_before_onset": mins, "healthy": False}, src, r["first_bad_at"]))
            elif slots["upstream"]:
                out.append(self.evidence(
                    task, "dependency_status", f"{slots['upstream']} reported OPERATIONAL throughout",
                    {"dependency": slots["upstream"], "healthy": True}, src))
        elif intent == "certificates":
            for r in rows:
                mins = round(minutes_between(r["expires_at"], onset), 1)
                expired = mins >= -5  # tolerate clock skew between systems
                out.append(self.evidence(
                    task, "certificate",
                    f"certificate for {r['host']} expires {r['expires_at']} "
                    f"({'EXPIRED ' + str(abs(int(mins))) + ' min before onset' if expired else 'valid'})",
                    {**r, "minutes_before_onset": mins, "expired_at_onset": expired}, src, r["expires_at"]))
        elif intent == "query_stats":
            by_fp: dict[str, list] = {}
            for r in rows:
                by_fp.setdefault(r["fingerprint"], []).append(r)
            for fp, rs in by_fp.items():
                before = [r["mean_ms"] for r in rs if r["hour"] < onset[:13] + ":00:00Z"]
                after = [r["mean_ms"] for r in rs if r["hour"] > onset[:13] + ":00:00Z"]
                if not before or not after:
                    continue
                b, a = sum(before) / len(before), sum(after) / len(after)
                out.append(self.evidence(
                    task, "query_regression" if a > 2 * b else "query_stable",
                    f"query '{fp[:60]}' mean latency {b:.0f}ms -> {a:.0f}ms",
                    {"fingerprint": fp, "before_mean_ms": round(b, 1), "after_mean_ms": round(a, 1),
                     "factor": round(a / b, 2) if b else None}, src))
        elif intent == "pool_stats":
            before = [r for r in rows if r["ts"] < onset]
            after = [r for r in rows if r["ts"] >= onset]
            if before and after:
                bw = sum(r["waiting"] for r in before) / len(before)
                aw = sum(r["waiting"] for r in after) / len(after)
                aa = sum(r["active"] for r in after) / len(after)
                pool = after[-1]["pool_size"]
                saturated = aw > max(1.0, 3 * bw) and aa >= 0.8 * pool
                out.append(self.evidence(
                    task, "pool_saturation" if saturated else "pool_normal",
                    f"db pool (size {pool}): waiting {bw:.1f} -> {aw:.1f}, active {aa:.1f}",
                    {"pool_size": pool, "before_waiting": round(bw, 2), "after_waiting": round(aw, 2),
                     "after_active": round(aa, 2), "saturated": saturated}, src))
        return out
