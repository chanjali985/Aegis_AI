"""Observability agent: error spikes, signature parsing, metric shifts, telemetry gaps."""
from __future__ import annotations

import re
from collections import Counter

from aegis.agents.base import Agent
from aegis.agents.models import AgentResult, AgentTask
from aegis.tools.gateway import ToolGateway
from aegis.util import shift

PARSERS = {
    "timeout_ms": re.compile(r"exceeded (\d+)ms timeout"),
    "pool_size": re.compile(r"pool_size=(\d+)"),
    "rate_limit": re.compile(r"limit=(\d+) rps"),
    "attempts": re.compile(r"attempt (\d+)/(\d+)"),
    "host": re.compile(r"host=([\w.\-]+)"),
    "missing_field": re.compile(r"KeyError: '(\w+)'"),
    "upstream": re.compile(r"^\w+: ([\w\-]+) (?:returned|did not respond)"),
    "memory_limit": re.compile(r"memory limit exceeded \((\d+)Mi\)"),
}

METRICS = ["error_rate_5xx", "rate_429", "latency_p95_ms", "db_latency_p95_ms", "db_pool_waiting",
           "memory_mb", "upstream_rps", "upstream_latency_p95_ms", "upstream_error_rate", "http_rps"]
# (relative change %, absolute change) needed to call a metric "shifted"
SHIFT_THRESHOLDS = {"error_rate_5xx": (50, 0.01), "rate_429": (50, 0.01), "db_pool_waiting": (50, 0.5),
                    "upstream_error_rate": (50, 0.02)}


def parse_signature(message: str) -> dict:
    out = {}
    for key, rx in PARSERS.items():
        if m := rx.search(message or ""):
            out[key] = m.group(1) if key != "attempts" else int(m.group(1))
    for k in ("timeout_ms", "pool_size", "rate_limit", "memory_limit"):
        if k in out:
            out[k] = int(out[k])
    return out


class ObservabilityAgent(Agent):
    name = "observability"
    title = "Log/Observability Agent"
    description = "Finds error spikes, parses failure signatures and compares service metrics around the onset."
    skills = [
        {"id": "error-spike-analysis", "name": "Error spike analysis",
         "description": "Poisson change-point detection per error type; extracts stack traces and parameters.",
         "tags": ["logs", "errors", "onset", "stack-trace"]},
        {"id": "metric-comparison", "name": "Metric comparison",
         "description": "Before/after comparison of latency, saturation, memory and dependency metrics.",
         "tags": ["metrics", "latency", "saturation", "memory"]},
    ]

    async def execute(self, task: AgentTask, gw: ToolGateway) -> AgentResult:
        service = task.params.get("service") or task.incident.service
        evidence, notes = [], []
        spikes_resp = await gw.call("observability.find_error_spikes", service=service)
        src = {"tool": "observability.find_error_spikes", "args": {"service": service}}
        for gap in spikes_resp["telemetry_gaps"]:
            evidence.append(self.evidence(task, "telemetry_gap",
                                          f"Log gap for {service} from {gap['from']}: {gap['message'][:90]}",
                                          {"service": service, "from": gap["from"]}, src, gap["from"]))
            notes.append("logs missing for part of the window")

        # keep spikes that are statistically strong and not pre-existing noise
        spikes = [s for s in spikes_resp["spikes"] if s["llr"] >= 8 and s["factor"] >= 3]
        onset = None
        for s in spikes[:4]:
            detail = parse_signature(s["sample"])
            lines = await gw.call("observability.search_logs", service=service, error_type=s["error_type"],
                                  start=s["onset"], limit=200)
            versions = Counter(l.get("version") for l in lines["lines"] if l.get("version"))
            stack = s.get("stack") or []
            frame = stack[-1] if stack else None
            feature = next((f["file"] for f in stack if "/features/" in f["file"]), None)
            data = {"service": service, "error_type": s["error_type"], "onset": s["onset"],
                    "factor": s["factor"], "rate_before_per_hour": s["rate_before_per_hour"],
                    "rate_after_per_hour": s["rate_after_per_hour"], "count_after": s["count_after"],
                    "llr": s["llr"], "sample": s["sample"], "stack": stack, "frame": frame,
                    "feature_path": feature, "versions": dict(versions), **detail}
            summary = (f"{s['error_type']} on {service} rose {s['factor']}x at {s['onset']} "
                       f"({s['rate_before_per_hour']}/h -> {s['rate_after_per_hour']}/h); "
                       f"sample: {s['sample'][:110]}")
            evidence.append(self.evidence(task, "error_spike", summary, data, src, s["onset"]))
            onset = s["onset"] if onset is None or s["onset"] < onset else onset

        if onset is None:
            # no usable logs: locate the onset from the error-rate metrics instead
            onset = await self._metric_onset(task, gw, service, evidence)
        if onset is None:
            return AgentResult(task_id=task.task_id, agent=self.name, status="no_data",
                               summary=f"No error spike or metric anomaly found for {service}",
                               evidence=evidence, notes=notes)

        for metric in task.params.get("metrics", METRICS):
            cmp_ = await gw.call("observability.compare_time_windows", service=service, metric=metric,
                                 split_at=onset, window_minutes=60)
            b, a = cmp_["before"]["mean"], cmp_["after"]["mean"]
            rel_min, abs_min = SHIFT_THRESHOLDS.get(metric, (25, 0.0))
            change = cmp_["change_pct"]
            direction = "flat"
            if abs(change) >= rel_min and abs(a - b) >= abs_min:
                direction = "up" if a > b else "down"
            evidence.append(self.evidence(
                task, "metric_shift", f"{metric} {direction}: {b} -> {a} ({change:+.0f}%) around {onset}",
                {"service": service, "metric": metric, "before_mean": b, "after_mean": a,
                 "before_p95": cmp_["before"]["p95"], "after_p95": cmp_["after"]["p95"],
                 "change_pct": change, "direction": direction, "split_at": onset},
                {"tool": "observability.compare_time_windows", "args": {"metric": metric, "split_at": onset}},
                onset))
        shifts = {e.data["metric"]: e.data for e in evidence if e.kind == "metric_shift"}
        if "upstream_rps" in shifts and "http_rps" in shifts and shifts["http_rps"]["after_mean"]:
            before = shifts["upstream_rps"]["before_mean"] / max(shifts["http_rps"]["before_mean"], 1e-9)
            after = shifts["upstream_rps"]["after_mean"] / max(shifts["http_rps"]["after_mean"], 1e-9)
            evidence.append(self.evidence(
                task, "metric_shift", f"upstream amplification (upstream_rps / http_rps): {before:.2f} -> {after:.2f}",
                {"service": service, "metric": "upstream_amplification", "before_mean": round(before, 2),
                 "after_mean": round(after, 2), "change_pct": round((after - before) / before * 100, 1),
                 "direction": "up" if after > before * 1.3 else "flat", "split_at": onset},
                {"tool": "derived", "args": {}}, onset))
        restarts = await gw.call("observability.get_service_metrics", service=service, metric="restarts",
                                 start=shift(onset, -60))
        if restarts["max"] > restarts["min"]:
            mem = await gw.call("observability.get_service_metrics", service=service, metric="memory_mb",
                                start=shift(onset, -180))
            evidence.append(self.evidence(
                task, "memory_sawtooth",
                f"{int(restarts['max'] - restarts['min'])} OOM restarts; memory peaked at {mem['max']:.0f}MB",
                {"service": service, "restarts": restarts["max"] - restarts["min"], "max_memory_mb": mem["max"]},
                {"tool": "observability.get_service_metrics", "args": {"metric": "restarts"}}, onset))

        top = next((e for e in evidence if e.kind == "error_spike"), None)
        summary = (f"Onset {onset}; " + (f"dominant signature {top.data['error_type']} ({top.data['factor']}x)"
                                         if top else "onset from metrics (logs unavailable)"))
        return AgentResult(task_id=task.task_id, agent=self.name, summary=summary, evidence=evidence,
                           notes=notes, data={"onset": onset, "service": service,
                                              "signatures": [e.data["error_type"] for e in evidence
                                                             if e.kind == "error_spike"]})

    async def _metric_onset(self, task, gw, service, evidence) -> str | None:
        """Locate the onset from metrics when logs are unavailable (mean-shift change point)."""
        best = None
        for metric in ("error_rate_5xx", "rate_429", "latency_p95_ms"):
            series = await gw.call("observability.get_service_metrics", service=service, metric=metric,
                                   step_minutes=5)
            pts = series["points"]
            cp = mean_shift([v for _, v in pts])
            if not cp:
                continue
            idx, before, after, strength = cp
            floor = 0.01 if metric != "latency_p95_ms" else 200
            if after < 2 * before or after - before < floor:
                continue
            if best is None or strength > best[4]:
                best = (metric, pts[idx][0], before, after, strength)
        if not best:
            return None
        metric, coarse, b, a, _ = best
        # refine to the first minute that crosses the midpoint between the two regimes
        fine = await gw.call("observability.get_service_metrics", service=service, metric=metric,
                             start=shift(coarse, -10), end=shift(coarse, 15), step_minutes=1)
        onset = next((t for t, v in fine["points"] if v > (a + b) / 2), coarse)
        evidence.append(self.evidence(
            task, "metric_anomaly", f"{metric} stepped up at {onset} ({b:.3f} -> {a:.3f}); logs unavailable",
            {"service": service, "metric": metric, "onset": onset, "before": round(b, 4), "after": round(a, 4),
             "onset_uncertainty_min": 5},
            {"tool": "observability.get_service_metrics", "args": {"metric": metric}}, onset))
        return onset


def mean_shift(values: list[float], min_seg: int = 6) -> tuple[int, float, float, float] | None:
    """Single upward mean-shift change point by maximal between-segment variance reduction."""
    n = len(values)
    if n < 2 * min_seg:
        return None
    prefix = [0.0]
    for v in values:
        prefix.append(prefix[-1] + v)
    total_var = sum((v - prefix[-1] / n) ** 2 for v in values) or 1e-12
    best = None
    for s in range(min_seg, n - 2):
        m1 = prefix[s] / s
        m2 = (prefix[-1] - prefix[s]) / (n - s)
        if m2 <= m1:
            continue
        gain = s * (n - s) / n * (m2 - m1) ** 2 / total_var
        if best is None or gain > best[3]:
            best = (s, m1, m2, gain)
    return best
