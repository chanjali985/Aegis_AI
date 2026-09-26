"""Observability MCP server: logs, metrics, traces and change-point detection.

Run standalone:  python -m aegis.mcp_servers.observability_server --workspace <ws>
"""
from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from mcp.server.fastmcp import FastMCP

FMT = "%Y-%m-%dT%H:%M:%SZ"


def _dt(s: str) -> datetime:
    return datetime.strptime(s, FMT).replace(tzinfo=timezone.utc)


def _iso(d: datetime) -> str:
    return d.strftime(FMT)


def _load(tdir: str) -> tuple[list[dict], dict, list[dict]]:
    stamp = (Path(tdir) / "logs.jsonl").stat().st_mtime_ns
    return _load_cached(tdir, stamp)


@lru_cache(maxsize=8)
def _load_cached(tdir: str, _stamp: int) -> tuple[list[dict], dict, list[dict]]:
    p = Path(tdir)
    logs = [json.loads(l) for l in (p / "logs.jsonl").read_text().splitlines() if l.strip()]
    metrics = json.loads((p / "metrics.json").read_text())
    traces = [json.loads(l) for l in (p / "traces.jsonl").read_text().splitlines() if l.strip()]
    return logs, metrics, traces


def detect_change_point(counts: list[int]) -> tuple[int, float, float, float] | None:
    """Best single upward change point in a Poisson count series.

    Returns ``(index, rate_before, rate_after, log_likelihood_ratio)``.
    """
    n = len(counts)
    total = sum(counts)
    if n < 8 or total == 0:
        return None
    lam0 = total / n
    base = total * math.log(lam0) - lam0 * n
    best = None
    prefix = [0]
    for c in counts:
        prefix.append(prefix[-1] + c)
    for s in range(6, n - 2):
        c1, n1 = prefix[s], s
        c2, n2 = total - c1, n - s
        l1, l2 = c1 / n1, c2 / n2
        if l2 <= l1:
            continue
        ll = (c1 * math.log(l1) if c1 else 0) - l1 * n1 + (c2 * math.log(l2) if c2 else 0) - l2 * n2
        llr = ll - base
        if best is None or llr > best[3]:
            best = (s, l1, l2, llr)
    return best


def build_server(workspace: str | Path) -> FastMCP:
    tdir = str(Path(workspace) / "telemetry")
    mcp = FastMCP("observability", instructions="Logs, metrics and traces for ACME services (last 24h).")

    def logs() -> list[dict]:
        return _load(tdir)[0]

    def window_bounds() -> tuple[datetime, datetime]:
        series = next(iter(_load(tdir)[1].values()))["http_rps"]
        return _dt(series[0][0]), _dt(series[-1][0]) + timedelta(minutes=1)

    @mcp.tool()
    def list_services() -> dict:
        """Services with telemetry and the covered time window."""
        start, end = window_bounds()
        return {"services": sorted(_load(tdir)[1].keys()), "window_start": _iso(start), "window_end": _iso(end),
                "metrics": sorted(next(iter(_load(tdir)[1].values())).keys())}

    @mcp.tool()
    def search_logs(query: str = "", service: str | None = None, level: str | None = None,
                    start: str | None = None, end: str | None = None, error_type: str | None = None,
                    limit: int = 20) -> dict:
        """Full-text log search. Returns matching lines (newest last) and the total match count."""
        rx = re.compile(re.escape(query), re.I) if query else None
        hits = []
        for l in logs():
            if service and l["service"] != service:
                continue
            if level and l["level"] != level.upper():
                continue
            if error_type and l.get("error_type") != error_type:
                continue
            if start and l["ts"] < start:
                continue
            if end and l["ts"] > end:
                continue
            if rx and not rx.search(l.get("message", "")):
                continue
            hits.append(l)
        return {"total": len(hits), "lines": hits[-limit:] if limit else []}

    @mcp.tool()
    def aggregate_errors(service: str, start: str | None = None, end: str | None = None,
                         bucket_minutes: int = 60) -> dict:
        """Error/warning counts per error type per time bucket."""
        buckets: dict[str, Counter] = defaultdict(Counter)
        for l in logs():
            if l["service"] != service or not l.get("error_type"):
                continue
            if (start and l["ts"] < start) or (end and l["ts"] > end):
                continue
            t = _dt(l["ts"])
            b = t - timedelta(minutes=t.minute % bucket_minutes, seconds=t.second)
            buckets[_iso(b)][l["error_type"]] += 1
        return {"service": service, "bucket_minutes": bucket_minutes,
                "buckets": [{"start": k, "counts": dict(v)} for k, v in sorted(buckets.items())]}

    @mcp.tool()
    def find_error_spikes(service: str, bucket_minutes: int = 5, min_factor: float = 3.0,
                          min_count: int = 5) -> dict:
        """Detect error types whose rate stepped up (Poisson change-point detection).

        Also reports telemetry gaps (log shipping failures) that would hide errors.
        """
        start, end = window_bounds()
        n = int((end - start).total_seconds() // (bucket_minutes * 60))
        series: dict[str, list[int]] = defaultdict(lambda: [0] * n)
        stamps: dict[str, list[str]] = defaultdict(list)
        samples: dict[str, dict] = {}
        coverage = [0] * n
        gaps = []
        for l in logs():
            if l["service"] == "fluent-bit" and service in l.get("message", ""):
                gaps.append({"from": l["ts"], "message": l["message"]})
            if l["service"] != service:
                continue
            idx = int((_dt(l["ts"]) - start).total_seconds() // (bucket_minutes * 60))
            if not 0 <= idx < n:
                continue
            coverage[idx] += 1
            et = l.get("error_type")
            if et and l["level"] in ("ERROR", "WARN"):
                series[et][idx] += 1
                stamps[et].append(l["ts"])
                samples.setdefault(et, l)
        spikes = []
        for et, counts in series.items():
            cp = detect_change_point(counts)
            if not cp:
                continue
            s, before, after, llr = cp
            factor = (after + 0.02) / (before + 0.02)
            count_after = sum(counts[s:])
            if factor >= min_factor and count_after >= min_count:
                # refine the bucketed change point to the first error inside the changed regime
                bucket_start = _iso(start + timedelta(minutes=s * bucket_minutes))
                first = next((t for t in sorted(stamps[et]) if t >= bucket_start), bucket_start)
                after_samples = [l for l in logs() if l["service"] == service and l.get("error_type") == et
                                 and l["ts"] >= first]
                if after_samples:
                    samples[et] = after_samples[0]
                spikes.append({
                    "error_type": et, "onset": first, "bucket_start": bucket_start,
                    "rate_before_per_hour": round(before * 60 / bucket_minutes, 2),
                    "rate_after_per_hour": round(after * 60 / bucket_minutes, 2),
                    "factor": round(factor, 1), "count_after": count_after, "llr": round(llr, 1),
                    "sample": samples[et].get("message"), "stack": samples[et].get("stack")})
        spikes.sort(key=lambda s: -s["llr"])
        # silent periods: consecutive empty buckets in the most recent part of the window
        empty_run, silent_from = 0, None
        for i, c in enumerate(coverage):
            if c == 0:
                empty_run += 1
                if empty_run == 4:
                    silent_from = _iso(start + timedelta(minutes=(i - 3) * bucket_minutes))
            else:
                empty_run = 0
        if silent_from and not gaps and empty_run >= 4:
            gaps.append({"from": silent_from, "message": "no log lines received from service"})
        return {"service": service, "spikes": spikes, "telemetry_gaps": gaps}

    @mcp.tool()
    def get_service_metrics(service: str, metric: str, start: str | None = None, end: str | None = None,
                            step_minutes: int = 15) -> dict:
        """Metric time series (downsampled by averaging) plus min/max/mean."""
        series = _load(tdir)[1].get(service, {}).get(metric)
        if series is None:
            raise ValueError(f"unknown service/metric {service}/{metric}")
        pts = [(t, v) for t, v in series if (not start or t >= start) and (not end or t <= end)]
        out = [[pts[i][0], round(sum(v for _, v in pts[i:i + step_minutes]) / len(pts[i:i + step_minutes]), 3)]
               for i in range(0, len(pts), step_minutes)]
        vals = [v for _, v in pts] or [0]
        return {"service": service, "metric": metric, "points": out, "min": min(vals), "max": max(vals),
                "mean": round(sum(vals) / len(vals), 3)}

    @mcp.tool()
    def compare_time_windows(service: str, metric: str, split_at: str, window_minutes: int = 60) -> dict:
        """Compare a metric in the window before vs after `split_at` (mean, p95, change %)."""
        series = _load(tdir)[1][service][metric]
        t = _dt(split_at)
        lo, hi = _iso(t - timedelta(minutes=window_minutes)), _iso(t + timedelta(minutes=window_minutes))
        before = sorted(v for ts, v in series if lo <= ts < split_at)
        after = sorted(v for ts, v in series if split_at <= ts < hi)

        def stats(v):
            if not v:
                return {"mean": 0.0, "p95": 0.0, "max": 0.0}
            return {"mean": round(sum(v) / len(v), 3), "p95": v[int(0.95 * (len(v) - 1))], "max": v[-1]}

        b, a = stats(before), stats(after)
        change = (a["mean"] - b["mean"]) / b["mean"] * 100 if b["mean"] else (100.0 if a["mean"] else 0.0)
        return {"service": service, "metric": metric, "split_at": split_at, "before": b, "after": a,
                "change_pct": round(change, 1)}

    @mcp.tool()
    def get_request_trace(trace_id: str) -> dict:
        """Full recorded trace (inputs and outcome) for one sampled request."""
        for t in _load(tdir)[2]:
            if t["id"] == trace_id:
                return t
        raise ValueError("trace not found")

    @mcp.tool()
    def export_traffic_sample(service: str, start: str, end: str, limit: int = 1500) -> dict:
        """Export sampled request inputs in a window, for replay-based reproduction tests."""
        keep = ("id", "ts", "service", "endpoint", "rps", "payload", "concurrent_db", "db_ms_base",
                "db_rows_scanned", "calls_upstream", "upstream_status", "upstream_ms_base", "flags")
        rows = [{k: t[k] for k in keep} for t in _load(tdir)[2]
                if t["service"] == service and start <= t["ts"] <= end]
        return {"service": service, "start": start, "end": end, "count": len(rows[:limit]),
                "traffic": rows[:limit]}

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    build_server(ap.parse_args().workspace).run("stdio")


if __name__ == "__main__":
    main()
