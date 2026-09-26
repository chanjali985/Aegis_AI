"""Minimal Prometheus-compatible metrics registry (text exposition format)."""
from __future__ import annotations

import threading
from collections import defaultdict


def _labels(labels: dict) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


class Counter:
    def __init__(self, name: str, help_: str):
        self.name, self.help = name, help_
        self._values: dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def inc(self, amount: float = 1.0, **labels) -> None:
        with self._lock:
            self._values[tuple(sorted(labels.items()))] += amount

    def render(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        for key, v in self._values.items():
            out.append(f"{self.name}{_labels(dict(key))} {v}")
        return out


class Histogram:
    BUCKETS = (0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)

    def __init__(self, name: str, help_: str):
        self.name, self.help = name, help_
        self._counts: dict[tuple, list[int]] = {}
        self._sum: dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def observe(self, value: float, **labels) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            counts = self._counts.setdefault(key, [0] * (len(self.BUCKETS) + 1))
            for i, b in enumerate(self.BUCKETS):
                if value <= b:
                    counts[i] += 1
            counts[-1] += 1
            self._sum[key] += value

    def render(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        for key, counts in self._counts.items():
            labels = dict(key)
            for b, c in zip(self.BUCKETS, counts):
                out.append(f"{self.name}_bucket{_labels({**labels, 'le': b})} {c}")
            out.append(f"{self.name}_bucket{_labels({**labels, 'le': '+Inf'})} {counts[-1]}")
            out.append(f"{self.name}_sum{_labels(labels)} {self._sum[key]}")
            out.append(f"{self.name}_count{_labels(labels)} {counts[-1]}")
        return out


AGENT_RUNS = Counter("aegis_agent_runs_total", "Agent task executions")
AGENT_LATENCY = Histogram("aegis_agent_latency_seconds", "Agent task latency")
TOOL_CALLS = Counter("aegis_tool_calls_total", "MCP tool calls by outcome")
TOOL_LATENCY = Histogram("aegis_tool_latency_seconds", "MCP tool call latency")
LLM_TOKENS = Counter("aegis_llm_tokens_total", "LLM tokens by model and direction")
LLM_COST = Counter("aegis_llm_cost_usd_total", "Estimated LLM spend in USD")
SECURITY_EVENTS = Counter("aegis_security_events_total", "Guardrail interventions")
INVESTIGATIONS = Counter("aegis_investigations_total", "Investigations by final status")

REGISTRY = [AGENT_RUNS, AGENT_LATENCY, TOOL_CALLS, TOOL_LATENCY, LLM_TOKENS, LLM_COST,
            SECURITY_EVENTS, INVESTIGATIONS]


def render_all() -> str:
    lines: list[str] = []
    for m in REGISTRY:
        lines += m.render()
    return "\n".join(lines) + "\n"
