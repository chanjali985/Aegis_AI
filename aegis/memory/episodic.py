"""Episodic memory: what happened in previous incidents and how they were resolved.

Three memory tiers in AegisAI:
* short-term  - the LangGraph state of the running investigation (checkpointed to SQLite)
* episodic    - this module: past incidents (imported postmortems + finished investigations)
* semantic    - ``aegis.memory.semantic``: failure patterns and how to recognise them
"""
from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path

from aegis.rag.ingestion import tokenize
from aegis.storage.db import Store


class EpisodicMemory:
    def __init__(self, store: Store):
        self.store = store

    def import_history(self, workspace: str | Path) -> int:
        path = Path(workspace) / "docs" / "_history.json"
        if not path.exists():
            return 0
        n = 0
        for rec in json.loads(path.read_text()):
            self.store.add_memory({"id": rec["incident_id"], "service": rec["service"], "root_cause": rec["root_cause"],
                                   "summary": rec["summary"], "resolution": rec["resolution"],
                                   "signature": "", "source": "postmortem"})
            n += 1
        return n

    def remember(self, rec: dict) -> None:
        self.store.add_memory(rec)

    def recall(self, query: str, service: str | None, k: int = 3) -> list[dict]:
        memories = self.store.memories()
        if not memories:
            return []
        q = Counter(tokenize(query))
        scored = []
        for m in memories:
            doc = Counter(tokenize(" ".join([m["service"], m["root_cause"].replace("_", " "), m["summary"],
                                             m["signature"] or ""])))
            dot = sum(q[t] * doc[t] for t in q)
            norm = math.sqrt(sum(v * v for v in q.values())) * math.sqrt(sum(v * v for v in doc.values()))
            sim = dot / norm if norm else 0.0
            if service and m["service"] == service:
                sim += 0.15
            scored.append((sim, m))
        scored.sort(key=lambda x: -x[0])
        return [{**m, "similarity": round(s, 3)} for s, m in scored[:k] if s > 0.1]

    def priors(self, service: str | None) -> dict[str, int]:
        counts: Counter = Counter()
        for m in self.store.memories():
            if not service or m["service"] == service:
                counts[m["root_cause"]] += 1
        return dict(counts)
