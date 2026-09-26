"""LangGraph state = the investigation's short-term memory (checkpointed after every step)."""
from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


def merge_evidence(left: list[dict] | None, right: list[dict] | None) -> list[dict]:
    seen = {e["id"] for e in (left or [])}
    out = list(left or [])
    for e in right or []:
        if e["id"] not in seen:
            out.append(e)
            seen.add(e["id"])
    return out


def merge_steps(left: list[dict] | None, right: list[dict] | None) -> list[dict]:
    """Plan steps keyed by id; later updates (status) win."""
    by_id = {s["id"]: s for s in (left or [])}
    order = [s["id"] for s in (left or [])]
    for s in right or []:
        if s["id"] not in by_id:
            order.append(s["id"])
        by_id[s["id"]] = {**by_id.get(s["id"], {}), **s}
    return [by_id[i] for i in order]


class InvestigationState(TypedDict, total=False):
    run_id: str
    workspace: str
    incident_id: str
    request: str
    reported_at: str
    brief: dict
    onset: str
    wave: int
    plan: Annotated[list[dict], merge_steps]
    plan_rationale: Annotated[list[str], operator.add]
    evidence: Annotated[list[dict], merge_evidence]
    results: Annotated[list[dict], operator.add]
    priors: dict
    hypotheses: list[dict]
    margin: float
    rejected: list[str]
    verification: dict
    verifications: Annotated[list[dict], operator.add]
    replans: int
    reflections: int
    fix: dict
    fix_verification: dict
    approval: dict
    applied: dict
    report: dict
    status: str
    auto_approve: bool
    options: dict[str, Any]
