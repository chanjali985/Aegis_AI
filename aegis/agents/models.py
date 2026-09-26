"""Typed contracts shared by all agents (Pydantic = validated structured output)."""
from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field


class IncidentBrief(BaseModel):
    """What the supervisor extracted from the human's request."""
    incident_id: str
    request: str
    service: str | None = None
    endpoint: str | None = None
    symptom: str = "errors"
    status_codes: list[int] = Field(default_factory=list)
    suspected_version: str | None = None
    reported_at: str
    reported_start: str | None = None
    severity: Literal["sev1", "sev2", "sev3"] = "sev2"


class Evidence(BaseModel):
    id: str
    agent: str
    kind: str
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    source: dict[str, Any] = Field(default_factory=dict)  # tool + args that produced it
    time: str | None = None


class AgentTask(BaseModel):
    task_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    agent: str
    goal: str
    workspace: str
    run_id: str | None = None
    incident: IncidentBrief
    params: dict[str, Any] = Field(default_factory=dict)
    wave: int = 1


class AgentResult(BaseModel):
    task_id: str
    agent: str
    status: Literal["completed", "failed", "no_data"] = "completed"
    summary: str
    evidence: list[Evidence] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    tools_called: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    security_findings: list[dict] = Field(default_factory=list)


class PlanStep(BaseModel):
    id: str
    agent: str
    goal: str
    params: dict[str, Any] = Field(default_factory=dict)
    wave: int = 1
    reason: str = ""
    status: Literal["pending", "running", "done", "failed", "skipped"] = "pending"


class Plan(BaseModel):
    steps: list[PlanStep]
    rationale: str = ""


class Hypothesis(BaseModel):
    id: str
    pattern: str
    title: str
    category: str
    score: float
    confidence: float
    supporting: list[dict] = Field(default_factory=list)     # {evidence_id, rule, weight}
    contradicting: list[dict] = Field(default_factory=list)
    culprit: dict[str, Any] = Field(default_factory=dict)
    fix_kind: str = ""
    verification_plan: list[str] = Field(default_factory=list)
    explanation: str = ""


class Check(BaseModel):
    name: str
    passed: bool | None
    detail: str
    data: dict[str, Any] = Field(default_factory=dict)


class VerificationReport(BaseModel):
    target: str
    verdict: Literal["verified", "refuted", "inconclusive"]
    checks: list[Check]
    requested_evidence: list[dict] = Field(default_factory=list)
    summary: str = ""
