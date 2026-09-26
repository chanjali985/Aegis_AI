"""Supervisor: understands the request (triage) and judges when evidence is sufficient."""
from __future__ import annotations

import re

from pydantic import BaseModel, Field

from aegis.agents.models import IncidentBrief
from aegis.llm.router import get_llm
from aegis.observability.tracing import agent_span
from aegis.util import parse_ts

SERVICE_RX = re.compile(r"\b([a-z][a-z0-9]*-service)\b")
ENDPOINT_RX = re.compile(r"(?<![\w.])(/[a-z0-9_/\-]+)")
STATUS_RX = re.compile(r"\b([45]\d\d)s?\b")
VERSION_RX = re.compile(r"\bv?(\d+\.\d+\.\d+)\b")
TIME_RX = re.compile(r"\b(?:around|since|at)\s+(\d{1,2}):(\d{2})\b")
SYMPTOMS = [("429", "rate limiting (429)"), ("timeout", "timeouts"), ("slow", "latency"), ("50", "5xx errors"),
            ("fail", "failures"), ("error", "errors")]
KEYWORDS = {"payment": "payment", "card": "payment", "checkout": "checkout", "cart": "checkout", "audit": "audit",
            "stock": "inventory", "inventory": "inventory", "notif": "notification", "email": "notification",
            "login": "auth", "token": "auth", "auth": "auth"}


class BriefDraft(BaseModel):
    service: str | None = Field(default=None, description="service name like payment-service, if stated")
    endpoint: str | None = None
    symptom: str = "errors"
    status_codes: list[int] = Field(default_factory=list)
    suspected_version: str | None = None
    severity: str = "sev2"


def regex_brief(incident_id: str, request: str, reported_at: str) -> IncidentBrief:
    low = request.lower()
    service = (SERVICE_RX.search(low) or [None, None])[1] if SERVICE_RX.search(low) else None
    endpoint = (ENDPOINT_RX.search(request) or [None, None])[1] if ENDPOINT_RX.search(request) else None
    codes = sorted({int(c) for c in STATUS_RX.findall(request)})
    version = VERSION_RX.search(request)
    symptom = next((label for key, label in SYMPTOMS if key in low), "errors")
    start = None
    if m := TIME_RX.search(low):
        start = reported_at[:11] + f"{int(m.group(1)):02d}:{m.group(2)}:00Z"
        if start > reported_at:
            start = None
    return IncidentBrief(incident_id=incident_id, request=request, service=service, endpoint=endpoint,
                         symptom=symptom, status_codes=codes, suspected_version=version.group(1) if version else None,
                         reported_at=reported_at, reported_start=start,
                         severity="sev1" if any(c >= 500 for c in codes) else "sev2")


def keywords(request: str) -> list[str]:
    low = request.lower()
    return list(dict.fromkeys(v for k, v in KEYWORDS.items() if k in low))


async def triage(incident_id: str, request: str, reported_at: str) -> IncidentBrief:
    async with agent_span("supervisor", "triage") as sp:
        base = regex_brief(incident_id, request, reported_at)
        llm = get_llm()
        # offline, the router records the (estimated) call and returns the regex fallback
        draft, source = await llm.structured(
            task="triage", system="Extract structured incident fields from an on-call report.",
            prompt=f"Report: {request}", schema=BriefDraft,
            fallback=lambda: BriefDraft(service=base.service, endpoint=base.endpoint, symptom=base.symptom,
                                        status_codes=base.status_codes, suspected_version=base.suspected_version))
        if source == "llm":
            # regex wins for exact identifiers; the LLM fills gaps
            base.service = base.service or (draft.service if draft.service and
                                            SERVICE_RX.fullmatch(draft.service) else None)
            base.endpoint = base.endpoint or draft.endpoint
            base.symptom = draft.symptom or base.symptom
        sp["attrs"]["result_summary"] = {"summary": f"service={base.service} endpoint={base.endpoint} "
                                                    f"symptom={base.symptom} version={base.suspected_version}"}
        return base


def default_onset(brief: IncidentBrief) -> str:
    if brief.reported_start:
        return brief.reported_start
    from aegis.util import shift
    return shift(brief.reported_at, -120)


def evidence_is_sufficient(hypotheses: list[dict], threshold: float) -> bool:
    top = hypotheses[0] if hypotheses else None
    return bool(top and top["pattern"] != "unknown" and top["confidence"] >= threshold)


def ts_ok(s: str | None) -> bool:
    try:
        parse_ts(s or "")
        return True
    except ValueError:
        return False
