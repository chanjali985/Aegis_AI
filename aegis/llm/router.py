"""Complexity-aware model routing, cost accounting and structured-output calls.

Cheap/fast models handle classification, planning, SQL drafting and report
writing; the strong model is reserved for root-cause reasoning, patch writing
and adversarial critique - and is only used for critique when the case is
actually ambiguous. Every call records the routed cost next to what the same
call would have cost on the strong model, so savings are measured, not assumed.
"""
from __future__ import annotations

import json
import time
from typing import Callable, TypeVar

from pydantic import BaseModel, ValidationError

from aegis.config import get_settings
from aegis.llm.providers import LLMProvider, LLMUnavailable, build_provider, estimate_tokens
from aegis.observability import metrics
from aegis.observability.tracing import current_agent, current_run, span
from aegis.security.prompt_injection import UNTRUSTED_SYSTEM_RULE
from aegis.storage.db import get_store

T = TypeVar("T", bound=BaseModel)

# USD per million tokens (input, output). Verify against the current price list
# (https://docs.claude.com/en/docs/about-claude/pricing) before quoting numbers.
PRICING: dict[str, tuple[float, float]] = {
    "claude-haiku-4-5-20251001": (1.0, 5.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-opus-5-5": (5.0, 25.0),
    "gpt-4o-mini": (0.15, 0.6),
    "gpt-4o": (2.5, 10.0),
}
DEFAULT_PRICE = (3.0, 15.0)

BASE_TIER = {
    "triage": "fast", "plan": "fast", "sql": "fast", "doc_summary": "fast", "report": "fast",
    "rca": "strong", "patch": "strong", "critique": "strong",
}


def price(model: str, inp: int, out: int) -> float:
    p_in, p_out = PRICING.get(model, DEFAULT_PRICE)
    return (inp * p_in + out * p_out) / 1_000_000


def route(task: str, signals: dict | None = None) -> str:
    """Pick a tier for ``task`` given complexity ``signals``."""
    signals = signals or {}
    tier = BASE_TIER.get(task, "fast")
    if task == "plan" and signals.get("replan_round", 0) > 0:
        tier = "strong"          # re-planning after failure needs more reasoning
    if task == "sql" and signals.get("retry", 0) > 0:
        tier = "strong"          # escalate after a failed query
    if task == "critique" and signals.get("margin", 0.0) >= 0.5:
        tier = "fast"            # clear-cut case: cheap sanity check is enough
    if task == "rca" and signals.get("candidates", 2) <= 1 and signals.get("margin", 0.0) >= 0.6:
        tier = "fast"
    return tier


class LLMClient:
    def __init__(self, provider: LLMProvider | None = None):
        s = get_settings()
        self.provider = provider or build_provider(s.provider, s.openai_base_url)
        self.models = {"fast": s.model_fast, "strong": s.model_strong}

    @property
    def live(self) -> bool:
        return self.provider.live

    async def structured(self, *, task: str, system: str, prompt: str, schema: type[T],
                         fallback: Callable[[], T], signals: dict | None = None,
                         max_tokens: int = 1500) -> tuple[T, str]:
        """Return ``(result, source)`` where source is ``llm`` or ``fallback``."""
        tier = route(task, signals)
        model = self.models[tier]
        system = system + "\n\n" + UNTRUSTED_SYSTEM_RULE
        json_schema = schema.model_json_schema()
        t0 = time.perf_counter()
        with span(f"llm:{task}", kind="llm", task=task, tier=tier, model=model) as sp:
            result, source = None, "fallback"
            inp = out = 0
            estimated = True
            if self.provider.live:
                attempt_prompt = prompt
                for _attempt in range(2):
                    try:
                        r = await self.provider.complete(system=system, prompt=attempt_prompt, model=model,
                                                         max_tokens=max_tokens, schema=json_schema)
                        inp += r.input_tokens
                        out += r.output_tokens
                        estimated = False
                        result = schema.model_validate(r.data if r.data is not None else json.loads(r.text))
                        source = "llm"
                        break
                    except (ValidationError, json.JSONDecodeError, TypeError) as exc:
                        attempt_prompt = (prompt + "\n\nYour previous answer failed validation: "
                                          f"{str(exc)[:500]}\nReturn a corrected answer.")
                    except LLMUnavailable:
                        break
                    except Exception as exc:  # network / API errors -> degrade gracefully
                        sp["attrs"]["provider_error"] = repr(exc)[:300]
                        break
            if result is None:
                result = fallback()
                if estimated:
                    inp = estimate_tokens(system + prompt)
                    out = estimate_tokens(result.model_dump_json())
            cost = price(model, inp, out)
            baseline = price(self.models["strong"], inp, out)
            sp["attrs"].update(source=source, input_tokens=inp, output_tokens=out, cost_usd=round(cost, 6))
        rec = {"run_id": current_run.get(), "agent": current_agent.get(), "task": task,
               "provider": self.provider.name, "model": model, "tier": tier, "input_tokens": inp,
               "output_tokens": out, "cost_usd": cost, "baseline_cost_usd": baseline,
               "latency_ms": (time.perf_counter() - t0) * 1000, "estimated": estimated}
        if rec["run_id"]:
            get_store().add_llm_call(rec)
        metrics.LLM_TOKENS.inc(inp, model=model, direction="input")
        metrics.LLM_TOKENS.inc(out, model=model, direction="output")
        metrics.LLM_COST.inc(cost, model=model)
        return result, source


_client: LLMClient | None = None


def get_llm() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client


def set_llm(client: LLMClient | None) -> None:
    global _client
    _client = client
