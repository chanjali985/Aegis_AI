"""Model-agnostic LLM providers.

``LLMProvider`` is the only interface agents depend on. Implementations:

* ``ClaudeProvider``     - Anthropic Messages API; structured output via forced tool use
* ``OpenAICompatProvider`` - any OpenAI-compatible endpoint (OpenAI, Gemini's OpenAI
                           endpoint, vLLM, Ollama) using JSON mode
* ``OfflineProvider``    - no network; signals callers to use their deterministic
                           fallback so the whole system runs (and is benchmarked)
                           reproducibly without API keys
"""
from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResult:
    text: str
    data: dict | None
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
    estimated: bool = False


class LLMUnavailable(Exception):
    """Raised by the offline provider; callers fall back to deterministic logic."""


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class LLMProvider(ABC):
    name = "base"

    @abstractmethod
    async def complete(self, *, system: str, prompt: str, model: str, max_tokens: int = 1500,
                       schema: dict | None = None) -> LLMResult: ...

    @property
    def live(self) -> bool:
        return True


class ClaudeProvider(LLMProvider):
    name = "claude"

    def __init__(self, api_key: str | None = None, client=None):
        if client is None:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.client = client

    async def complete(self, *, system, prompt, model, max_tokens=1500, schema=None) -> LLMResult:
        t0 = time.perf_counter()
        kwargs = dict(model=model, max_tokens=max_tokens, system=system,
                      messages=[{"role": "user", "content": prompt}])
        if schema:
            kwargs["tools"] = [{"name": "submit", "description": "Submit the structured answer.",
                                "input_schema": schema}]
            kwargs["tool_choice"] = {"type": "tool", "name": "submit"}
        resp = await self.client.messages.create(**kwargs)
        data, text = None, ""
        for block in resp.content:
            if getattr(block, "type", None) == "tool_use":
                data = dict(block.input)
            elif getattr(block, "type", None) == "text":
                text += block.text
        return LLMResult(text=text or json.dumps(data or {}), data=data, model=model,
                         input_tokens=resp.usage.input_tokens, output_tokens=resp.usage.output_tokens,
                         latency_ms=(time.perf_counter() - t0) * 1000)


class OpenAICompatProvider(LLMProvider):
    name = "openai"

    def __init__(self, base_url: str, api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    async def complete(self, *, system, prompt, model, max_tokens=1500, schema=None) -> LLMResult:
        import httpx
        t0 = time.perf_counter()
        sys_msg = system
        if schema:
            sys_msg += "\n\nRespond with a single JSON object matching this JSON schema:\n" + json.dumps(schema)
        body = {"model": model, "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": sys_msg}, {"role": "user", "content": prompt}]}
        if schema:
            body["response_format"] = {"type": "json_object"}
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(f"{self.base_url}/chat/completions", json=body,
                                  headers={"Authorization": f"Bearer {self.api_key}"})
            r.raise_for_status()
            payload = r.json()
        text = payload["choices"][0]["message"]["content"] or ""
        data = None
        if schema:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = None
        usage = payload.get("usage", {})
        return LLMResult(text=text, data=data, model=model,
                         input_tokens=usage.get("prompt_tokens", estimate_tokens(sys_msg + prompt)),
                         output_tokens=usage.get("completion_tokens", estimate_tokens(text)),
                         latency_ms=(time.perf_counter() - t0) * 1000)


class OfflineProvider(LLMProvider):
    name = "offline"

    @property
    def live(self) -> bool:
        return False

    async def complete(self, *, system, prompt, model, max_tokens=1500, schema=None) -> LLMResult:
        raise LLMUnavailable("offline provider: use deterministic fallback")


def build_provider(kind: str = "auto", openai_base_url: str = "https://api.openai.com/v1") -> LLMProvider:
    if kind == "auto":
        if os.environ.get("ANTHROPIC_API_KEY"):
            kind = "claude"
        elif os.environ.get("OPENAI_API_KEY"):
            kind = "openai"
        else:
            kind = "offline"
    if kind == "claude":
        return ClaudeProvider()
    if kind == "openai":
        return OpenAICompatProvider(openai_base_url)
    return OfflineProvider()
