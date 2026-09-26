from types import SimpleNamespace

from pydantic import BaseModel

from aegis.llm.providers import ClaudeProvider, LLMProvider, LLMResult, OfflineProvider
from aegis.llm.router import LLMClient, price, route


class Answer(BaseModel):
    value: int


def test_routing_rules():
    assert route("triage") == "fast"
    assert route("rca") == "strong"
    assert route("critique", {"margin": 0.8}) == "fast"
    assert route("sql", {"retry": 1}) == "strong"
    assert route("plan", {"replan_round": 1}) == "strong"


def test_pricing():
    assert price("claude-haiku-4-5-20251001", 1_000_000, 0) == 1.0


async def test_offline_uses_fallback_and_estimates():
    client = LLMClient(OfflineProvider())
    result, source = await client.structured(task="triage", system="s", prompt="hello world" * 10,
                                             schema=Answer, fallback=lambda: Answer(value=7))
    assert (result.value, source) == (7, "fallback")


class FlakyProvider(LLMProvider):
    name = "flaky"

    def __init__(self):
        self.calls = 0

    async def complete(self, **kw) -> LLMResult:
        self.calls += 1
        data = {"value": "not a number"} if self.calls == 1 else {"value": 42}
        return LLMResult(text="", data=data, model=kw["model"], input_tokens=10, output_tokens=5, latency_ms=1)


async def test_validation_failure_triggers_self_correction():
    provider = FlakyProvider()
    result, source = await LLMClient(provider).structured(task="rca", system="s", prompt="p", schema=Answer,
                                                          fallback=lambda: Answer(value=0))
    assert (result.value, source, provider.calls) == (42, "llm", 2)


async def test_claude_provider_uses_forced_tool_for_structured_output():
    captured = {}

    class Messages:
        async def create(self, **kw):
            captured.update(kw)
            return SimpleNamespace(content=[SimpleNamespace(type="tool_use", input={"value": 3})],
                                   usage=SimpleNamespace(input_tokens=12, output_tokens=4))

    provider = ClaudeProvider(client=SimpleNamespace(messages=Messages()))
    r = await provider.complete(system="s", prompt="p", model="claude-sonnet-5", schema=Answer.model_json_schema())
    assert r.data == {"value": 3} and captured["tool_choice"] == {"type": "tool", "name": "submit"}
