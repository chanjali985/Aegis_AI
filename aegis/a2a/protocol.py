"""Agent2Agent (A2A) protocol subset: Agent Cards, JSON-RPC ``message/send`` and ``tasks/get``.

Every specialist is exposed as an independent A2A agent. The supervisor only
knows each agent's *card* (name, skills, endpoint) and exchanges messages with
it; it never touches another agent's tools or internal state. Agents can run
in-process (local transport, same JSON-RPC envelopes) or as separate services
over HTTP, selected per agent with ``AEGIS_REMOTE_AGENTS``.
"""
from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field

PROTOCOL_VERSION = "0.3.0"


class AgentSkill(BaseModel):
    id: str
    name: str
    description: str
    tags: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)


class AgentCapabilities(BaseModel):
    streaming: bool = False
    pushNotifications: bool = False
    stateTransitionHistory: bool = False


class AgentCard(BaseModel):
    protocolVersion: str = PROTOCOL_VERSION
    name: str
    description: str
    url: str
    version: str = "0.1.0"
    preferredTransport: str = "JSONRPC"
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    defaultInputModes: list[str] = Field(default_factory=lambda: ["application/json"])
    defaultOutputModes: list[str] = Field(default_factory=lambda: ["application/json"])
    skills: list[AgentSkill] = Field(default_factory=list)
    # AegisAI extension: least-privilege summary advertised to callers
    metadata: dict[str, Any] = Field(default_factory=dict)


class DataPart(BaseModel):
    kind: Literal["data"] = "data"
    data: dict[str, Any]


class TextPart(BaseModel):
    kind: Literal["text"] = "text"
    text: str


class Message(BaseModel):
    kind: Literal["message"] = "message"
    role: Literal["user", "agent"] = "user"
    messageId: str = Field(default_factory=lambda: uuid.uuid4().hex)
    contextId: str | None = None
    parts: list[DataPart | TextPart]


class TaskStatus(BaseModel):
    state: Literal["submitted", "working", "completed", "failed", "rejected"]
    message: str | None = None


class Artifact(BaseModel):
    artifactId: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str
    parts: list[DataPart | TextPart]


class Task(BaseModel):
    kind: Literal["task"] = "task"
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    contextId: str
    status: TaskStatus
    artifacts: list[Artifact] = Field(default_factory=list)
    history: list[Message] = Field(default_factory=list)


class JSONRPCRequest(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Any = None


class JSONRPCResponse(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int | None
    result: dict[str, Any] | None = None
    error: JSONRPCError | None = None
