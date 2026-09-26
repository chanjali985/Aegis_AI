"""Runtime settings (environment variables, prefix ``AEGIS_``)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("AEGIS_DATA_DIR", "./.aegis")).resolve())
    # llm provider: auto | claude | openai | offline
    provider: str = field(default_factory=lambda: _env("AEGIS_PROVIDER", "auto"))
    model_fast: str = field(default_factory=lambda: _env("AEGIS_MODEL_FAST", "claude-haiku-4-5-20251001"))
    model_strong: str = field(default_factory=lambda: _env("AEGIS_MODEL_STRONG", "claude-sonnet-5"))
    openai_base_url: str = field(default_factory=lambda: _env("AEGIS_OPENAI_BASE_URL", "https://api.openai.com/v1"))
    # MCP transport between agents and tool servers: memory | stdio
    mcp_transport: str = field(default_factory=lambda: _env("AEGIS_MCP_TRANSPORT", "memory"))
    # comma-separated "agent=url" pairs for agents served remotely over A2A HTTP
    remote_agents: str = field(default_factory=lambda: _env("AEGIS_REMOTE_AGENTS", ""))
    max_replans: int = field(default_factory=lambda: int(_env("AEGIS_MAX_REPLANS", "2")))
    max_reflections: int = field(default_factory=lambda: int(_env("AEGIS_MAX_REFLECTIONS", "2")))
    confidence_threshold: float = field(default_factory=lambda: float(_env("AEGIS_CONFIDENCE", "0.70")))
    sandbox_timeout_s: int = field(default_factory=lambda: int(_env("AEGIS_SANDBOX_TIMEOUT", "120")))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "aegis.db"

    @property
    def checkpoint_path(self) -> Path:
        return self.data_dir / "checkpoints.db"

    @property
    def workspaces_dir(self) -> Path:
        return self.data_dir / "workspaces"

    def remote_agent_map(self) -> dict[str, str]:
        out = {}
        for pair in filter(None, (p.strip() for p in self.remote_agents.split(","))):
            name, url = pair.split("=", 1)
            out[name.strip()] = url.strip().rstrip("/")
        return out

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.workspaces_dir.mkdir(parents=True, exist_ok=True)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.ensure_dirs()
    return _settings


def reset_settings(**overrides) -> Settings:
    global _settings
    _settings = Settings(**overrides)
    _settings.ensure_dirs()
    return _settings
