"""Small helper for building git repositories with back-dated history."""
from __future__ import annotations

import os
import subprocess
from datetime import datetime
from pathlib import Path


def git_date(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S+0000")


class GitRepo:
    def __init__(self, path: Path):
        self.path = Path(path)

    def run(self, *args: str, env: dict | None = None, check: bool = True) -> str:
        full_env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(self.path.parent)}
        if env:
            full_env.update(env)
        proc = subprocess.run(["git", *args], cwd=self.path, env=full_env, check=check,
                              capture_output=True, text=True)
        return proc.stdout

    def init(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        self.run("init", "-q", "-b", "main")
        self.run("config", "user.name", "acme-ci")
        self.run("config", "user.email", "ci@acme.dev")
        self.run("config", "commit.gpgsign", "false")
        self.run("config", "tag.gpgsign", "false")

    def write_tree(self, files: dict[str, str]) -> None:
        for rel, content in files.items():
            p = self.path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if not p.exists() or p.read_text() != content:
                p.write_text(content)

    def commit(self, message: str, author: str, when: datetime) -> str:
        name, email = author.rsplit(" <", 1)
        email = email.rstrip(">")
        env = {
            "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email,
            "GIT_AUTHOR_DATE": git_date(when), "GIT_COMMITTER_DATE": git_date(when),
        }
        self.run("add", "-A")
        self.run("commit", "-q", "--allow-empty", "-m", message, env=env)
        return self.run("rev-parse", "HEAD").strip()

    def tag(self, name: str, message: str, when: datetime) -> None:
        env = {"GIT_COMMITTER_DATE": git_date(when), "GIT_COMMITTER_NAME": "deploy-bot",
               "GIT_COMMITTER_EMAIL": "deploy-bot@acme.dev"}
        self.run("tag", "-a", name, "-m", message, env=env)
