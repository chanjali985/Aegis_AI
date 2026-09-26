"""Isolated execution of repository code (replays, tests) for verification and fixes.

Each sandbox is a detached git worktree in a temp directory. Repository code is
untrusted, so it only ever runs in a separate process with a stripped
environment, CPU/memory/file-size limits and a wall-clock timeout; nothing it
does can touch the agent process or the main checkout. (Network isolation needs
an OS-level sandbox such as a container or nsjail in production.)
"""
from __future__ import annotations

import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPLAY_RUNNER = """
import json, sys
from platform_sim.replay import replay
data = json.load(sys.stdin)
print(json.dumps(replay('.', data['service'], data['traffic'], data.get('runtime'))))
"""


def _limits(cpu_s: int):
    def apply():
        for limit, value in ((resource.RLIMIT_CPU, cpu_s),
                             (resource.RLIMIT_AS, 2 * 1024**3),
                             (resource.RLIMIT_FSIZE, 50 * 1024**2)):
            try:
                resource.setrlimit(limit, (value, value))
            except (ValueError, OSError):
                pass  # e.g. macOS rejects RLIMIT_AS; keep the limits the OS supports
        os.setsid()
    return apply


class SandboxError(Exception):
    pass


class Sandbox:
    def __init__(self, repo: str | Path, rev: str = "HEAD", timeout_s: int = 120, agent: str | None = None):
        if agent is not None:
            from aegis.security.permissions import PermissionDenied, is_allowed
            if not is_allowed(agent, "sandbox.execute"):
                raise PermissionDenied(f"agent '{agent}' may not open a sandbox")
        self.repo = Path(repo)
        self.rev = rev
        self.timeout_s = timeout_s
        self.tmp: Path | None = None
        self.path: Path | None = None

    def __enter__(self) -> "Sandbox":
        self.tmp = Path(tempfile.mkdtemp(prefix="aegis-sbx-"))
        self.path = self.tmp / "wt"
        self._git(self.repo, "worktree", "add", "--detach", "-q", str(self.path), self.rev)
        return self

    def __exit__(self, *exc) -> None:
        self._git(self.repo, "worktree", "remove", "--force", str(self.path), check=False)
        shutil.rmtree(self.tmp, ignore_errors=True)
        self._git(self.repo, "worktree", "prune", check=False)

    @staticmethod
    def _git(cwd: Path, *args: str, check: bool = True, stdin: str | None = None) -> subprocess.CompletedProcess:
        proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, input=stdin)
        if check and proc.returncode != 0:
            raise SandboxError(proc.stderr.strip()[:400])
        return proc

    def _run(self, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(self.path),
               "HOME": str(self.tmp), "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8"}
        try:
            return subprocess.run(args, cwd=self.path, env=env, input=stdin, capture_output=True, text=True,
                                  timeout=self.timeout_s, preexec_fn=_limits(self.timeout_s))
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(f"timed out after {self.timeout_s}s") from exc

    # -- file operations --------------------------------------------------------
    def read(self, rel: str) -> str:
        return (self.path / rel).read_text()

    def write(self, rel: str, content: str) -> None:
        p = (self.path / rel).resolve()
        if not str(p).startswith(str(self.path.resolve())):
            raise SandboxError("path escapes sandbox")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def listdir(self, rel: str) -> list[str]:
        return sorted(os.listdir(self.path / rel))

    def apply_patch(self, patch: str, reverse: bool = False) -> None:
        args = ["apply", "--whitespace=nowarn"] + (["-R"] if reverse else []) + ["-"]
        self._git(self.path, *args, stdin=patch)

    def revert_commit(self, sha: str) -> None:
        proc = self._git(self.path, "revert", "--no-commit", sha, check=False)
        if proc.returncode != 0:
            self._git(self.path, "revert", "--abort", check=False)
            self._git(self.path, "checkout", "--", ".", check=False)
            diff = self._git(self.path, "show", "--format=", sha).stdout
            self.apply_patch(diff, reverse=True)

    def _stage(self) -> None:
        self._git(self.path, "add", "-A", "--", ".", ":(exclude)**/__pycache__/**", ":(exclude)*.pyc")

    def diff(self) -> str:
        self._stage()
        return self._git(self.path, "diff", "--cached", "--no-color").stdout

    def changed_files(self) -> list[str]:
        self._stage()
        return [l for l in self._git(self.path, "diff", "--cached", "--name-only").stdout.splitlines() if l]

    # -- execution ------------------------------------------------------------------
    def replay(self, service: str, traffic: list[dict], runtime: dict | None = None) -> dict:
        proc = self._run([sys.executable, "-c", REPLAY_RUNNER],
                         stdin=json.dumps({"service": service, "traffic": traffic, "runtime": runtime or {}}))
        if proc.returncode != 0:
            raise SandboxError(proc.stderr.strip()[-600:])
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def pytest(self, *targets: str) -> dict:
        proc = self._run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header",
                          "-o", "addopts=", *targets])
        out = proc.stdout + proc.stderr
        passed = sum(int(n) for n in re.findall(r"(\d+) passed", out))
        failed = sum(int(n) for n in re.findall(r"(\d+) (?:failed|error)", out))
        return {"ok": proc.returncode == 0, "passed": passed, "failed": failed, "output": out[-1500:]}

    def compile_check(self, files: list[str]) -> list[str]:
        errors = []
        for f in files:
            if f.endswith(".py"):
                proc = self._run([sys.executable, "-c", f"compile(open('{f}').read(), '{f}', 'exec')"])
                if proc.returncode != 0:
                    errors.append(f"{f}: {proc.stderr.strip()[-200:]}")
            elif f.endswith((".yaml", ".yml")):
                proc = self._run([sys.executable, "-c", f"import yaml; yaml.safe_load(open('{f}'))"])
                if proc.returncode != 0:
                    errors.append(f"{f}: invalid YAML")
        return errors
