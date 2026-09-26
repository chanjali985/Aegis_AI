"""Git MCP server: read-only repository intelligence plus one approval-gated write.

Run standalone (e.g. for Claude Desktop):  python -m aegis.mcp_servers.git_server --workspace <ws>
"""
from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

SAFE_REV = re.compile(r"^[A-Za-z0-9_./~^:@{}\-]+$")
MAX_DIFF = 12000


def _git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=repo, capture_output=True,
                          text=True, check=False)
    if check and proc.returncode != 0:
        raise ValueError(proc.stderr.strip()[:500] or f"git {' '.join(args)} failed")
    return proc.stdout


def _rev(rev: str) -> str:
    if not rev or rev.startswith("-") or not SAFE_REV.match(rev):
        raise ValueError(f"invalid revision: {rev!r}")
    return rev


def _path(repo: Path, path: str) -> str:
    p = (repo / path).resolve()
    if not str(p).startswith(str(repo.resolve())) or path.startswith("-"):
        raise ValueError("path escapes repository")
    return path


def build_server(workspace: str | Path) -> FastMCP:
    repo = Path(workspace) / "repo"
    mcp = FastMCP("git", instructions="Read-only access to the acme-platform monorepo and its deploy tags.")

    @mcp.tool()
    def list_deploys(service: str | None = None, since: str | None = None, until: str | None = None) -> dict:
        """List deployments recorded as `deploy/<service>/v<version>` tags, oldest first.

        Timestamps are ISO-8601 UTC; `since`/`until` filter by deploy time.
        """
        out = _git(repo, "for-each-ref", "refs/tags/deploy", "--sort=taggerdate",
                   "--format=%(refname:short)|%(*objectname)|%(taggerdate:iso-strict)")
        deploys = []
        for line in out.splitlines():
            tag, sha, date = line.split("|")
            _, svc, version = tag.split("/", 2)
            when = date.replace("+00:00", "Z")
            if service and svc != service:
                continue
            if since and when < since:
                continue
            if until and when > until:
                continue
            deploys.append({"service": svc, "version": version.lstrip("v"), "tag": tag,
                            "commit": sha, "deployed_at": when})
        return {"deploys": deploys}

    @mcp.tool()
    def git_log(rev_range: str | None = None, path: str | None = None, max_count: int = 30) -> dict:
        """Commit history (newest first) for a revision range such as `A..B` and optional path."""
        args = ["log", f"--max-count={min(max_count, 200)}", "--date=iso-strict",
                "--format=%x1e%H%x1f%an <%ae>%x1f%ad%x1f%s%x1f%b%x1f", "--name-only"]
        if rev_range:
            args.append(_rev(rev_range))
        if path:
            args += ["--", _path(repo, path)]
        out = _git(repo, *args)
        commits = []
        for rec in out.split("\x1e")[1:]:
            sha, author, date, subject, body, files = rec.split("\x1f")
            commits.append({"sha": sha, "author": author, "date": date.replace("+00:00", "Z"),
                            "subject": subject, "body": body.strip(),
                            "files": [f for f in files.strip().splitlines() if f.strip()]})
        return {"commits": commits}

    @mcp.tool()
    def git_show(sha: str, max_chars: int = MAX_DIFF) -> dict:
        """Show one commit: metadata, changed files and the unified diff (truncated)."""
        sha = _rev(sha)
        meta = _git(repo, "show", "-s", "--date=iso-strict", "--format=%H|%P|%an <%ae>|%ad|%s%n%b", sha)
        header, _, body = meta.partition("\n")
        full, parents, author, date, subject = header.split("|", 4)
        stat = _git(repo, "show", "--format=", "--name-status", sha)
        diff = _git(repo, "show", "--format=", "--unified=3", sha)
        files = [{"status": l.split("\t")[0], "path": l.split("\t")[-1]} for l in stat.splitlines() if l]
        return {"sha": full, "parents": parents.split(), "author": author, "date": date.replace("+00:00", "Z"),
                "subject": subject, "body": body.strip(), "files": files,
                "diff": diff[:max_chars], "truncated": len(diff) > max_chars}

    @mcp.tool()
    def git_diff(base: str, head: str = "HEAD", path: str | None = None) -> dict:
        """Unified diff between two revisions, optionally limited to a path."""
        args = ["diff", "--unified=3", _rev(base), _rev(head)]
        if path:
            args += ["--", _path(repo, path)]
        diff = _git(repo, *args)
        return {"diff": diff[:MAX_DIFF], "truncated": len(diff) > MAX_DIFF}

    @mcp.tool()
    def show_file_at(path: str, rev: str = "HEAD") -> dict:
        """File contents at a given revision."""
        return {"path": path, "rev": rev, "content": _git(repo, "show", f"{_rev(rev)}:{_path(repo, path)}")}

    @mcp.tool()
    def read_file(path: str) -> dict:
        """File contents at HEAD."""
        return show_file_at(path, "HEAD")

    @mcp.tool()
    def git_blame(path: str, line: int, rev: str = "HEAD") -> dict:
        """Which commit last changed `line` of `path` as of `rev`."""
        out = _git(repo, "blame", "--porcelain", "-L", f"{int(line)},{int(line)}", _rev(rev), "--",
                   _path(repo, path))
        lines = out.splitlines()
        sha = lines[0].split()[0]
        info = {l.split(" ", 1)[0]: l.split(" ", 1)[1] for l in lines[1:] if " " in l and not l.startswith("\t")}
        text = next((l[1:] for l in lines if l.startswith("\t")), "")
        return {"path": path, "line": line, "rev": rev, "commit": sha, "author": info.get("author"),
                "author_time": info.get("author-time"), "summary": info.get("summary"), "text": text}

    @mcp.tool()
    def search_repository(pattern: str, path_glob: str | None = None, max_results: int = 50) -> dict:
        """Regex search over tracked files at HEAD (git grep)."""
        args = ["grep", "-n", "-E", "-e", pattern]
        if path_glob:
            args += ["--", path_glob]
        out = _git(repo, *args, check=False)
        matches = []
        for l in out.splitlines()[:max_results]:
            f, ln, text = l.split(":", 2)
            matches.append({"file": f, "line": int(ln), "text": text.strip()})
        return {"matches": matches}

    @mcp.tool()
    def find_symbol(name: str) -> dict:
        """Locate function or class definitions by name."""
        if not re.match(r"^\w+$", name):
            raise ValueError("symbol names are identifiers")
        return search_repository(rf"^\s*(def|class) {name}\b")

    @mcp.tool()
    def create_fix_branch(branch: str, patch: str, message: str) -> dict:
        """[approval required] Create a branch with the patch applied (the pull request source)."""
        if not re.match(r"^aegis/[\w.\-]+$", branch):
            raise ValueError("branch must be named aegis/<name>")
        with tempfile.TemporaryDirectory() as tmp:
            wt = Path(tmp) / "wt"
            _git(repo, "worktree", "add", "-q", "-b", branch, str(wt), "HEAD")
            try:
                patch_file = Path(tmp) / "fix.patch"
                patch_file.write_text(patch)
                _git(wt, "apply", "--whitespace=nowarn", str(patch_file))
                _git(wt, "add", "-A")
                env_msg = message + "\n\nPrepared by AegisAI; approved by a human reviewer."
                _git(wt, "-c", "user.name=AegisAI", "-c", "user.email=aegis@acme.dev", "commit", "-q",
                     "-m", env_msg)
                sha = _git(wt, "rev-parse", "HEAD").strip()
            finally:
                _git(repo, "worktree", "remove", "--force", str(wt), check=False)
        return {"branch": branch, "commit": sha}

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    build_server(ap.parse_args().workspace).run("stdio")


if __name__ == "__main__":
    main()
