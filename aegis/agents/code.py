"""Code intelligence agent: deploy history, config/code/migration diffs, blame."""
from __future__ import annotations

import re
from datetime import datetime, timezone

import yaml

from aegis.agents.base import Agent
from aegis.agents.models import AgentResult, AgentTask
from aegis.tools.gateway import ToolError, ToolGateway
from aegis.util import flatten, minutes_between, shift

HUNK_FN = re.compile(r"^@@[^@]*@@\s*(?:def|class)\s+(\w+)", re.M)
INDEX_STMT = re.compile(r"(CREATE|DROP)\s+INDEX\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(\w+)", re.I)


def file_diffs(diff: str) -> dict[str, str]:
    out = {}
    for block in re.split(r"(?m)^diff --git ", diff):
        if not block.strip():
            continue
        m = re.match(r"a/(\S+) b/(\S+)", block)
        if m:
            out[m.group(2)] = block
    return out


def changed_lines(block: str) -> tuple[list[str], list[str]]:
    removed, added = [], []
    for line in block.splitlines():
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
    return removed, added


def code_risks(removed: list[str], added: list[str]) -> list[str]:
    risks = []
    removed_get = [l for l in removed if ".get(" in l]
    added_subscript = [l for l in added if re.search(r"(payload|fields)\[\s*['\"]\w+['\"]\s*\]", l)
                       or re.search(r"payload\[k\]", l)]
    if removed_get and added_subscript:
        risks.append("removed_default")
    elif added_subscript:
        risks.append("direct_subscript")
    code_like = [l for l in removed + added if l.strip() and not l.strip().startswith(("#", '"', "'"))
                 and re.search(r"[=(\[]", l)]
    if not code_like:
        risks.append("comment_or_text_only")
    return risks


def direction(old, new) -> str:
    if old is None and new is not None:
        return "added" if not isinstance(new, (int, float)) else "set"
    if new is None and old is not None:
        return "removed"
    if isinstance(old, (int, float)) and isinstance(new, (int, float)):
        return "increased" if new > old else "decreased"
    return "changed"


class CodeAgent(Agent):
    name = "code"
    title = "Code Intelligence Agent"
    description = "Correlates deploys with config, code and schema changes; blames stack-trace lines."
    skills = [
        {"id": "change-analysis", "name": "Change analysis",
         "description": "Diffs every deploy of a service in the incident window and classifies changes.",
         "tags": ["git", "deploys", "config", "diff"]},
        {"id": "blame", "name": "Stack trace blame",
         "description": "git blame at the deployed revision for frames in a stack trace.",
         "tags": ["git", "blame", "stack-trace"]},
    ]

    async def execute(self, task: AgentTask, gw: ToolGateway) -> AgentResult:
        if task.params.get("mode") == "resolve_service":
            return await self.resolve_service(task, gw)
        service = task.params.get("service") or task.incident.service
        onset = task.params.get("onset") or task.incident.reported_at
        pkg = service.replace("-", "_")
        evidence, notes = [], []
        deploys = (await gw.call("git.list_deploys", service=service))["deploys"]
        window_start = shift(onset, -24 * 60)
        change_evidence = 0
        recent_commits: set[str] = set()
        for i, d in enumerate(deploys):
            if d["deployed_at"] < window_start or i == 0:
                continue
            prev = deploys[i - 1]
            log = await gw.call("git.git_log", rev_range=f"{prev['tag']}..{d['tag']}", max_count=50)
            relevant = [c for c in log["commits"]
                        if any(f.startswith(f"services/{pkg}/") or f.startswith("migrations/") for f in c["files"])]
            mins = round(minutes_between(d["deployed_at"], onset), 1)
            evidence.append(self.evidence(
                task, "deploy",
                f"{service} v{d['version']} deployed {d['deployed_at']} "
                f"({abs(mins):.0f} min {'before' if mins >= 0 else 'after'} onset): "
                + "; ".join(c["subject"] for c in relevant if not c["subject"].startswith("release:"))[:160],
                {"service": service, "version": d["version"], "tag": d["tag"], "commit": d["commit"],
                 "deployed_at": d["deployed_at"], "minutes_before_onset": mins,
                 "commits": [{"sha": c["sha"], "subject": c["subject"].split("\n")[0], "author": c["author"],
                              "files": c["files"]} for c in relevant]},
                {"tool": "git.git_log", "args": {"rev_range": f"{prev['tag']}..{d['tag']}"}}, d["deployed_at"]))
            for c in relevant:
                recent_commits.add(c["sha"])
                show = await gw.call("git.git_show", sha=c["sha"])
                diffs = file_diffs(show["diff"])
                for f in show["files"]:
                    path = f["path"]
                    ctx = {"service": service, "commit": c["sha"], "version": d["version"],
                           "deployed_at": d["deployed_at"], "minutes_before_onset": mins, "file": path,
                           "author": c["author"], "subject": c["subject"]}
                    src = {"tool": "git.git_show", "args": {"sha": c["sha"]}}
                    if path == f"services/{pkg}/config.yaml":
                        for ev in await self._config_changes(task, gw, path, c["sha"], ctx, src):
                            evidence.append(ev)
                            if not ev.data["key"].startswith("observability."):
                                change_evidence += 1
                    elif path.startswith(f"services/{pkg}/") and path.endswith(".py"):
                        removed, added = changed_lines(diffs.get(path, ""))
                        risks = code_risks(removed, added)
                        fns = HUNK_FN.findall(diffs.get(path, ""))
                        evidence.append(self.evidence(
                            task, "code_change",
                            f"{path} changed in {c['sha'][:8]} '{c['subject'][:60]}' risks={risks or ['none']}",
                            {**ctx, "risks": risks, "functions": fns, "removed": removed[:12], "added": added[:12]},
                            src, d["deployed_at"]))
                        if "comment_or_text_only" not in risks:
                            change_evidence += 1
                    elif path.startswith("migrations/") and path.endswith(".sql"):
                        content = (await gw.call("git.show_file_at", path=path, rev=c["sha"]))["content"]
                        stmts = INDEX_STMT.findall(content)
                        dropped = [n for op, n in stmts if op.upper() == "DROP"]
                        created = [n for op, n in stmts if op.upper() == "CREATE"]
                        evidence.append(self.evidence(
                            task, "migration_change",
                            f"migration {path} in {c['sha'][:8]}: dropped={dropped} created={created}",
                            {**ctx, "dropped_indexes": dropped, "created_indexes": created}, src, d["deployed_at"]))
                        change_evidence += 1

        for frame in task.params.get("frames", []):
            rev = f"deploy/{service}/v{frame['version']}" if frame.get("version") else "HEAD"
            try:
                blame = await gw.call("git.git_blame", path=frame["file"], line=int(frame["line"]), rev=rev)
            except ToolError as exc:
                notes.append(f"blame failed for {frame}: {exc}")
                continue
            when = datetime.fromtimestamp(int(blame["author_time"]), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            evidence.append(self.evidence(
                task, "blame",
                f"{frame['file']}:{frame['line']} (v{frame.get('version')}) last changed by {blame['commit'][:8]} "
                f"'{blame['summary']}' on {when}: {blame['text'].strip()[:80]}",
                {"file": frame["file"], "line": frame["line"], "rev": rev, "commit": blame["commit"],
                 "summary": blame["summary"], "authored_at": when, "text": blame["text"],
                 "recent": blame["commit"] in recent_commits,
                 "minutes_before_onset": round(minutes_between(when, onset), 1)},
                {"tool": "git.git_blame", "args": {"path": frame["file"], "line": frame["line"], "rev": rev}}, when))

        if change_evidence == 0:
            evidence.append(self.evidence(
                task, "no_recent_change",
                f"No functional config, code or schema change to {service} in the 24h before {onset}",
                {"service": service, "window_start": window_start, "onset": onset},
                {"tool": "git.git_log", "args": {"service": service}}))
        n_deploys = sum(e.kind == "deploy" for e in evidence)
        summary = (f"{n_deploys} deploys in window, {change_evidence} functional changes, "
                   f"{sum(e.kind == 'blame' for e in evidence)} blamed frames")
        return AgentResult(task_id=task.task_id, agent=self.name, summary=summary, evidence=evidence, notes=notes)

    async def resolve_service(self, task: AgentTask, gw: ToolGateway) -> AgentResult:
        """Map an endpoint or keyword from the report to the owning service via its config."""
        candidates = []
        if task.params.get("endpoint"):
            res = await gw.call("git.search_repository", pattern=rf"endpoint: {re.escape(task.params['endpoint'])}$",
                                path_glob="services/*/config.yaml")
            candidates = [m["file"] for m in res["matches"]]
        for word in task.params.get("keywords", []):
            if candidates:
                break
            res = await gw.call("git.search_repository", pattern=rf"^service: .*{re.escape(word)}",
                                path_glob="services/*/config.yaml")
            candidates = [m["file"] for m in res["matches"]]
        if not candidates:
            return AgentResult(task_id=task.task_id, agent=self.name, status="no_data",
                               summary="could not map the report to a service")
        cfg = yaml.safe_load((await gw.call("git.read_file", path=candidates[0]))["content"])
        return AgentResult(task_id=task.task_id, agent=self.name,
                           summary=f"{task.params.get('endpoint') or task.params.get('keywords')} is served by "
                                   f"{cfg['service']} ({candidates[0]})",
                           data={"service": cfg["service"], "config": candidates[0]})

    async def _config_changes(self, task, gw, path, sha, ctx, src):
        try:
            old = yaml.safe_load((await gw.call("git.show_file_at", path=path, rev=f"{sha}^"))["content"])
        except ToolError:
            old = {}
        new = yaml.safe_load((await gw.call("git.show_file_at", path=path, rev=sha))["content"])
        fo, fn = flatten(old), flatten(new)
        out = []
        for key in sorted(set(fo) | set(fn)):
            if key in ("version",) or fo.get(key) == fn.get(key):
                continue
            d = direction(fo.get(key), fn.get(key))
            out.append(self.evidence(
                task, "config_change",
                f"{path}: {key} {fo.get(key)} -> {fn.get(key)} ({d}) in {sha[:8]} '{ctx['subject'][:60]}'",
                {**ctx, "key": key, "old": fo.get(key), "new": fn.get(key), "direction": d}, src, ctx["deployed_at"]))
        return out
