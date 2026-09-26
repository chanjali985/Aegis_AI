"""Verification agent: adversarial checks that try to prove the hypothesis (or fix) wrong.

For a hypothesis it checks temporal precedence, contradicting evidence, how
clearly it beats the alternatives, and - the decisive test - a counterfactual
replay: recorded incident traffic is replayed in a sandbox against the
deployed code, then again with the suspected cause removed. The hypothesis is
only *verified* if the failure reproduces and then disappears.

For a fix it re-runs the reproduction test and the full suite in a fresh
sandbox (never trusting the fix agent's own report), scans the patch for
secrets and checks it only touches allowed paths.
"""
from __future__ import annotations

import asyncio
import math
from pathlib import Path

from aegis.agents.base import Agent
from aegis.agents.models import AgentResult, AgentTask, Check, VerificationReport
from aegis.config import get_settings
from aegis.sandbox.executor import Sandbox, SandboxError
from aegis.security.pii import scan_secrets
from aegis.tools.gateway import ToolGateway
from aegis.util import minutes_between, shift

REQUEST_FOR = {
    "database": ["dependency_status", "flag_changes", "certificates", "query_stats", "pool_stats"],
}


def culprit_time(culprit: dict) -> str | None:
    return culprit.get("deployed_at") or culprit.get("changed_at") or culprit.get("since") or culprit.get("expires_at")


def signatures(evidence: list[dict]) -> list[str]:
    return sorted({e["data"]["error_type"] for e in evidence if e["kind"] == "error_spike"})


def signature_rate(report: dict, sigs: list[str]) -> float:
    """Share of replayed requests failing with the incident's own error signatures."""
    n = max(1, report["requests"])
    if not sigs:
        return report["failed"] / n
    return sum(report["errors_by_type"].get(s, 0) for s in sigs) / n


def tolerance(rate: float, n: int, sigs: list[str]) -> float:
    """Allowed excess failure rate: a floor plus ~3 standard deviations of binomial noise."""
    n = max(1, n)
    return max(0.005 if sigs else 0.01, 3 * math.sqrt(max(rate, 1 / n) / n))


def replay_verdict(head: dict, fixed: dict, pre: dict, sigs: list[str]) -> tuple[bool, bool, dict]:
    """Did the incident reproduce on the deployed revision, and disappear once the cause is removed?

    Judged on the incident's own error signatures so unrelated background errors cannot mask
    (or fake) a reproduction. Without signatures (logs lost) the total error rate is used.
    """
    rh, rf, rp = (signature_rate(r, sigs) for r in (head, fixed, pre))
    tol = tolerance(rp, pre["requests"], sigs)
    reproduced = rh >= 2 * rp + tol and rh * head["requests"] >= 3
    resolved = rf <= rp + tol or rf <= 0.1 * rh
    return reproduced, resolved, {"signature_rate_head": round(rh, 4), "signature_rate_fixed": round(rf, 4),
                                  "signature_rate_pre": round(rp, 4), "signatures": sigs}


async def incident_traffic(gw: ToolGateway, service: str, onset: str) -> tuple[list, list]:
    inc = await gw.call("observability.export_traffic_sample", service=service, start=onset,
                        end=shift(onset, 100), limit=600)
    pre = await gw.call("observability.export_traffic_sample", service=service, start=shift(onset, -150),
                        end=shift(onset, -30), limit=600)
    return inc["traffic"], pre["traffic"]


def runtime_for(hyp: dict, evidence: list[dict], service: str) -> tuple[dict, dict]:
    """(runtime reproducing the incident, runtime with the ops remediation applied)."""
    culprit = hyp.get("culprit") or {}
    pkg = service.replace("-", "_")
    certs = {e["data"]["host"]: e["data"]["expires_at"] for e in evidence
             if e["kind"] == "certificate" and e["data"].get("expired_at_onset")}
    incident_rt = {"cert_expires_at": certs} if certs else {}
    if culprit.get("type") == "certificate":
        return incident_rt, {}
    if culprit.get("type") == "flag":
        return incident_rt, {**incident_rt, "flags": {culprit["id"]: False}}
    if culprit.get("type") == "dependency":
        return incident_rt, {**incident_rt, "flags": {f"{pkg}_gateway_fallback": True}}
    return incident_rt, incident_rt


class VerificationAgent(Agent):
    name = "verification"
    title = "Verification Agent"
    description = "Adversarially tests hypotheses and fixes with counterfactual replays in a sandbox."
    skills = [
        {"id": "verify-hypothesis", "name": "Verify hypothesis",
         "description": "Temporal, contradiction, margin and counterfactual-replay checks.",
         "tags": ["verification", "reflection", "sandbox"]},
        {"id": "verify-fix", "name": "Verify fix",
         "description": "Independent test run, secret scan and path policy for a proposed patch.",
         "tags": ["verification", "tests", "security"]},
    ]

    async def execute(self, task: AgentTask, gw: ToolGateway) -> AgentResult:
        if task.params.get("mode") == "fix":
            report = await self.verify_fix(task, gw)
        else:
            report = await self.verify_hypothesis(task, gw)
        return AgentResult(task_id=task.task_id, agent=self.name, summary=report.summary,
                           data={"report": report.model_dump()})

    # ------------------------------------------------------------------------------
    async def verify_hypothesis(self, task: AgentTask, gw: ToolGateway) -> VerificationReport:
        hyp, evidence = task.params["hypothesis"], task.params["evidence"]
        onset, service = task.params["onset"], task.incident.service
        margin = task.params.get("margin", 1.0)
        culprit = hyp.get("culprit") or {}
        checks: list[Check] = []

        if hyp["pattern"] == "unknown":
            return VerificationReport(target=hyp["id"], verdict="inconclusive", checks=[],
                                      requested_evidence=self._requests(task), summary="no hypothesis to verify")

        t = culprit_time(culprit)
        if t:
            lead = minutes_between(t, onset)
            ok = lead >= -5 if culprit.get("type") != "dependency" else -30 <= lead <= 60
            checks.append(Check(name="temporal_precedence", passed=ok,
                                detail=f"cause at {t}, onset at {onset} ({lead:+.0f} min lead)"))
        else:
            checks.append(Check(name="temporal_precedence", passed=None, detail="culprit time unknown"))

        contra = sum(c["weight"] for c in hyp.get("contradicting", []))
        checks.append(Check(name="contradicting_evidence", passed=contra > -2.0,
                            detail=f"total contradicting weight {contra:.1f}: "
                                   + (", ".join(c["rule"] for c in hyp.get("contradicting", [])) or "none")))
        checks.append(Check(name="beats_alternatives", passed=margin >= 0.2,
                            detail=f"confidence margin over next hypothesis {margin:.2f}"))

        replay = await self._counterfactual(task, gw, hyp, evidence, service, onset)
        checks.append(replay)

        failed = [c for c in checks if c.passed is False]
        hard_fail = [c for c in failed if c.name in ("temporal_precedence", "counterfactual_replay",
                                                     "contradicting_evidence")]
        if hard_fail:
            verdict = "refuted"
        elif replay.passed:
            verdict = "verified"
        elif failed or hyp["confidence"] < get_settings().confidence_threshold:
            verdict = "inconclusive"
        else:
            verdict = "verified" if replay.passed is None and hyp["confidence"] >= 0.9 else "inconclusive"
        summary = f"{hyp['title']}: {verdict} (" + ", ".join(
            f"{c.name}={'pass' if c.passed else 'fail' if c.passed is False else 'n/a'}" for c in checks) + ")"
        return VerificationReport(target=hyp["id"], verdict=verdict, checks=checks, summary=summary,
                                  requested_evidence=self._requests(task) if verdict == "inconclusive" else [])

    async def _counterfactual(self, task, gw, hyp, evidence, service, onset) -> Check:
        culprit = hyp.get("culprit") or {}
        if not culprit:
            return Check(name="counterfactual_replay", passed=None, detail="no concrete culprit to remove")
        repo = Path(task.workspace) / "repo"
        deploys = (await gw.call("git.list_deploys", service=service))["deploys"]
        running = [d for d in deploys if d["deployed_at"] <= shift(onset, 100)][-1]
        traffic, pre = await incident_traffic(gw, service, onset)
        if len(traffic) < 50:
            return Check(name="counterfactual_replay", passed=None, detail="not enough recorded traffic")
        rt_incident, rt_fixed = runtime_for(hyp, evidence, service)

        def run() -> dict:
            timeout = get_settings().sandbox_timeout_s
            with Sandbox(repo, running["tag"], timeout, agent=self.name) as sbx:
                e_head = sbx.replay(service, traffic, rt_incident)
                if culprit.get("type") in ("commit", "deploy"):
                    if culprit.get("type") == "deploy":
                        prev = [d for d in deploys if d["deployed_at"] < culprit["deployed_at"]][-1]
                        sbx._git(sbx.path, "checkout", "-q", prev["tag"])
                    else:
                        sbx.revert_commit(culprit["commit"])
                    e_fix = sbx.replay(service, traffic, rt_incident)
                    e_pre = sbx.replay(service, pre, rt_incident)
                else:
                    e_fix = sbx.replay(service, traffic, rt_fixed)
                    e_pre = sbx.replay(service, pre, rt_fixed)
            return {"head": e_head, "fixed": e_fix, "pre": e_pre}

        try:
            r = await asyncio.to_thread(run)
        except SandboxError as exc:
            return Check(name="counterfactual_replay", passed=None, detail=f"sandbox error: {exc}")
        sigs = signatures(evidence)
        reproduced, fixed, rates = replay_verdict(r["head"], r["fixed"], r["pre"], sigs)
        action = "reverting " + culprit.get("commit", "")[:8] if culprit.get("type") == "commit" else \
            f"remediating {culprit.get('type')} {culprit.get('id', culprit.get('version', ''))}"
        what = "/".join(sigs) if sigs else "all errors"
        detail = (f"replayed {len(traffic)} recorded requests on {running['tag']}: {what} rate "
                  f"{rates['signature_rate_head']:.1%} as deployed -> {rates['signature_rate_fixed']:.1%} after "
                  f"{action} (pre-incident {rates['signature_rate_pre']:.1%}); "
                  f"reproduced={reproduced}, resolved={fixed}")
        return Check(name="counterfactual_replay", passed=reproduced and fixed, detail=detail,
                     data={**r, **rates, "reproduced": reproduced, "resolved": fixed, "requests": len(traffic)})

    def _requests(self, task: AgentTask) -> list[dict]:
        return [{"agent": "database", "questions": REQUEST_FOR["database"]},
                {"agent": "code", "reason": "blame and full change history"},
                {"agent": "research", "focus": "runbooks"}]

    # ------------------------------------------------------------------------------
    async def verify_fix(self, task: AgentTask, gw: ToolGateway) -> VerificationReport:
        fix = task.params["fix"]
        service = task.incident.service
        pkg = service.replace("-", "_")
        checks: list[Check] = []
        if fix["kind"] == "ops_action":
            repl = fix.get("replay") or {}
            checks.append(Check(name="remediation_replay", passed=bool(repl.get("resolved")),
                                detail=repl.get("detail", "no replay available")))
            allowed = {"ops.set_feature_flag", "ops.rotate_certificate"}
            bad = [a for a in fix.get("actions", []) if a["tool"] not in allowed]
            checks.append(Check(name="action_policy", passed=not bad,
                                detail="actions limited to approved control-plane tools" if not bad else f"{bad}"))
            verdict = "verified" if all(c.passed for c in checks) else "refuted"
            return VerificationReport(target="fix", verdict=verdict, checks=checks,
                                      summary=f"ops remediation {verdict}")
        if not fix.get("patch"):
            return VerificationReport(target="fix", verdict="refuted",
                                      checks=[Check(name="patch_present", passed=False, detail="no patch")],
                                      summary="no patch to verify")
        patch = fix["patch"]
        repo = Path(task.workspace) / "repo"

        def run() -> dict:
            with Sandbox(repo, "HEAD", get_settings().sandbox_timeout_s, agent=self.name) as sbx:
                sbx.apply_patch(patch)
                files = sbx.changed_files()
                suite = sbx.pytest("tests")
                repro = sbx.pytest(fix["repro_test"]) if fix.get("repro_test") else None
                compile_errors = sbx.compile_check(files)
            before = None
            if fix.get("repro_test") and fix.get("test_files"):
                # the reproduction test alone (without the fix) must fail on current HEAD
                with Sandbox(repo, "HEAD", get_settings().sandbox_timeout_s, agent=self.name) as sbx:
                    for rel, content in fix["test_files"].items():
                        sbx.write(rel, content)
                    before = sbx.pytest(fix["repro_test"])
            return {"files": files, "suite": suite, "repro": repro, "before": before, "compile": compile_errors}

        try:
            r = await asyncio.to_thread(run)
        except SandboxError as exc:
            return VerificationReport(target="fix", verdict="refuted",
                                      checks=[Check(name="apply_patch", passed=False, detail=str(exc))],
                                      summary=f"patch could not be applied: {exc}")
        checks.append(Check(name="patch_applies", passed=True, detail=f"{len(r['files'])} files changed"))
        checks.append(Check(name="test_suite", passed=r["suite"]["ok"],
                            detail=f"{r['suite']['passed']} passed, {r['suite']['failed']} failed"))
        if r["repro"] is not None:
            checks.append(Check(name="reproduction_test_passes_with_fix", passed=r["repro"]["ok"],
                                detail=f"{fix['repro_test']}: {'pass' if r['repro']['ok'] else 'fail'}"))
        if r["before"] is not None:
            checks.append(Check(name="reproduction_test_fails_without_fix", passed=not r["before"]["ok"],
                                detail="the new test catches the incident on current HEAD" if not r["before"]["ok"]
                                else "test passes without the fix - it does not capture the failure"))
        checks.append(Check(name="static_checks", passed=not r["compile"],
                            detail="py_compile / YAML parse clean" if not r["compile"] else "; ".join(r["compile"])))
        secrets = scan_secrets("\n".join(l for l in patch.splitlines() if l.startswith("+")))
        checks.append(Check(name="secret_scan", passed=not secrets,
                            detail="no secrets in added lines" if not secrets else f"found {secrets}"))
        allowed = (f"services/{pkg}/", "migrations/", "tests/")
        outside = [f for f in r["files"] if not f.startswith(allowed)]
        checks.append(Check(name="path_policy", passed=not outside,
                            detail="changes confined to the service, migrations and tests" if not outside
                            else f"unexpected paths: {outside}"))
        verdict = "verified" if all(c.passed for c in checks) else "refuted"
        return VerificationReport(target="fix", verdict=verdict, checks=checks,
                                  summary=f"fix {verdict}: " + ", ".join(
                                      f"{c.name}={'pass' if c.passed else 'fail'}" for c in checks))
