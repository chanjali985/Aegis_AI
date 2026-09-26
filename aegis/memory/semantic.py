"""Semantic memory: the catalogue of known failure patterns and how to recognise them.

Each pattern lists evidence rules with log-likelihood-ratio style weights:
positive rules support the pattern, negative rules contradict it. The RCA agent
sums matched weights (plus an episodic-memory prior) and normalises across
patterns - so confidence comes from an explicit evidence model, never from an
LLM asserting a number.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


class EvidenceIndex:
    def __init__(self, evidence: list[dict]):
        self.items = evidence

    def of(self, kind: str, **match) -> list[dict]:
        out = []
        for e in self.items:
            if e["kind"] != kind:
                continue
            if all(e["data"].get(k) == v for k, v in match.items()):
                out.append(e)
        return out

    def spikes(self, *types: str) -> list[dict]:
        return [e for e in self.of("error_spike") if not types or e["data"]["error_type"] in types]

    def metric(self, name: str, direction: str) -> list[dict]:
        return [e for e in self.of("metric_shift", metric=name) if e["data"]["direction"] == direction]

    def config(self, key: str, *directions: str, window=(-5, 360)) -> list[dict]:
        return [e for e in self.of("config_change", key=key)
                if e["data"]["direction"] in directions
                and window[0] <= e["data"]["minutes_before_onset"] <= window[1]]


def ids(items: list[dict]) -> list[str]:
    return [e["id"] for e in items]


Rule = Callable[[EvidenceIndex, dict], list[str]]


@dataclass
class RuleSpec:
    name: str
    weight: float
    fn: Rule


@dataclass
class Pattern:
    id: str
    title: str
    category: str
    fix_kind: str
    rules: list[RuleSpec] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)
    prior: float = 0.0

    def culprit(self, E: EvidenceIndex, ctx: dict, matched: dict[str, list[str]]) -> dict:
        return CULPRITS.get(self.id, lambda E, ctx, m: {})(E, ctx, matched)


# -- helpers for rules ----------------------------------------------------------
def _doc_mismatch(key: str, op: str):
    def fn(E, ctx):
        changes = E.config(key, "decreased", "increased", "removed", window=(0, 720))
        out = []
        for d in E.of("doc_expectation", key=key):
            exp = d["data"]["expected"]
            for c in changes:
                new = c["data"]["new"]
                if isinstance(exp, int) and isinstance(new, (int, float)):
                    if (op == "lt" and new < exp) or (op == "gt" and new > exp):
                        out += [d["id"], c["id"]]
                elif new is None:
                    out += [d["id"], c["id"]]
        return out
    return fn


def _spike_param_matches(param: str, key: str):
    def fn(E, ctx):
        out = []
        for s in E.spikes():
            v = s["data"].get(param)
            if v is None:
                continue
            for c in E.of("config_change", key=key):
                if c["data"]["new"] == v:
                    out += [s["id"], c["id"]]
        return out
    return fn


def _runbook(pattern: str):
    def fn(E, ctx):
        return [e["id"] for e in E.of("runbook") if pattern in e["data"].get("patterns", [])
                and e["data"].get("rank") == 1]
    return fn


def _functional_deploy(max_minutes: float):
    def fn(E, ctx):
        functional = {e["data"]["commit"] for e in E.of("migration_change")}
        functional |= {e["data"]["commit"] for e in E.of("config_change")
                       if not e["data"]["key"].startswith("observability.")}
        functional |= {e["data"]["commit"] for e in E.of("code_change")
                       if "comment_or_text_only" not in e["data"]["risks"]}
        return [d["id"] for d in E.of("deploy") if -5 <= d["data"]["minutes_before_onset"] <= max_minutes
                and any(c["sha"] in functional for c in d["data"]["commits"])]
    return fn


def _code_risk_on_stack(E, ctx):
    out = []
    frames = {(s["data"]["frame"] or {}).get("file") for s in E.spikes() if s["data"].get("frame")}
    for c in E.of("code_change"):
        if c["data"]["file"] in frames and ({"removed_default", "direct_subscript"} & set(c["data"]["risks"])):
            if -5 <= c["data"]["minutes_before_onset"] <= 720:
                out.append(c["id"])
    return out


def _blame_recent(E, ctx):
    changes = {c["data"]["commit"] for c in E.of("code_change")}
    return [b["id"] for b in E.of("blame") if b["data"]["recent"] and b["data"]["commit"] in changes]


def _blame_old(E, ctx):
    return [b["id"] for b in E.of("blame") if not b["data"]["recent"]]


def _python_exception_in_handler(E, ctx):
    return [s["id"] for s in E.spikes() if s["data"].get("frame") and "/features/" not in
            (s["data"]["frame"] or {}).get("file", "") and s["data"]["error_type"] not in ("ValidationError",)]


def _feature_exception(E, ctx):
    return [s["id"] for s in E.spikes() if s["data"].get("feature_path")]


def _flag_enabled_before(E, ctx):
    out = []
    for f in E.of("flag_change"):
        d = f["data"]
        if d.get("service") == ctx.get("service") and d.get("new_value") == 1 and -5 <= d["minutes_before_onset"] <= 90:
            out.append(f["id"])
    return out


def _flag_matches_stack(E, ctx):
    out = []
    for s in E.spikes():
        path = s["data"].get("feature_path") or ""
        for f in E.of("flag_change"):
            if f["data"].get("new_value") == 1 and f["data"]["flag"] in path:
                out += [s["id"], f["id"]]
    return out


def _dependency_unhealthy_near_onset(E, ctx):
    return [d["id"] for d in E.of("dependency_status", healthy=False)
            if -30 <= d["data"]["minutes_before_onset"] <= 60]


def _dependency_healthy(E, ctx):
    return ids(E.of("dependency_status", healthy=True))


def _dependency_unhealthy(E, ctx):
    return ids(E.of("dependency_status", healthy=False))


def _cert_expired_near_onset(E, ctx):
    return [c["id"] for c in E.of("certificate") if c["data"]["expired_at_onset"]
            and -5 <= c["data"]["minutes_before_onset"] <= 120]


def _cert_host_matches(E, ctx):
    out = []
    for s in E.spikes("SSLError"):
        for c in E.of("certificate"):
            if c["data"]["host"] == s["data"].get("host") and c["data"]["expired_at_onset"]:
                out += [s["id"], c["id"]]
    return out


def _many_attempts(E, ctx):
    return [s["id"] for s in E.spikes("UpstreamTimeout") if (s["data"].get("attempts") or 0) > 4]


def _no_recent_change(E, ctx):
    return ids(E.of("no_recent_change"))


def _dropped_index(E, ctx):
    return [m["id"] for m in E.of("migration_change") if m["data"]["dropped_indexes"]
            and -5 <= m["data"]["minutes_before_onset"] <= 720]


def _any_spike(E, ctx):
    return ids(E.spikes()[:1]) or ids(E.of("metric_anomaly")[:1])


def R(name, weight, fn) -> RuleSpec:
    return RuleSpec(name, weight, fn)


PATTERNS: list[Pattern] = [
    Pattern("db_timeout_reduced", "Database client timeout reduced below real query latency", "config",
            "config_revert", [
                R("DatabaseTimeoutError spike", 2.0, lambda E, c: ids(E.spikes("DatabaseTimeoutError"))),
                R("db.timeout_ms decreased shortly before onset", 3.0,
                  lambda E, c: ids(E.config("db.timeout_ms", "decreased"))),
                R("timeout in error message equals new config value", 1.5,
                  _spike_param_matches("timeout_ms", "db.timeout_ms")),
                R("database latency unchanged", 1.0, lambda E, c: ids(E.metric("db_latency_p95_ms", "flat"))),
                R("new value violates documented invariant", 1.0, _doc_mismatch("db.timeout_ms", "lt")),
                R("runbook match", 0.5, _runbook("db_timeout_reduced")),
                R("database latency increased (points elsewhere)", -2.5,
                  lambda E, c: ids(E.metric("db_latency_p95_ms", "up"))),
                R("query latency regression (points elsewhere)", -1.5, lambda E, c: ids(E.of("query_regression"))),
            ], ["replay incident traffic with db.timeout_ms restored", "temporal precedence",
                "database latency stable"]),
    Pattern("missing_index", "Schema migration dropped an index used by a hot query", "schema", "migration", [
        R("SlowQuery / DatabaseTimeoutError spike", 1.5,
          lambda E, c: ids(E.spikes("SlowQuery", "DatabaseTimeoutError"))),
        R("database latency increased", 2.0, lambda E, c: ids(E.metric("db_latency_p95_ms", "up"))),
        R("migration dropped an index before onset", 3.0, _dropped_index),
        R("hot query latency regressed", 2.0, lambda E, c: ids(E.of("query_regression"))),
        R("runbook match", 0.5, _runbook("missing_index")),
        R("database latency unchanged (points elsewhere)", -1.5,
          lambda E, c: ids(E.metric("db_latency_p95_ms", "flat"))),
    ], ["replay incident traffic with the index restored", "query stats regression"]),
    Pattern("pool_size_reduced", "Connection pool shrunk below peak concurrency", "config", "config_revert", [
        R("ConnectionPoolExhausted spike", 2.5, lambda E, c: ids(E.spikes("ConnectionPoolExhausted"))),
        R("db.pool_size decreased shortly before onset", 3.0,
          lambda E, c: ids(E.config("db.pool_size", "decreased"))),
        R("pool size in error equals new config value", 1.0, _spike_param_matches("pool_size", "db.pool_size")),
        R("pool saturated after onset", 1.5, lambda E, c: ids(E.of("pool_saturation"))),
        R("pool wait time rose", 1.0, lambda E, c: ids(E.metric("db_pool_waiting", "up"))),
        R("new value violates documented invariant", 0.5, _doc_mismatch("db.pool_size", "lt")),
    ], ["replay incident traffic with db.pool_size restored"]),
    Pattern("code_missing_field", "Handler change dereferences an optional request field", "code", "code_revert", [
        R("unhandled exception in handler", 2.0, _python_exception_in_handler),
        R("recent change removed a default on the failing line's file", 3.0, _code_risk_on_stack),
        R("blamed line changed by a recent commit", 2.0, _blame_recent),
        R("blamed line is old (points elsewhere)", -1.0, _blame_old),
        R("exception raised inside a feature-flag path (points elsewhere)", -1.5, _feature_exception),
    ], ["replay incident traffic with the handler change reverted", "legacy-payload regression test"]),
    Pattern("rate_limit_reduced", "Edge rate limit set below real traffic", "config", "config_revert", [
        R("RateLimitExceeded spike", 2.5, lambda E, c: ids(E.spikes("RateLimitExceeded"))),
        R("http.rate_limit_rps decreased shortly before onset", 3.0,
          lambda E, c: ids(E.config("http.rate_limit_rps", "decreased"))),
        R("limit in error equals new config value", 1.0, _spike_param_matches("rate_limit", "http.rate_limit_rps")),
        R("traffic volume unchanged", 1.0, lambda E, c: ids(E.metric("http_rps", "flat"))),
        R("new value violates documented invariant", 0.5, _doc_mismatch("http.rate_limit_rps", "lt")),
        R("organic traffic surge (points elsewhere)", -1.5, lambda E, c: ids(E.metric("http_rps", "up"))),
    ], ["replay incident traffic with the rate limit restored"]),
    Pattern("cache_unbounded", "In-process cache left unbounded (memory growth, OOM)", "config", "config_revert", [
        R("OOMKilled / restart errors", 2.0, lambda E, c: ids(E.spikes("OOMKilled", "ServiceUnavailable"))),
        R("saw-tooth memory with OOM restarts", 2.0, lambda E, c: ids(E.of("memory_sawtooth"))),
        R("cache.max_entries removed/increased before onset", 3.0,
          lambda E, c: ids(E.config("cache.max_entries", "removed", "increased"))),
        R("documented cache bound violated", 0.5, _doc_mismatch("cache.max_entries", "gt")),
    ], ["replay incident traffic with the cache bound restored"]),
    Pattern("upstream_outage", "Third-party dependency outage", "external", "ops_action", [
        R("UpstreamError spike", 2.5, lambda E, c: ids(E.spikes("UpstreamError"))),
        R("dependency reported unhealthy at onset", 3.5, _dependency_unhealthy_near_onset),
        R("upstream error rate rose", 1.0, lambda E, c: ids(E.metric("upstream_error_rate", "up"))),
        R("no functional change to the service", 0.5, _no_recent_change),
        R("dependency reported healthy (points elsewhere)", -2.5, _dependency_healthy),
        R("retry policy changed (points elsewhere)", -1.0,
          lambda E, c: ids(E.config("upstream.max_retries", "increased"))),
    ], ["replay incident traffic with the fallback path enabled", "dependency status timeline"]),
    Pattern("flag_enabled", "Feature flag enabled an untested code path", "ops", "ops_action", [
        R("exception raised inside a feature-flag code path", 2.0, _feature_exception),
        R("service flag enabled shortly before onset", 3.5, _flag_enabled_before),
        R("enabled flag matches the failing module", 1.0, _flag_matches_stack),
        R("no functional change to the service", 0.5, _no_recent_change),
    ], ["replay incident traffic with the flag disabled"]),
    Pattern("cert_expired", "mTLS certificate expired", "ops", "ops_action", [
        R("SSLError spike", 2.5, lambda E, c: ids(E.spikes("SSLError"))),
        R("certificate expired at onset", 3.5, _cert_expired_near_onset),
        R("expired certificate host matches failing host", 1.0, _cert_host_matches),
    ], ["replay incident traffic with a renewed certificate"]),
    Pattern("retry_storm", "Aggressive retries without backoff amplify upstream load", "config", "config_revert", [
        R("UpstreamTimeout spike", 2.0, lambda E, c: ids(E.spikes("UpstreamTimeout"))),
        R("upstream.max_retries increased before onset", 2.0,
          lambda E, c: ids(E.config("upstream.max_retries", "increased"))),
        R("upstream.backoff_ms reduced before onset", 1.5,
          lambda E, c: ids(E.config("upstream.backoff_ms", "decreased"))),
        R("upstream request amplification rose", 2.0,
          lambda E, c: ids(E.metric("upstream_amplification", "up"))),
        R("high retry attempt counts in errors", 1.0, _many_attempts),
        R("dependency itself healthy", 1.0, _dependency_healthy),
        R("dependency unhealthy (points elsewhere)", -2.0, _dependency_unhealthy),
    ], ["replay incident traffic with the retry policy restored"]),
    Pattern("bad_deploy_generic", "Recent deploy introduced an unclassified regression", "code", "rollback", [
        R("error spike", 1.0, _any_spike),
        R("functional change deployed within 2h before onset", 2.0, _functional_deploy(120)),
    ], ["replay incident traffic on the previous release"], prior=-0.5),
]
PATTERN_BY_ID = {p.id: p for p in PATTERNS}
NULL_SCORE = 2.5  # the "none of the above / insufficient evidence" hypothesis


# -- culprit extraction -------------------------------------------------------------
def _config_culprit(keys):
    def fn(E, ctx, matched):
        changes = [c for k in keys for c in E.of("config_change", key=k)]
        changes = [c for c in changes if -5 <= c["data"]["minutes_before_onset"] <= 720]
        if not changes:
            return {}
        c = max(changes, key=lambda c: c["data"]["deployed_at"])
        return {"type": "commit", "commit": c["data"]["commit"], "version": c["data"]["version"],
                "file": c["data"]["file"], "subject": c["data"]["subject"], "author": c["data"]["author"],
                "keys": sorted({x["data"]["key"] for x in changes if x["data"]["commit"] == c["data"]["commit"]}),
                "changes": [{"key": x["data"]["key"], "old": x["data"]["old"], "new": x["data"]["new"]}
                            for x in changes if x["data"]["commit"] == c["data"]["commit"]],
                "deployed_at": c["data"]["deployed_at"]}
    return fn


def _code_culprit(E, ctx, matched):
    for eid in matched.get("recent change removed a default on the failing line's file", []):
        c = next(e for e in E.items if e["id"] == eid)
        return {"type": "commit", "commit": c["data"]["commit"], "version": c["data"]["version"],
                "file": c["data"]["file"], "subject": c["data"]["subject"], "author": c["data"]["author"],
                "deployed_at": c["data"]["deployed_at"]}
    for b in E.of("blame"):
        if b["data"]["recent"]:
            return {"type": "commit", "commit": b["data"]["commit"], "file": b["data"]["file"],
                    "subject": b["data"]["summary"]}
    return {}


def _index_culprit(E, ctx, matched):
    for m in E.of("migration_change"):
        if m["data"]["dropped_indexes"]:
            return {"type": "commit", "commit": m["data"]["commit"], "version": m["data"]["version"],
                    "file": m["data"]["file"], "subject": m["data"]["subject"],
                    "indexes": m["data"]["dropped_indexes"], "deployed_at": m["data"]["deployed_at"]}
    return {}


def _dep_culprit(E, ctx, matched):
    for d in E.of("dependency_status", healthy=False):
        return {"type": "dependency", "id": d["data"]["dependency"], "since": d["data"]["first_bad_at"]}
    return {}


def _flag_culprit(E, ctx, matched):
    for f in E.of("flag_change"):
        if f["data"].get("service") == ctx.get("service") and f["data"].get("new_value") == 1:
            return {"type": "flag", "id": f["data"]["flag"], "changed_at": f["data"]["changed_at"],
                    "changed_by": f["data"]["changed_by"]}
    return {}


def _cert_culprit(E, ctx, matched):
    for c in E.of("certificate"):
        if c["data"]["expired_at_onset"]:
            return {"type": "certificate", "id": c["data"]["host"], "expires_at": c["data"]["expires_at"]}
    return {}


def _deploy_culprit(E, ctx, matched):
    for eid in matched.get("functional change deployed within 2h before onset", []):
        d = next(e for e in E.items if e["id"] == eid)
        return {"type": "deploy", "commit": d["data"]["commit"], "version": d["data"]["version"],
                "tag": d["data"]["tag"], "deployed_at": d["data"]["deployed_at"]}
    return {}


CULPRITS = {
    "db_timeout_reduced": _config_culprit(["db.timeout_ms"]),
    "pool_size_reduced": _config_culprit(["db.pool_size"]),
    "rate_limit_reduced": _config_culprit(["http.rate_limit_rps"]),
    "cache_unbounded": _config_culprit(["cache.max_entries"]),
    "retry_storm": _config_culprit(["upstream.max_retries", "upstream.backoff_ms"]),
    "code_missing_field": _code_culprit,
    "missing_index": _index_culprit,
    "upstream_outage": _dep_culprit,
    "flag_enabled": _flag_culprit,
    "cert_expired": _cert_culprit,
    "bad_deploy_generic": _deploy_culprit,
}
