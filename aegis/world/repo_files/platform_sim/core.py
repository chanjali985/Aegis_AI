"""Deterministic traffic replay engine for the ACME platform.

Given a service's deployed configuration, handler code, schema indexes and
runtime state (feature flags, certificates), replay recorded request samples
and compute the outcome of every request. The same engine produces the
telemetry the platform emits and powers reproduction tests in CI, so a replay
of recorded traffic against a candidate fix is a faithful counterfactual.
"""
from __future__ import annotations

import hashlib
import traceback
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Callable

UPSTREAM_TIMEOUT_MS = 2000
MEMORY_LIMIT_MB = 2048
BASE_MEMORY_MB = 600
CACHE_ENTRY_MB = 0.08
UNBOUNDED_GROWTH_MB_PER_SAMPLE = 3.0
RESTART_SAMPLES = 12
SLOW_QUERY_MS = 2000
FULL_SCAN_MS_PER_ROW = 0.01


class ValidationError(Exception):
    """Client error (HTTP 400)."""


def unit(req_id: str, salt: str) -> float:
    """Stable pseudo-random number in [0, 1) derived from a request id."""
    digest = hashlib.sha256(f"{req_id}:{salt}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def load_source(source: str, relpath: str) -> ModuleType:
    """Execute module source under its repository-relative filename.

    Tracebacks raised from the module report ``relpath`` and real line numbers,
    exactly as they would in production logs.
    """
    module = ModuleType(relpath.replace("/", ".").removesuffix(".py"))
    module.__file__ = relpath
    exec(compile(source, relpath, "exec"), module.__dict__)
    return module


class Ctx:
    def __init__(self, flags: dict[str, bool], features: dict[str, ModuleType]):
        self.flags = flags or {}
        self._features = features
        self.ValidationError = ValidationError

    def flag(self, name: str) -> bool:
        return bool(self.flags.get(name))

    def feature(self, name: str) -> ModuleType:
        return self._features[name]

    @staticmethod
    def respond(status: int, body: dict) -> dict:
        return {"status": status, "body": body}


@dataclass
class Outcome:
    status: int
    error_type: str | None = None
    message: str | None = None
    stack: list[dict] = field(default_factory=list)
    db_ms: float = 0.0
    upstream_ms: float | None = None
    upstream_attempts: int = 0
    warnings: list[str] = field(default_factory=list)
    memory_mb: float = 0.0

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "error_type": self.error_type,
            "message": self.message,
            "stack": self.stack,
            "db_ms": round(self.db_ms, 1),
            "upstream_ms": None if self.upstream_ms is None else round(self.upstream_ms, 1),
            "warnings": self.warnings,
            "memory_mb": round(self.memory_mb, 1),
        }


def _get(cfg: dict, dotted: str, default: Any = None) -> Any:
    node: Any = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


class ServiceModel:
    """One running replica of a service with a given deployed revision."""

    def __init__(
        self,
        service: str,
        config: dict,
        handler: Callable,
        features: dict[str, ModuleType],
        indexes: set[str],
        table: str,
        upstream_host: str,
    ):
        self.service = service
        self.config = config
        self.handler = handler
        self.features = features
        self.indexes = indexes
        self.table = table
        self.upstream_host = upstream_host
        self.memory_mb = float(BASE_MEMORY_MB)
        self.cache_entries = 0
        self.restarting = 0
        self.restarts = 0

    # -- helpers -----------------------------------------------------------
    def cfg(self, key: str, default: Any = None) -> Any:
        return _get(self.config, key, default)

    @property
    def index_required(self) -> str:
        return f"idx_{self.table}_customer_id"

    def amplification(self) -> float:
        retries = int(self.cfg("upstream.max_retries", 3) or 0)
        backoff = int(self.cfg("upstream.backoff_ms", 200) or 0)
        return 1.0 + retries * (0.35 if backoff < 50 else 0.03)

    def _memory_step(self) -> None:
        cap = self.cfg("cache.max_entries", 10000)
        if cap is None:
            self.memory_mb += UNBOUNDED_GROWTH_MB_PER_SAMPLE
        else:
            self.cache_entries = min(int(cap), self.cache_entries + 40)
            self.memory_mb = BASE_MEMORY_MB + self.cache_entries * CACHE_ENTRY_MB

    # -- request path ------------------------------------------------------
    def handle(self, req: dict, runtime: dict | None = None) -> Outcome:
        runtime = runtime or {}
        flags = dict(req.get("flags") or {})
        flags.update(runtime.get("flags", {}))
        rid = req["id"]

        if self.restarting > 0:
            self.restarting -= 1
            return Outcome(503, "ServiceUnavailable",
                           "upstream connect error: container restarting after OOMKilled",
                           memory_mb=self.memory_mb)

        self._memory_step()
        if self.memory_mb > MEMORY_LIMIT_MB:
            self.restarts += 1
            self.restarting = RESTART_SAMPLES
            mem = self.memory_mb
            self.memory_mb = float(BASE_MEMORY_MB)
            self.cache_entries = 0
            return Outcome(503, "OOMKilled",
                           f"container memory limit exceeded ({MEMORY_LIMIT_MB}Mi), "
                           f"rss={mem:.0f}Mi; pod restarted", memory_mb=mem)

        # Rate limiting at the edge
        limit = float(self.cfg("http.rate_limit_rps", 500))
        rps = float(req.get("rps", 0))
        if rps > limit and unit(rid, "ratelimit") < 1 - limit / rps:
            return Outcome(429, "RateLimitExceeded",
                           f"429 Too Many Requests (limit={limit:.0f} rps, observed={rps:.0f} rps)",
                           memory_mb=self.memory_mb)

        # Database
        pool = int(self.cfg("db.pool_size", 40))
        if int(req.get("concurrent_db", 0)) > pool:
            return Outcome(500, "ConnectionPoolExhausted",
                           f"timed out waiting for a connection from pool (pool_size={pool}, "
                           f"in_use={pool}, waiting={int(req['concurrent_db']) - pool})",
                           memory_mb=self.memory_mb)
        db_ms = float(req.get("db_ms_base", 0))
        if self.index_required not in self.indexes:
            db_ms += float(req.get("db_rows_scanned", 0)) * FULL_SCAN_MS_PER_ROW
        timeout = float(self.cfg("db.timeout_ms", 5000))
        if db_ms > timeout:
            return Outcome(500, "DatabaseTimeoutError",
                           f"query on {self.table} exceeded {timeout:.0f}ms timeout",
                           db_ms=timeout, memory_mb=self.memory_mb)
        warnings = []
        if db_ms > SLOW_QUERY_MS:
            warnings.append(
                f"SlowQuery: SELECT * FROM {self.table} WHERE customer_id = $1 took {db_ms:.0f}ms")

        # Upstream dependency
        upstream_ms = None
        attempts = 0
        if req.get("calls_upstream"):
            expires = (runtime.get("cert_expires_at") or {}).get(self.upstream_host)
            if expires is not None and req["ts"] >= expires:
                return Outcome(502, "SSLError",
                               f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                               f"certificate has expired (host={self.upstream_host})",
                               db_ms=db_ms, memory_mb=self.memory_mb)
            retries = int(self.cfg("upstream.max_retries", 3) or 0)
            upstream_ms = float(req.get("upstream_ms_base", 0)) * self.amplification()
            attempts = 1
            if req.get("upstream_status", 200) >= 500:
                if flags.get(f"{self.service.replace('-', '_')}_gateway_fallback"):
                    warnings.append("served degraded response from fallback path")
                else:
                    return Outcome(502, "UpstreamError",
                                   f"{self.upstream_name} returned {req['upstream_status']} "
                                   f"Service Unavailable after {retries + 1} attempts",
                                   db_ms=db_ms, upstream_ms=upstream_ms,
                                   upstream_attempts=retries + 1, memory_mb=self.memory_mb)
            if upstream_ms > UPSTREAM_TIMEOUT_MS:
                return Outcome(504, "UpstreamTimeout",
                               f"{self.upstream_name} did not respond within "
                               f"{UPSTREAM_TIMEOUT_MS}ms (attempt {retries + 1}/{retries + 1})",
                               db_ms=db_ms, upstream_ms=UPSTREAM_TIMEOUT_MS,
                               upstream_attempts=retries + 1, memory_mb=self.memory_mb)

        # Application handler
        ctx = Ctx(flags, self.features)
        try:
            self.handler(dict(req.get("payload") or {}), ctx)
        except ValidationError as exc:
            return Outcome(400, "ValidationError", str(exc), db_ms=db_ms,
                           upstream_ms=upstream_ms, memory_mb=self.memory_mb)
        except Exception as exc:  # noqa: BLE001 - mirrors the service's error middleware
            frames = [
                {"file": f.filename, "line": f.lineno, "function": f.name}
                for f in traceback.extract_tb(exc.__traceback__)
                if not f.filename.endswith("core.py")
            ]
            return Outcome(500, type(exc).__name__, str(exc), stack=frames, db_ms=db_ms,
                           upstream_ms=upstream_ms, memory_mb=self.memory_mb)
        return Outcome(200, db_ms=db_ms, upstream_ms=upstream_ms, upstream_attempts=attempts,
                       warnings=warnings, memory_mb=self.memory_mb)

    @property
    def upstream_name(self) -> str:
        return self.upstream_host.split(".")[0]


def summarize(outcomes: list[Outcome]) -> dict:
    total = len(outcomes) or 1
    errors: dict[str, int] = {}
    for o in outcomes:
        if o.status >= 500 or o.status == 429:
            errors[o.error_type or "unknown"] = errors.get(o.error_type or "unknown", 0) + 1
    failed = sum(errors.values())
    return {
        "requests": len(outcomes),
        "failed": failed,
        "error_rate": round(failed / total, 4),
        "errors_by_type": dict(sorted(errors.items(), key=lambda kv: -kv[1])),
    }
