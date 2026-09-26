"""Source templates for the synthetic ACME platform monorepo."""
from __future__ import annotations

from aegis.world.catalog import SERVICES, Service


def render_config(svc: Service, state: dict) -> str:
    cache = "null" if state["cache.max_entries"] is None else state["cache.max_entries"]
    return f"""# Runtime configuration for {svc.name}.
# Changes to this file are deployed with the service. See the
# architecture notes for the reasoning behind each value.
service: {svc.name}
version: {state['version']}
handler: {svc.handler}
http:
  endpoint: {svc.endpoint}
  rate_limit_rps: {state['http.rate_limit_rps']}
db:
  host: {svc.db_host}
  table: {svc.table}
  timeout_ms: {state['db.timeout_ms']}
  pool_size: {state['db.pool_size']}
cache:
  max_entries: {cache}
  ttl_s: 300
upstream:
  host: {svc.upstream_host}
  max_retries: {state['upstream.max_retries']}
  backoff_ms: {state['upstream.backoff_ms']}
observability:
  log_level: {state['log_level']}
"""


def render_handler(svc: Service, state: dict) -> str:
    doc_extra = ""
    if state.get("handler_comment"):
        doc_extra = (
            "\nRequests are authenticated by the edge gateway before reaching this\n"
            "module; handlers must never trust client-supplied identifiers.\n"
        )
    if state.get("handler_variant") == "missing_field":
        parse = (
            f'    fields = {{k: payload[k] for k in ("amount", "{svc.field}")}}\n'
            f'    amount = int(fields["amount"])\n'
            f'    if amount < 0:\n'
            f'        raise ctx.ValidationError("amount must be non-negative")\n'
            f'    {svc.field} = fields["{svc.field}"]\n'
        )
    else:
        parse = (
            f'    amount = int(payload.get("amount", 0))\n'
            f'    if amount < 0:\n'
            f'        raise ctx.ValidationError("amount must be non-negative")\n'
            f'    {svc.field} = payload.get("{svc.field}", "{svc.field_default}")\n'
        )
    return f'''"""HTTP handlers for {svc.name} ({svc.method} {svc.endpoint}).

Owned by team-{svc.team}. Architecture notes live in the engineering docs
portal under architecture/{svc.name}.
{doc_extra}"""


def {svc.handler}(payload, ctx):
    """Handle {svc.method} {svc.endpoint}."""
{parse}    record = {{"{svc.field}": {svc.field}, "amount": amount}}
    if ctx.flag("{svc.flag}"):
        feature = ctx.feature("{svc.flag}")
        record = feature.apply(record, payload)
    return ctx.respond(200, record)
'''


def render_feature(svc: Service) -> str:
    return f'''"""Experimental {svc.flag_error} path behind the `{svc.flag}` feature flag.

Rolled out gradually via the flag service. Not yet covered by contract tests.
"""

SUPPORTED_DISCOUNTS = {{"percent", "fixed"}}


def apply(record, payload):
    kind = payload.get("discount_type", "percent")
    if kind not in SUPPORTED_DISCOUNTS:
        raise ValueError(f"unsupported discount type {{kind!r}} in {svc.flag_error} path")
    record["{svc.flag_error}_applied"] = True
    return record
'''


def render_service_readme(svc: Service, extra: bool = False) -> str:
    text = f"""# {svc.name}

Handles `{svc.method} {svc.endpoint}`. Owned by team-{svc.team}.

* Config: `config.yaml` (deployed with the service)
* Handlers: `handlers.py`
* Experimental paths: `features/`
"""
    if extra:
        text += "\nOn-call: page #team-" + svc.team + " for anything touching this service.\n"
    return text


def render_migration_init() -> str:
    lines = ["-- Initial schema for ACME platform services", ""]
    for svc in SERVICES.values():
        lines += [
            f"CREATE TABLE {svc.table} (id BIGSERIAL PRIMARY KEY, customer_id BIGINT NOT NULL, "
            f"amount_cents BIGINT, status TEXT, created_at TIMESTAMPTZ DEFAULT now());",
            f"CREATE INDEX idx_{svc.table}_customer_id ON {svc.table}(customer_id);",
            f"CREATE INDEX idx_{svc.table}_legacy_status ON {svc.table}(status);",
            "",
        ]
    return "\n".join(lines)


def render_drop_migration(svc: Service) -> str:
    return f"""-- Remove indexes reported as low-usage by the weekly pg_stat review.
DROP INDEX IF EXISTS idx_{svc.table}_legacy_status;
DROP INDEX IF EXISTS idx_{svc.table}_customer_id;
"""


def render_tests() -> str:
    services = ", ".join(f'"{s}"' for s in SERVICES)
    return f'''"""Unit tests for service handlers and configuration invariants."""
from pathlib import Path

import pytest

from platform_sim.core import Ctx
from platform_sim.replay import load_service

ROOT = Path(__file__).resolve().parents[1]
SERVICES = [{services}]


@pytest.mark.parametrize("service", SERVICES)
def test_config_is_sane(service):
    model = load_service(ROOT, service)
    assert model.cfg("db.timeout_ms") > 0
    assert model.cfg("db.pool_size") > 0
    assert model.cfg("http.rate_limit_rps") > 0
    assert model.cfg("upstream.max_retries") >= 0


@pytest.mark.parametrize("service", SERVICES)
def test_handler_happy_path(service):
    model = load_service(ROOT, service)
    field = {{
        "payment-service": "currency", "checkout-service": "cart_id",
        "audit-service": "actor_id", "inventory-service": "warehouse",
        "notification-service": "channel", "auth-service": "client_id",
    }}[service]
    result = model.handler({{"amount": 1200, field: "x"}}, Ctx({{}}, model.features))
    assert result["status"] == 200


@pytest.mark.parametrize("service", SERVICES)
def test_negative_amount_rejected(service):
    model = load_service(ROOT, service)
    with pytest.raises(Exception):
        model.handler({{"amount": -1}}, Ctx({{}}, model.features))
'''


CONFTEST = '''import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
'''

ROOT_README = """# acme-platform

Monorepo for ACME's customer-facing services. Each service lives in
`services/<name>/` and is deployed independently (tag: `deploy/<service>/v<version>`).

* `platform_sim/` - deterministic traffic replay used by reproduction tests
* `migrations/` - shared PostgreSQL schema migrations (applied at deploy time)
* `tests/` - unit tests run in CI on every commit
"""

REQUIREMENTS = "pyyaml==6.0.2\npytest==8.3.3\nhttpx=={httpx}\n"
