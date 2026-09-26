"""Command-line entry point: ``aegis <command>``."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys


def _print_event(e: dict) -> None:
    d = e["data"]
    t = e["type"]
    if t in ("agent_started",):
        return
    if t == "evidence":
        line = f"    - [{d['id']}] {d['summary'][:130]}"
    elif t == "plan":
        line = "  plan wave %s: %s" % (d["wave"], "; ".join(f"{s['agent']} -> {s['goal']}" for s in d["steps"]))
    elif t == "hypotheses":
        line = "  hypotheses: " + ", ".join(f"{h['title']} ({h['confidence']:.0%})" for h in d["hypotheses"][:3])
    elif t == "verification":
        line = f"  verification: {d['summary'][:200]}"
    elif t == "agent_finished":
        line = f"  {e['agent']:<13} done in {d.get('latency_ms', 0):.0f}ms: {d.get('summary', '')[:120]}"
    elif t == "delegation":
        line = f"  supervisor -> {d['to']} (A2A): {d['goal'][:100]}"
    elif t == "security_event":
        line = f"  !! security: {d['kind']} {d.get('rule', '')} via {d.get('tool', '')}"
    else:
        line = f"  {e['agent']:<13} {t}: {json.dumps(d, default=str)[:160]}"
    print(line)


async def _demo(args) -> None:
    from aegis.observability.tracing import bus
    from aegis.orchestration.runner import InvestigationService
    from aegis.storage.db import get_store
    svc = InvestigationService()
    run_id = "demo-" + __import__("uuid").uuid4().hex[:8]
    queue = bus.subscribe(run_id)

    async def printer():
        while True:
            _print_event(await queue.get())

    ptask = asyncio.create_task(printer())
    print(f"AegisAI investigating scenario '{args.scenario}' (run {run_id})\n")
    await svc.start(request=args.request, scenario=args.scenario, run_id=run_id, background=False)
    state = await svc.state(run_id)
    if state["next"]:
        payload = state["interrupts"][0]
        print("\n" + "=" * 70 + "\nHUMAN APPROVAL REQUIRED")
        print(f"Agent: {payload['agent']}   Tool: {payload['tool']}\nAction: {payload['action']}\n"
              f"Reason: {payload['reason']} (confidence {payload['confidence']:.0%})")
        for c in payload["checks"]:
            print(f"  [{'x' if c['passed'] else ' '}] {c['name']}: {c['detail'][:110]}")
        if payload.get("diff"):
            print("\n" + "\n".join(l for l in payload["diff"].splitlines() if not l.startswith("+{"))[:1500])
        decision = "approve" if args.approve else input("\nApprove? [approve/reject/request_changes]: ").strip()
        await svc.decide(run_id, decision or "reject", by="cli user", background=False)
        state = await svc.state(run_id)
    await asyncio.sleep(0.1)
    ptask.cancel()
    report = get_store().get_investigation(run_id)["result"]
    print("\n" + "=" * 70)
    print(f"STATUS: {report['status']}\n{report['headline']}\n\n{report['summary']}")
    print(f"\nGrounded: {report['grounding']['grounded']}   Tool calls: {report['stats']['tool_calls']}   "
          f"Injections quarantined: {report['security']['prompt_injections_quarantined']}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="aegis", description="AegisAI multi-agent incident investigator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="investigate a demo incident in the terminal")
    d.add_argument("--scenario", default="payment-db-timeout")
    d.add_argument("--request", default=None, help="override the incident report text")
    d.add_argument("--approve", action="store_true", help="auto-approve the remediation")
    s = sub.add_parser("serve", help="run the API, dashboard and A2A endpoints")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    b = sub.add_parser("benchmark", help="evaluate on generated incidents")
    b.add_argument("--n", type=int, default=100)
    b.add_argument("--seed", type=int, default=2026)
    b.add_argument("--no-ablations", action="store_true")
    b.add_argument("--out", default="evaluation/results")
    b.add_argument("--keep", action="store_true", help="keep generated workspaces")
    g = sub.add_parser("generate", help="generate an incident workspace")
    g.add_argument("--scenario", default=None)
    g.add_argument("--index", type=int, default=None)
    g.add_argument("--out", required=True)
    a = sub.add_parser("serve-agent", help="serve one specialist agent over A2A HTTP")
    a.add_argument("agent")
    a.add_argument("--host", default="127.0.0.1")
    a.add_argument("--port", type=int, default=9100)
    m = sub.add_parser("mcp", help="run an MCP tool server over stdio")
    m.add_argument("server", choices=["git", "observability", "database", "docs", "ops"])
    m.add_argument("--workspace", required=True)
    sub.add_parser("scenarios", help="list demo scenarios")
    args = ap.parse_args(argv)

    if args.cmd == "demo":
        asyncio.run(_demo(args))
    elif args.cmd == "serve":
        import uvicorn
        uvicorn.run("aegis.api.app:app", host=args.host, port=args.port)
    elif args.cmd == "benchmark":
        from aegis.evaluation.benchmark import render_markdown, run_benchmark
        summary = asyncio.run(run_benchmark(args.n, not args.no_ablations, args.out, args.seed, args.keep))
        print(render_markdown(summary))
    elif args.cmd == "generate":
        from aegis.world.generator import build_workspace, demo_spec, sample_spec
        spec = sample_spec(args.index) if args.index is not None else demo_spec(args.scenario or "payment-db-timeout")
        print(build_workspace(spec, args.out))
    elif args.cmd == "serve-agent":
        import uvicorn
        from fastapi import FastAPI

        from aegis.a2a.client import SPECIALISTS
        from aegis.a2a.server import A2AAgentServer, build_router
        cls = next(c for c in SPECIALISTS if c.name == args.agent)
        app = FastAPI(title=f"AegisAI {cls.title} (A2A)")
        app.include_router(build_router({cls.name: A2AAgentServer(cls(), f"http://{args.host}:{args.port}")}))
        uvicorn.run(app, host=args.host, port=args.port)
    elif args.cmd == "mcp":
        import importlib
        importlib.import_module(f"aegis.mcp_servers.{args.server}_server").build_server(args.workspace).run("stdio")
    elif args.cmd == "scenarios":
        from aegis.world.generator import DEMO_SCENARIOS
        for name, kw in DEMO_SCENARIOS.items():
            print(f"{name:<26} {kw['family']:<20} {kw['request']}")


if __name__ == "__main__":
    main(sys.argv[1:])
