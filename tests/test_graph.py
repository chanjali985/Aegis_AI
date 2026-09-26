"""End-to-end investigations through the LangGraph workflow."""
import subprocess

from aegis.orchestration.runner import InvestigationService
from aegis.storage.db import get_store


async def test_full_investigation_with_human_approval(demo_ws):
    svc = InvestigationService()
    run_id = await svc.start(workspace=demo_ws, background=False)
    state = await svc.state(run_id)
    assert state["next"] == ["approval"], "must pause for a human before touching the repo"
    payload = state["interrupts"][0]
    assert payload["tool"] == "git.create_fix_branch" and "timeout_ms" in payload["diff"]
    assert get_store().get_investigation(run_id)["status"] == "awaiting_approval"

    await svc.decide(run_id, "approve", by="pytest", background=False)
    report = (await svc.state(run_id))["values"]["report"]
    assert report["status"] == "completed"
    assert report["root_cause"]["pattern"] == "db_timeout_reduced" and report["root_cause"]["verified"]
    assert report["grounding"]["grounded"]
    assert report["security"]["prompt_injections_quarantined"] > 0  # the demo docs contain an injection
    branch = report["applied"]["detail"][0]["branch"]
    diff = subprocess.run(["git", "diff", "main", branch, "--", "services/payment_service/config.yaml"],
                          cwd=demo_ws / "repo", capture_output=True, text=True).stdout
    assert "+  timeout_ms: 5000" in diff


async def test_rejection_leaves_repo_untouched(flag_ws):
    svc = InvestigationService()
    run_id = await svc.start(workspace=flag_ws, background=False)
    await svc.decide(run_id, "reject", comment="not during peak", by="pytest", background=False)
    report = (await svc.state(run_id))["values"]["report"]
    assert report["status"] == "rejected"
    assert report["root_cause"]["pattern"] == "flag_enabled"
    assert not (flag_ws / "control_plane_actions.jsonl").exists()


async def test_durable_resume_after_restart(tmp_path, flag_ws):
    """Pause for approval, drop the service, resume from the SQLite checkpoint in a new one."""
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
    db = str(tmp_path / "ckpt.db")
    async with AsyncSqliteSaver.from_conn_string(db) as saver:
        run_id = await InvestigationService(saver).start(workspace=flag_ws, background=False)
    async with AsyncSqliteSaver.from_conn_string(db) as saver:
        svc = InvestigationService(saver)
        assert (await svc.state(run_id))["next"] == ["approval"]
        await svc.decide(run_id, "approve", by="pytest", background=False)
        assert (await svc.state(run_id))["values"]["report"]["status"] == "completed"
