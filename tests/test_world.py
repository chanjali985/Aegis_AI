import json
import subprocess

from aegis.world.generator import build_workspace, load_truth, sample_spec
from aegis.world.repo_files.platform_sim.core import unit


def test_demo_workspace_layout(demo_ws):
    for rel in ("incident.json", ".ground_truth.json", "repo/.git", "telemetry/logs.jsonl",
                "telemetry/metrics.json", "telemetry/traces.jsonl", "prod_replica.db", "docs/runbooks"):
        assert (demo_ws / rel).exists(), rel
    truth = load_truth(demo_ws)
    assert truth["family"] == "db_timeout_reduced"
    assert truth["culprit"]["version"] == "2.7.1"
    tags = subprocess.run(["git", "tag"], cwd=demo_ws / "repo", capture_output=True, text=True).stdout
    assert "deploy/payment-service/v2.7.1" in tags


def test_telemetry_is_causally_consistent(demo_ws):
    truth = load_truth(demo_ws)
    logs = [json.loads(l) for l in (demo_ws / "telemetry/logs.jsonl").read_text().splitlines()]
    timeouts = [l for l in logs if l["service"] == "payment-service" and l.get("error_type") == "DatabaseTimeoutError"]
    assert timeouts, "the culprit must produce timeout errors"
    assert all(l["ts"] >= truth["onset"][:15] for l in timeouts)  # none before the bad deploy
    assert all(l["version"] == "2.7.1" for l in timeouts)


def test_repo_tests_pass_at_head(demo_ws):
    proc = subprocess.run(["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"],
                          cwd=demo_ws / "repo", capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout[-500:]


def test_generation_is_deterministic(tmp_path):
    a = build_workspace(sample_spec(3), tmp_path / "a")
    b = build_workspace(sample_spec(3), tmp_path / "b")
    ta, tb = load_truth(a), load_truth(b)
    assert ta["family"] == tb["family"] and ta["onset"] == tb["onset"]
    assert (a / "telemetry/logs.jsonl").read_text() == (b / "telemetry/logs.jsonl").read_text()


def test_unit_hash_is_stable():
    assert unit("abc", "x") == unit("abc", "x")
    assert 0 <= unit("abc", "y") < 1
