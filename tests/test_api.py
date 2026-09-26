from fastapi.testclient import TestClient

from aegis.api.app import app


def test_api_endpoints():
    with TestClient(app) as client:
        assert client.get("/healthz").json()["ok"]
        scenarios = client.get("/api/scenarios").json()
        assert any(s["id"] == "payment-db-timeout" for s in scenarios)
        agents = client.get("/api/agents").json()
        assert {a["name"] for a in agents["agents"]} >= {"research", "code", "fix", "verification"}
        card = client.get("/a2a/research/.well-known/agent-card.json").json()
        assert card["protocolVersion"] and card["skills"]
        assert "aegis_" in client.get("/metrics").text
        assert client.get("/").status_code == 200
        assert client.post("/api/investigations", json={"scenario": "nope"}).status_code == 400
