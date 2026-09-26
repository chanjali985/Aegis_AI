import pytest

from aegis.observability.tracing import bind_run
from aegis.security.permissions import PermissionDenied
from aegis.tools.gateway import ToolGateway


async def test_gateway_memory_transport(demo_ws):
    bind_run("t-mcp")
    async with ToolGateway(demo_ws, "observability", transport="memory") as gw:
        spikes = await gw.call("observability.find_error_spikes", service="payment-service")
        assert spikes["spikes"][0]["error_type"] == "DatabaseTimeoutError"
        tools = await gw.list_tools("observability")
        assert any(t["name"] == "observability.search_logs" for t in tools)


async def test_gateway_denies_out_of_policy_calls(demo_ws):
    async with ToolGateway(demo_ws, "research", transport="memory") as gw:
        with pytest.raises(PermissionDenied):
            await gw.call("database.execute_readonly_sql", sql="SELECT 1")
        assert gw.calls[-1]["denied"]


async def test_gateway_masks_secrets_from_repo(demo_ws):
    async with ToolGateway(demo_ws, "code", transport="memory") as gw:
        env = await gw.call("git.read_file", path=".env.example")
        assert "sk_live_" not in env["content"] and "REDACTED" in env["content"]


async def test_database_server_is_read_only(demo_ws):
    async with ToolGateway(demo_ws, "database", transport="memory") as gw:
        res = await gw.call("database.execute_readonly_sql", sql="DELETE FROM payments")
        assert not res["ok"]
        rows = await gw.call("database.execute_readonly_sql", sql="SELECT card_number FROM payments")
        assert all(r["card_number"].startswith("[CARD") for r in rows["rows"])


async def test_git_server_rejects_option_injection(demo_ws):
    async with ToolGateway(demo_ws, "code", transport="memory") as gw:
        with pytest.raises(Exception):
            await gw.call("git.git_show", sha="--output=/tmp/pwned")


async def test_stdio_transport(demo_ws):
    async with ToolGateway(demo_ws, "code", transport="stdio") as gw:
        deploys = await gw.call("git.list_deploys", service="payment-service")
        assert deploys["deploys"][-1]["version"] == "2.7.1"
