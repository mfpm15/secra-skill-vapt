"""MCP v2 protocol acceptance with the official in-process Client."""
import asyncio
import json
from uuid import uuid4

import pytest

from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher
from app.mcp.manifest import ToolManifest, ManifestError
from app.mcp.server import create_server, LocalHTTPAuth


@pytest.mark.anyio
async def test_mcp_tools_list_and_real_tool_call_to_sealed_stub(tmp_path):
    from mcp import Client
    store = TaskStore(tmp_path)
    engine = ToolDispatcher(tmp_path, store=store)
    tid = store.create("127.0.0.1", "127.0.0.1/32", authorized=True)
    store.start(tid)
    server = create_server(engine)
    async with Client(server) as client:
        listing = await client.list_tools()
        tools = listing.tools if hasattr(listing, "tools") else listing
        advertised = {entry.name: entry for entry in tools}
        assert set(advertised) == set(engine.manifest.tools)
        assert advertised["demo.httpx_probe"].input_schema["required"] == ["task_id", "port"]
        assert advertised["nmap.tcp_top20"].input_schema["additionalProperties"] is False
        result = await client.call_tool("demo.nmap_scan", {"task_id": tid})
        structured = result.structured_content
        assert structured["status"] == "simulated"
        assert structured["masked"] is True
        assert structured["output_ref"].startswith("evidence://")
        assert "127.0.0.1" not in json.dumps(structured)
        invalid = await client.call_tool("demo.nmap_scan",
                                         {"task_id": tid, "nmap_script": "vuln"})
        assert invalid.structured_content["status"] == "denied"
        assert invalid.is_error is True


@pytest.mark.anyio
async def test_local_http_token_origin_and_host_protection(monkeypatch):
    monkeypatch.setenv("SECRA_DASHBOARD_TOKEN", "ci-local-operator-token-123456")
    reached = []
    async def inner(scope, receive, send):
        reached.append(scope)
        await send({"type": "http.response.start", "status": 202, "headers": []})
        await send({"type": "http.response.body", "body": b""})
    wrapper = LocalHTTPAuth(inner)
    async def req(host="127.0.0.1:8766", origin=None, token="ci-local-operator-token-123456"):
        scope = {"type": "http", "method": "POST", "path": "/mcp",
                 "headers": [(b"host", host.encode()),
                             (b"authorization", ("Bearer " + token).encode())]}
        if origin is not None:
            scope["headers"].append((b"origin", origin.encode()))
        sent = []
        async def receive(): return {"type": "http.request", "body": b"", "more_body": False}
        async def send(value): sent.append(value)
        await wrapper(scope, receive, send)
        return sent[0]["status"]
    assert await req() == 202
    assert await req(origin="https://attacker.example") == 403
    assert await req(host="attacker.example:8766") == 403
    assert await req(token="wrong") == 401
    assert len(reached) == 1


def test_manifest_new_tool_is_data_not_server_source(tmp_path):
    m = ToolManifest()
    assert set(m.tools) >= {"demo.nmap_scan", "demo.httpx_probe",
                            "nmap.tcp_top20", "curl.http_head"}
    raw = {"schema": 1, "tools": [{
        "name": "demo.custom_read", "description": "Offline reviewed read-only stub.",
        "risk": "R0", "mode": "demo", "adapter": "inventory_read",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {"task_id": {"type": "string"}},
            "required": ["task_id"],
        },
    }]}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(raw))
    added = ToolManifest(path)
    assert "demo.custom_read" in added.tools
    raw["tools"][0]["adapter"] = "subprocess.anything"
    path.write_text(json.dumps(raw))
    with pytest.raises(ManifestError):
        ToolManifest(path)
