"""Real local-only HTTP HEAD against ephemeral 127.0.0.1 test server.

This is a genuine loopback TCP request with a fake/mock model, NOT a Kali
scan or an independently verified real external 9Router provider.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import UUID

import pytest

from app.loop.agent import AgentLoop
from app.loop.provider import Choice, NineRouterPlanner
from app.loop.store import TaskStore, TaskError
from app.mcp.dispatcher import ToolDispatcher


class OnlyHead(BaseHTTPRequestHandler):
    request_count = 0

    def do_HEAD(self):
        if self.path != "/":
            self.send_response(404)
        else:
            type(self).request_count += 1
            self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def local_http():
    OnlyHead.request_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), OnlyHead)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class OneLocalTool:
    def __init__(self, port):
        self.port = port
        self.seen = []
    def choose(self, *, prior, **kwargs):
        self.seen.append(prior)
        if prior is None:
            return Choice("local.http_head", {"port": self.port})
        return None


def test_genuine_local_loopback_head_with_model_feedback(tmp_path, local_http):
    store = TaskStore(tmp_path)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    tid = store.create("127.0.0.1", "127.0.0.1/32",
                       authorized=True, mode="local", model="glm/mock")
    fake = OneLocalTool(local_http)
    result = AgentLoop(store, dispatcher).run(tid, model=fake)
    assert result.status == "completed" and result.steps == 1
    assert OnlyHead.request_count == 1
    receipt = result.receipts[0]
    assert receipt["status"] == "completed" and receipt["exit_code"] == 0
    assert receipt["masked"] is True
    assert receipt["summary"] == f"LOCAL HEAD: status 204 on loopback port {local_http}."
    assert len(fake.seen) == 2 and fake.seen[1] == ("local.http_head", receipt["summary"])
    ref = receipt["output_ref"].split("/")
    raw = dispatcher.vault.verify_and_read(UUID(tid), UUID(ref[-1]))["stdout"]
    observation = json.loads(raw)
    assert observation == {"local_only": True, "target_alias": "ASSET_001",
                           "method": "HEAD", "status": 204, "port": local_http,
                           "peer_verified": True}


def test_local_mode_cannot_be_redirected_outside_loopback(tmp_path, local_http):
    store = TaskStore(tmp_path)
    for target, scope in [
        ("127.0.0.2", "127.0.0.0/8"),
        ("198.51.100.1", "198.51.100.0/24"),
        ("localhost", "127.0.0.1/32"),
        ("127.0.0.1", "0.0.0.0/0"),
    ]:
        with pytest.raises(TaskError):
            store.create(target, scope, authorized=True, mode="local")
    tid = store.create("127.0.0.1", "127.0.0.1/32",
                       authorized=True, mode="local")
    store.start(tid)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    for port in (0, 80, 99999, "not-a-port"):
        result = dispatcher.call("local.http_head", {"task_id": tid, "port": port})
        assert result["status"] == "denied"
    assert OnlyHead.request_count == 0


def test_9router_compatible_tool_selection_performs_real_local_head(tmp_path, monkeypatch, local_http):
    """Wire is mocked; the loopback HTTP HEAD is real, bounded and witnessed."""
    import app.loop.provider as provider_module
    observed = []
    class MockResult:
        def __init__(self, n):
            self.n = n
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, n=0):
            message = ({"tool_calls": [{"function": {
                "name": "local__http_head", "arguments": json.dumps({"port": local_http})
            }}]} if self.n == 1 else {"content": "Review completed."})
            return json.dumps({"choices": [{"message": message}]}).encode()

    def mocked_router(req, timeout=0):
        observed.append(json.loads(req.data))
        return MockResult(len(observed))

    monkeypatch.setattr(provider_module.urllib.request, "urlopen", mocked_router)
    planner = NineRouterPlanner("glm/mock", key="ci-synthetic-key",
                               gateway="http://127.0.0.1:20128/v1")
    store = TaskStore(tmp_path)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    tid = store.create("127.0.0.1", "127.0.0.1/32", mode="local",
                       authorized=True, model="glm/mock")
    result = AgentLoop(store, dispatcher).run(tid, model=planner)
    assert result.status == "completed" and result.steps == 1
    assert OnlyHead.request_count == 1
    assert len(observed) == 2
    assert "local__http_head" in [t["function"]["name"] for t in observed[0]["tools"]]
    assert observed[1]["messages"][-1]["content"].startswith("Previous reviewed tool: local.http_head.")
    assert all("127.0.0.1" not in json.dumps(body) for body in observed)
    assert store.require(tid)["status"] == "completed"
