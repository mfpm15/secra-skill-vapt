"""Operator console: localhost boot, authenticated API, durable events and SSE."""
import importlib
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

from fastapi.testclient import TestClient
from app.loop.agent import AgentLoop
from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher

ui = importlib.import_module("app.ui.server")


def build_client(tmp_path, monkeypatch):
    store = TaskStore(tmp_path)
    engine = ToolDispatcher(tmp_path, store=store)
    monkeypatch.setattr(ui, "STORE", store)
    monkeypatch.setattr(ui, "DISPATCHER", engine)
    monkeypatch.setattr(ui, "LOOP", AgentLoop(store, engine))
    monkeypatch.setattr(ui, "TOKEN", "ci-ui-operator-token-123456")
    return TestClient(ui.app), store


def test_one_page_start_sse_approval_and_stop(tmp_path, monkeypatch):
    client, store = build_client(tmp_path, monkeypatch)
    assert client.get("/").status_code == 200
    assert "Execution timeline" in client.get("/").text
    assert client.get("/api/tools").status_code == 401
    headers = {"X-Secra-Token": "ci-ui-operator-token-123456"}
    tools = client.get("/api/tools", headers=headers)
    assert tools.status_code == 200
    assert {t["name"] for t in tools.json()} >= {"demo.nmap_scan", "demo.httpx_probe"}
    forbidden = client.post("/api/tasks", headers=headers,
                            json={"target": "127.0.0.1", "scope": "127.0.0.1/32",
                                  "authorized": False, "mode": "demo"})
    assert forbidden.status_code == 400
    created = client.post("/api/tasks", headers=headers,
                          json={"target": "127.0.0.1", "scope": "127.0.0.1/32",
                                "authorized": True, "mode": "demo"})
    assert created.status_code == 200
    tid = created.json()["id"]
    launched = client.post("/api/tasks/" + tid + "/start", headers=headers)
    assert launched.status_code == 200
    for _ in range(100):
        if store.require(tid)["status"] in {"completed", "failed"}:
            break
        time.sleep(0.02)
    assert store.require(tid)["status"] == "completed"
    streamed = client.get("/api/tasks/" + tid + "/events", headers=headers)
    assert streamed.status_code == 200
    assert streamed.headers["content-type"].startswith("text/event-stream")
    assert "event: secra" in streamed.text
    assert "demo.nmap_scan" in streamed.text and "demo.httpx_probe" in streamed.text
    assert "127.0.0.1" not in streamed.text
    assert client.get("/api/tasks/" + tid + "/approvals", headers=headers).json() == []
    report = client.get("/api/tasks/" + tid, headers=headers).json()
    assert report["status"] == "completed" and report["asset"] == "ASSET_001"

    tid2 = client.post("/api/tasks", headers=headers,
                       json={"target": "127.0.0.1", "scope": "127.0.0.1/32",
                             "authorized": True}).json()["id"]
    stopped = client.post("/api/tasks/" + tid2 + "/stop", headers=headers)
    assert stopped.status_code == 200
    assert store.require(tid2)["status"] == "stopped"
    assert client.post("/api/tasks/" + tid2 + "/start", headers=headers).status_code == 409


def test_r3_ui_approval_is_review_only_and_r4_refused(tmp_path, monkeypatch):
    client, store = build_client(tmp_path, monkeypatch)
    headers = {"X-Secra-Token": "ci-ui-operator-token-123456"}
    tid = store.create("127.0.0.1", "127.0.0.1/32", authorized=True)
    store.start(tid)
    aid = store.request_approval(tid, "http.authenticated_test", "R3")
    response = client.post("/api/tasks/" + tid + "/approvals/" + aid, headers=headers,
                           json={"decision": "approved"})
    assert response.status_code == 200
    assert response.json()["execution"] == "not-enabled-until-reviewed-R3-adapter"
    assert store.approvals(tid)[0]["state"] == "approved"
    blocked = store.request_approval(tid, "prohibited.r4", "R4")
    rejected = client.post("/api/tasks/" + tid + "/approvals/" + blocked,
                           headers=headers, json={"decision": "approved"})
    assert rejected.status_code == 400
    assert store.approvals(tid)[-1]["state"] == "pending"


def test_python_m_app_serves_localhost(tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    env = dict(os.environ)
    env.update({"SECRA_UI_PORT": str(port), "SECRA_DATA_DIR": str(tmp_path),
                "SECRA_DASHBOARD_TOKEN": "ci-ui-operator-token-123456"})
    process = subprocess.Popen([sys.executable, "-m", "app"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env)
    ready = False
    try:
        for _ in range(60):
            try:
                with urllib.request.urlopen("http://127.0.0.1:" + str(port) + "/", timeout=1) as r:
                    ready = r.status == 200
                    if ready: break
            except (OSError, TimeoutError):
                if process.poll() is not None:
                    break
                time.sleep(0.1)
        assert ready, "python -m app did not start the local UI"
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=3)
