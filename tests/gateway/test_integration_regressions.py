"""Additional safety integration coverage on POSIX synthetic processes only.

No Kali tool or external target is contacted by these tests.
"""
import os
import sys
import threading
import time
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app, TOKEN
from app.tool_gateway import ToolGateway, ToolCancelled
from app.tool_registry import StructuredToolIntent, REGISTRY
from app.evidence_vault import EvidenceWriter, EvidenceError


def _intent():
    return StructuredToolIntent(uuid4(), uuid4(), "recon", "nmap.tcp_top20",
                                "192.0.2.10", {})


def test_live_pipeline_fails_instead_of_sending_llm_or_fabricating_results():
    client = TestClient(app)
    headers = {"X-Secra-Token": TOKEN}
    response = client.post("/api/engagements", headers=headers, json={
        "name": "Synthetic blocked gateway assessment", "target": "192.0.2.10",
        "scope": "192.0.2.0/24", "mode": "live",
        "authorized": True, "model": ""})
    assert response.status_code == 200
    eid = response.json()["id"]
    assert client.post("/api/engagements/" + eid + "/start", headers=headers).status_code == 200
    for _ in range(150):
        state = client.get("/api/engagements/" + eid, headers=headers).json()
        if state["status"] in {"failed", "completed", "cancelled"}:
            break
        time.sleep(0.05)
    assert state["status"] == "failed"
    assert state["services"] == []
    assert client.get("/api/engagements/" + eid + "/report", headers=headers).status_code == 404
    events = client.get("/api/engagements/" + eid + "/events", headers=headers).json()
    assert not any(e["agent"] == "LLM Advisor" for e in events)
    assert not any(e["agent"] == "Report Builder" and e["level"] == "completed" for e in events)


def test_real_child_process_is_killed_with_parent_group(tmp_path):
    gateway = ToolGateway(tmp_path / "store")
    intent = _intent()
    cancel = threading.Event()
    unexpected = []
    marker = tmp_path / "child-escaped.txt"
    child = "import time,pathlib;time.sleep(2);pathlib.Path(" + repr(str(marker)) + ").write_text('escaped')"
    parent = ("import subprocess,sys,time;"
              "subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);"
              "print('READY',flush=True);time.sleep(30)")
    def launch():
        try:
            gateway._run_fixed_process((sys.executable, "-u", "-c", parent),
                                       intent, REGISTRY["nmap.tcp_top20"],
                                       uuid4(), cancel)
        except BaseException as error:
            unexpected.append(error)
    thread = threading.Thread(target=launch)
    thread.start()
    for _ in range(200):
        with gateway._lock:
            alive = bool(gateway._active)
        if alive:
            break
        time.sleep(0.01)
    assert alive
    time.sleep(0.35)  # child has time to fork before cancellation
    cancel.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert len(unexpected) == 1 and isinstance(unexpected[0], ToolCancelled)
    time.sleep(2)
    assert not marker.exists(), "a surviving process-group child wrote after cancellation"
    assert not gateway._active


def test_real_disk_failure_does_not_publish_seal_or_parse(tmp_path, monkeypatch):
    gateway = ToolGateway(tmp_path)
    intent = _intent()
    def fail(self, stream, raw):
        raise OSError("synthetic disk failure")
    monkeypatch.setattr(EvidenceWriter, "append", fail)
    with pytest.raises(OSError):
        gateway._run_fixed_process(
            (sys.executable, "-u", "-c", "print('highly sensitive')"),
            intent, REGISTRY[intent.action_id], uuid4(), threading.Event())
    outcomes = [item["outcome"] for item in gateway.audit.events(intent.engagement_id)]
    assert outcomes == ["EXECUTION_STARTED", "EVIDENCE_FAILED"]
    records = tmp_path / "records" / str(intent.engagement_id)
    assert list(records.iterdir()) == []


def test_sanitized_subprocess_environment_never_inherits_proxy(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.66:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://192.0.2.66:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://192.0.2.66:1080")
    gateway = ToolGateway(tmp_path)
    intent = _intent()
    code = "import os;print(int(any('proxy' in k.lower() for k in os.environ)))"
    receipt = gateway._run_fixed_process(
        (sys.executable, "-u", "-c", code),
        intent, REGISTRY[intent.action_id], uuid4(), threading.Event())
    raw = gateway.vault.verify_and_read(intent.engagement_id, receipt.run_id)["stdout"]
    assert raw.strip() == b"0"
