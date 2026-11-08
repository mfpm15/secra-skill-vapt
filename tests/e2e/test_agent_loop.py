"""No Kali, sockets, or external LLM needed: two real dispatches, sealed evidence."""
import json
import subprocess
import threading
from uuid import UUID
from pathlib import Path

import pytest

from app.loop.agent import AgentLoop, FakeDemoModel
from app.loop.provider import Choice
from app.loop.store import TaskStore, TaskError
from app.mcp.dispatcher import ToolDispatcher


def fixture(tmp_path):
    store = TaskStore(tmp_path)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    tid = store.create("127.0.0.1", "127.0.0.1/32",
                       mode="demo", authorized=True)
    return store, dispatcher, tid


def test_complete_offline_model_tool_gateway_feedback_loop(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("demo must not spawn processes")))
    store, dispatcher, tid = fixture(tmp_path)
    fake = FakeDemoModel()
    result = AgentLoop(store, dispatcher).run(tid, model=fake)
    assert result.status == "completed" and result.steps == 2
    assert [r["status"] for r in result.receipts] == ["simulated", "simulated"]
    assert all(r["masked"] and r["exit_code"] == 0 for r in result.receipts)
    assert fake.context_seen[0]["prior"] is None
    assert fake.context_seen[1]["prior"][0] == "demo.nmap_scan"
    assert "SIMULATED Nmap:" in fake.context_seen[1]["prior"][1]
    assert fake.context_seen[2]["prior"][0] == "demo.httpx_probe"
    events = store.events(tid)
    selected = [x["tool"] for x in events if x["kind"] == "model"]
    assert selected == ["demo.nmap_scan", "demo.httpx_probe"]
    assert store.require(tid)["status"] == "completed"
    for item in result.receipts:
        eid, rid = tid, item["output_ref"].rsplit("/", 1)[-1]
        raw = dispatcher.vault.verify_and_read(UUID(eid), UUID(rid))["stdout"]
        assert json.loads(raw)["simulated"] is True
        assert b"127.0.0.1" not in raw and b"private" not in raw
    assert all("127.0.0.1" not in x["summary"] for x in events)
    trace = json.loads((Path(__file__).parent / "fixtures/loop_transcript.json").read_text())
    observed = [{key: e[key] for key in ("kind", "tool", "status", "summary")} for e in events]
    assert observed == trace["events"]
    assert trace["synthetic"] and trace["outcome"]["tool_steps"] == result.steps
    assert fake.context_seen[1]["prior"] == (
        trace["model_feedback"][1]["prior"]["tool"],
        trace["model_feedback"][1]["prior"]["summary"])
    assert fake.context_seen[2]["prior"] == (
        trace["model_feedback"][2]["prior"]["tool"],
        trace["model_feedback"][2]["prior"]["summary"])
    transcript = [(e["kind"], e["tool"], e["status"]) for e in events]
    assert ("tool", "demo.nmap_scan", "done") in transcript
    assert ("tool", "demo.httpx_probe", "done") in transcript
    assert transcript[-1] == ("task", "", "completed")


def test_25_step_ceiling_and_exhausted_is_durable(tmp_path):
    store, dispatcher, tid = fixture(tmp_path)
    result = AgentLoop(store, dispatcher, max_steps=1).run(tid, model=FakeDemoModel())
    assert result.status == "exhausted" and result.steps == 1
    assert store.require(tid)["status"] == "exhausted"
    assert store.events(tid)[-1]["summary"].startswith("Task exhausted")


def test_stop_prevents_any_tool_start(tmp_path):
    store, dispatcher, tid = fixture(tmp_path)
    stop = threading.Event()
    stop.set()
    result = AgentLoop(store, dispatcher).run(tid, model=FakeDemoModel(), stop=stop)
    assert result.status == "stopped" and result.steps == 0
    assert not [x for x in store.events(tid) if x["kind"] == "tool"]
    with pytest.raises(TaskError):
        store.start(tid)


class RiskModel:
    def __init__(self, name):
        self.name = name
    def choose(self, **_):
        return Choice(self.name, {})


def test_r3_queued_but_approval_does_not_activate_adapter(tmp_path):
    store, dispatcher, tid = fixture(tmp_path)
    result = AgentLoop(store, dispatcher).run(tid, model=RiskModel("http.authenticated_test"))
    assert result.status == "awaiting_approval" and result.steps == 0
    approvals = store.approvals(tid)
    assert len(approvals) == 1 and approvals[0]["state"] == "pending"
    store.decide(tid, approvals[0]["id"], "approved")
    assert store.approvals(tid)[0]["state"] == "approved"
    assert not [x for x in store.events(tid) if x["kind"] == "tool" and x["status"] == "done"]


def test_r4_prohibited_even_after_review(tmp_path):
    store, dispatcher, tid = fixture(tmp_path)
    result = AgentLoop(store, dispatcher).run(tid, model=RiskModel("prohibited.r4"))
    assert result.status == "failed" and result.steps == 0
    pending = store.approvals(tid)[0]
    with pytest.raises(TaskError, match="R4_ALWAYS_PROHIBITED"):
        store.decide(tid, pending["id"], "approved")


def test_live_network_denied_without_kernel_attestation(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("network subprocess must not start")))
    store = TaskStore(tmp_path)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    tid = store.create("192.0.2.10", "192.0.2.0/24", mode="live", authorized=True)
    store.start(tid)
    result = dispatcher.call("nmap.tcp_top20", {"task_id": tid})
    assert result["status"] == "blocked"
    assert result["masked"] is True and result["output_ref"] is None
    assert "127.0.0.1" not in str(result)


def test_unknown_manifest_name_and_arguments_fail_closed(tmp_path):
    store, dispatcher, tid = fixture(tmp_path)
    store.start(tid)
    for name, args in [
        ("missing.tool", {"task_id": tid}),
        ("demo.nmap_scan", {"task_id": tid, "extra": "bad"}),
        ("demo.httpx_probe", {"task_id": tid, "port": 65535}),
        ("demo.nmap_scan", {"task_id": "00000000-0000-0000-0000-000000000000"}),
    ]:
        response = dispatcher.call(name, args)
        assert response["status"] == "denied"
        assert response["masked"] and response["exit_code"] is None
    assert not [x for x in store.events(tid) if x["kind"] == "tool" and x["status"] == "done"]
