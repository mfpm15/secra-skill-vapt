"""Agent replay safety: resume from stored receipts without redoing work."""
from __future__ import annotations

from app.loop.agent import AgentLoop, FakeDemoModel
from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher


def setup(tmp_path):
    store = TaskStore(tmp_path)
    tid = store.create("127.0.0.1", "127.0.0.1/32",
                       mode="demo", authorized=True)
    engine = ToolDispatcher(tmp_path, store=store)
    store.start(tid)
    return store, engine, tid


def test_resume_after_first_reviewed_tool_skips_duplicate_scan(tmp_path):
    store, engine, tid = setup(tmp_path)
    initial = engine.call("demo.nmap_scan", {"task_id": tid})
    assert initial["status"] == "simulated"
    fake = FakeDemoModel()
    result = AgentLoop(store, engine, max_steps=4).run(tid, model=fake)
    assert result.status == "completed"
    assert result.steps == 1
    audit = [row["tool"] for row in store.tool_runs(tid)]
    assert audit.count("demo.nmap_scan") == 1
    assert audit.count("demo.httpx_probe") == 1
    assert fake.context_seen[0]["prior"][0] == "demo.nmap_scan"
    assert fake.context_seen[0]["services"] == [
        {"port": 80, "service": "http"}, {"port": 443, "service": "https"}
    ]


def test_unfinished_tool_audit_requires_operator_review_before_resume(tmp_path):
    store, engine, tid = setup(tmp_path)
    store.begin_tool_run(tid, "demo.nmap_scan")  # simulated crash during execution
    fake = FakeDemoModel()
    result = AgentLoop(store, engine).run(tid, model=fake)
    assert result.status == "failed"
    assert result.steps == 0
    assert fake.context_seen == []
    assert len(store.tool_runs(tid)) == 1


def test_cross_session_budget_is_not_reset(tmp_path):
    store, engine, tid = setup(tmp_path)
    assert engine.call("demo.nmap_scan", {"task_id": tid})["status"] == "simulated"
    fake = FakeDemoModel()
    result = AgentLoop(store, engine, max_steps=1).run(tid, model=fake)
    assert result.status == "exhausted"
    assert not fake.context_seen
    assert len(store.tool_runs(tid)) == 1


def test_offline_process_preflight_does_not_consume_execution_budget(tmp_path):
    store, engine, tid = setup(tmp_path)
    assert engine.call("workflow.capabilities", {"task_id": tid})["status"] == "completed"
    fake = FakeDemoModel()
    result = AgentLoop(store, engine, max_steps=3).run(tid, model=fake)
    assert result.status == "completed"
    assert result.steps == 2
    names = [row["tool"] for row in store.tool_runs(tid)]
    assert names.count("demo.nmap_scan") == 1
    assert names.count("demo.httpx_probe") == 1
    assert names.count("workflow.capabilities") == 1
