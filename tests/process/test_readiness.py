"""Offline capability preflight contract (no live connectivity implied)."""
from __future__ import annotations

import json

from app.loop.store import TaskStore
from app.loop.readiness import inspect_capabilities, short_capabilities
from app.mcp.manifest import ToolManifest
from app.mcp.dispatcher import ToolDispatcher


def prepare(tmp_path, mode):
    store = TaskStore(tmp_path)
    target, scope = ("127.0.0.1", "127.0.0.1/32") if mode in {"demo", "local"} else ("10.77.0.2", "10.77.0.2/32")
    tid = store.create(target, scope, mode=mode, authorized=True)
    return store, tid, ToolDispatcher(tmp_path, store=store)


def get(records, name):
    return next(item for item in records["tools"] if item["name"] == name)


def test_demo_mode_readiness_reports_simulation_and_no_fake_live_authority(tmp_path):
    store, tid, dispatcher = prepare(tmp_path, "demo")
    report = inspect_capabilities(store, dispatcher.manifest, tid)
    assert report["live_execution_ready"] is False
    assert report["scope_attested"] is False
    assert get(report, "demo.nmap_scan")["classification"] == "blocked"  # task not started
    assert get(report, "nmap.tcp_top20")["classification"] == "blocked"
    assert get(report, "prohibited.r4")["classification"] == "blocked"
    receipt = dispatcher.call("workflow.capabilities", {"task_id": tid})
    assert receipt["status"] == "completed"  # introspection allowed before task start
    assert "not" in receipt["summary"].lower() or "NOT" in receipt["summary"]
    assert "127.0.0.1" not in json.dumps(report) + json.dumps(receipt)


def test_demo_running_reports_local_simulated_tools_only(tmp_path):
    store, tid, dispatcher = prepare(tmp_path, "demo")
    store.start(tid)
    report = inspect_capabilities(store, dispatcher.manifest, tid)
    assert get(report, "demo.nmap_scan")["classification"] == "simulated"
    assert get(report, "local.http_head")["classification"] == "blocked"
    assert get(report, "workflow.lead_propose")["classification"] == "proposal_only"
    assert get(report, "workflow.handoff")["classification"] == "read_only"
    assert get(report, "workflow.capabilities")["classification"] == "read_only"
    assert len(short_capabilities(report)) <= 490


def test_live_mode_never_claims_kernel_fence_ready(tmp_path):
    store, tid, dispatcher = prepare(tmp_path, "live")
    store.start(tid)
    report = inspect_capabilities(store, dispatcher.manifest, tid)
    for name in ("nmap.tcp_top20", "curl.http_head"):
        assert get(report, name)["classification"] == "gated"
        assert "kernel_fence" in get(report, name)["reason"]
    assert get(report, "http.authenticated_test")["classification"] == "operator_review"
    receipt = dispatcher.call("workflow.capabilities", {"task_id": tid})
    assert receipt["status"] == "completed"
    assert "10.77.0.2" not in str(receipt)
    assert "NOT attested" in receipt["summary"]


def test_completed_task_supports_readiness_but_not_network_execution(tmp_path):
    store, tid, dispatcher = prepare(tmp_path, "local")
    store.start(tid)
    store.set_status(tid, "completed", "Synthetic exercise complete")
    result = dispatcher.call("workflow.capabilities", {"task_id": tid})
    assert result["status"] == "completed"
    attempt = dispatcher.call("local.http_head", {"task_id": tid, "port": 8765})
    assert attempt["status"] == "denied"
    invalid = dispatcher.call("workflow.capabilities", {"task_id": tid, "argv": ["bash"]})
    assert invalid["status"] == "denied"
    assert "127.0.0.1" not in json.dumps(result)


def test_per_task_mcp_call_limit_persists_across_client_sessions(tmp_path, monkeypatch):
    import app.loop.store as store_module
    monkeypatch.setattr(store_module, "MAX_TASK_TOOL_CALLS", 2)
    store, tid, dispatcher = prepare(tmp_path, "demo")
    for _ in range(2):
        result = dispatcher.call("workflow.capabilities", {"task_id": tid})
        assert result["status"] == "completed"
    second_dispatcher = ToolDispatcher(tmp_path, store=TaskStore(tmp_path))
    blocked = second_dispatcher.call("workflow.capabilities", {"task_id": tid})
    assert blocked["status"] == "blocked"
    assert "127.0.0.1" not in str(blocked)
    assert len(store.tool_runs(tid)) == 2


def test_same_tool_limit_does_not_block_other_allowed_metadata(tmp_path, monkeypatch):
    import app.loop.store as store_module
    monkeypatch.setattr(store_module, "MAX_TASK_TOOL_CALLS", 10)
    monkeypatch.setattr(store_module, "MAX_TASK_SAME_TOOL_CALLS", 1)
    store, tid, dispatcher = prepare(tmp_path, "demo")
    assert dispatcher.call("workflow.capabilities", {"task_id": tid})["status"] == "completed"
    assert dispatcher.call("workflow.capabilities", {"task_id": tid})["status"] == "blocked"
    assert dispatcher.call("workflow.handoff", {"task_id": tid})["status"] == "completed"
    assert len(store.tool_runs(tid)) == 2
