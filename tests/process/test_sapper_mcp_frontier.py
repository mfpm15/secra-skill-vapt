"""Proof the vendored Sapper-v2 CLI is reachable through safe MCP summaries."""
from __future__ import annotations

from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher
from app.sapper_integration import initialize_graph, stage_begin, stage_end


def make(tmp_path):
    store = TaskStore(tmp_path)
    task_id = store.create("", "", mode="evidence", authorized=True)
    store.start(task_id)
    return store, task_id, ToolDispatcher(tmp_path, store=store)


def test_sapper_frontier_metadata_only_before_and_after_initialized_graph(tmp_path):
    store, tid, dispatcher = make(tmp_path)
    empty = dispatcher.call("workflow.graph_frontier", {"task_id": tid})
    assert empty["status"] == "completed"
    assert empty["masked"] is True
    assert "not initialized" in empty["summary"]
    created = dispatcher.call("workflow.graph_initialize", {"task_id": tid})
    assert created["status"] == "completed"
    assert "No target" not in created["summary"]
    anchor = initialize_graph(tid, tmp_path)  # Idempotent on the same real graph
    intent = stage_begin(tid, tmp_path, "Review Web", anchor)
    active = dispatcher.call("workflow.graph_frontier", {"task_id": tid})
    assert active["status"] == "completed"
    assert "graph integrity valid" in active["summary"]
    assert intent in active["summary"]
    assert "No target" not in active["summary"]  # no invented target data
    stage_end(tid, tmp_path, "Review Web", intent,
              "Operator approved offline review completed")
    completed = dispatcher.call("workflow.graph_frontier", {"task_id": tid})
    assert completed["status"] == "completed"
    assert "eligible intent IDs: none" in completed["summary"]
    assert "arena" not in completed["summary"].lower()
    assert len(store.tool_runs(tid)) == 4


def test_frontier_is_still_read_only_after_case_completed(tmp_path):
    store, tid, dispatcher = make(tmp_path)
    store.set_status(tid, "completed", "Manual audit completed")
    result = dispatcher.call("workflow.graph_frontier", {"task_id": tid})
    assert result["status"] == "completed"
    denied = dispatcher.call("workflow.graph_frontier",
                             {"task_id": tid, "argv": ["sapper", "dispatch"]})
    assert denied["status"] == "denied"
    no_new_graph = dispatcher.call("workflow.graph_initialize", {"task_id": tid})
    assert no_new_graph["status"] == "denied"


def test_sapper_read_only_tool_is_classified_as_nonexecuting(tmp_path):
    from app.loop.readiness import inspect_capabilities
    store, tid, dispatcher = make(tmp_path)
    report = inspect_capabilities(store, dispatcher.manifest, tid)
    graph = next(t for t in report["tools"]
                 if t["name"] == "workflow.graph_frontier")
    assert graph["risk"] == "R0"
    assert graph["classification"] == "read_only"
    assert report["live_execution_ready"] is False
