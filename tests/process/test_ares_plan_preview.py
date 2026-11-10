"""Offline ARES-inspired tool-chain preflight; no Kali or network required."""
from __future__ import annotations

import json
import sqlite3

import pytest

from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher
from app.planning.preview import PlanError, goal_steps, preview_plan, short_preview


def setup_task(tmp_path, mode="demo", start=True):
    store = TaskStore(tmp_path)
    if mode == "live":
        target, scope = "10.77.0.2", "10.77.0.2/32"
    elif mode == "evidence":
        target, scope = "", ""
    else:
        target, scope = "127.0.0.1", "127.0.0.1/32"
    tid = store.create(target, scope, mode=mode, authorized=True)
    if start:
        store.start(tid)
    return store, tid, ToolDispatcher(tmp_path, store=store)


def test_preview_safely_classifies_demo_and_unknown_steps(tmp_path):
    store, tid, dispatcher = setup_task(tmp_path)
    plan = preview_plan(store, dispatcher.manifest, tid, [
        "inventory.read", "demo.nmap_scan", "nmap.tcp_top20",
        "prohibited.r4", "unknown.pentest",
    ])
    assert plan["schema"] == "secra-plan-preview-v1"
    assert plan["plan_verdict"] == "blocked"
    assert plan["execution_authorized"] is False
    assert plan["kernel_fence_attested"] is False
    assert plan["tool_calls_performed"] == 0
    assert [x["verdict"] for x in plan["steps"]] == [
        "metadata_candidate", "simulation_candidate",
        "blocked", "blocked", "rejected",
    ]
    assert plan["steps"][-1]["reason"] == "tool_not_reviewed"
    assert "127.0.0.1" not in json.dumps(plan)
    assert len(short_preview(plan)) <= 490
    assert "0 tools executed" in short_preview(plan)


def test_live_network_never_promoted_to_execution_ready(tmp_path):
    store, tid, dispatcher = setup_task(tmp_path, "live")
    plan = preview_plan(store, dispatcher.manifest, tid, [
        "nmap.tcp_top20", "curl.http_head", "http.authenticated_test",
    ])
    assert plan["blocked_steps"] == 3
    assert plan["plan_verdict"] == "blocked"
    assert plan["steps"][0]["classification"] == "gated"
    assert plan["steps"][1]["classification"] == "gated"
    assert plan["steps"][2]["classification"] == "operator_review"
    assert all(x["verdict"] == "blocked" for x in plan["steps"])
    assert "10.77.0.2" not in json.dumps(plan)


def test_preview_after_stop_is_still_only_metadata(tmp_path):
    store, tid, dispatcher = setup_task(tmp_path, "demo")
    store.stop(tid)
    plan = preview_plan(store, dispatcher.manifest, tid, [
        "workflow.capabilities", "demo.httpx_probe",
    ])
    assert plan["task_status"] == "stopped"
    assert plan["steps"][0]["verdict"] == "read_only_candidate"
    assert plan["steps"][1]["verdict"] == "blocked"


@pytest.mark.parametrize("steps", [[], ["inventory.read"] * 2,
    ["inventory.read"] * 9, ["../escape"], [123], "inventory.read"])
def test_preview_strict_input_contract(tmp_path, steps):
    store, tid, dispatcher = setup_task(tmp_path)
    with pytest.raises(PlanError):
        preview_plan(store, dispatcher.manifest, tid, steps)


def test_dispatcher_exposes_preview_without_any_child_execution(tmp_path):
    store, tid, dispatcher = setup_task(tmp_path)
    # A gateway that would throw if any live path accidentally runs.
    class NoNetworkGateway:
        def execute(self, *args, **kwargs):
            raise AssertionError("unexpected live tool execution")
    dispatcher.gateway = NoNetworkGateway()
    before = len(store.tool_runs(tid))
    result = dispatcher.call("workflow.plan_preview", {
        "task_id": tid,
        "steps": ["inventory.read", "demo.nmap_scan", "nmap.tcp_top20"],
    })
    assert result["status"] == "completed"
    assert result["exit_code"] == 0
    assert result["masked"] is True
    assert result["output_ref"] is None
    assert "preview" in result["summary"].lower()
    assert "0 tools executed" in result["summary"]
    assert "nmap.tcp_top20=blocked" in result["summary"]
    assert "127.0.0.1" not in json.dumps(result)
    assert len(store.tool_runs(tid)) == before + 1
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT COUNT(*) FROM approvals WHERE task_id=?", (tid,)).fetchone()[0] == 0


def test_mcp_schema_rejects_unreviewed_target_fields(tmp_path):
    store, tid, dispatcher = setup_task(tmp_path)
    for extra in ({"argv": ["nmap"]}, {"target": "10.0.0.1"},
                  {"scope": "0.0.0.0/0"}, {"authorization": True}):
        args = {"task_id": tid, "steps": ["inventory.read"], **extra}
        assert dispatcher.call("workflow.plan_preview", args)["status"] == "denied"
    assert dispatcher.call("workflow.plan_preview", {
        "task_id": tid, "steps": ["inventory.read", "inventory.read"],
    })["status"] == "denied"


def test_read_only_preflight_before_task_start_and_after_completion(tmp_path):
    store, tid, dispatcher = setup_task(tmp_path, start=False)
    result = dispatcher.call("workflow.plan_preview", {
        "task_id": tid, "steps": ["workflow.capabilities"],
    })
    assert result["status"] == "completed"
    assert "read_only_candidate" in result["summary"]
    store.start(tid)
    store.set_status(tid, "completed", "Synthetic done")
    result = dispatcher.call("workflow.plan_preview", {
        "task_id": tid, "steps": ["demo.httpx_probe"],
    })
    assert result["status"] == "completed"
    assert "blocked" in result["summary"]


def test_fixed_goal_templates_use_reviewed_manifest_names(tmp_path):
    store, tid, dispatcher = setup_task(tmp_path, "demo")
    for goal in ("engagement_overview", "demo_web_baseline",
                 "artifact_triage", "sapper_graph_review", "live_recon_review"):
        steps = goal_steps(goal)
        assert 1 <= len(steps) <= 8
        assert all(name in dispatcher.manifest.tools for name in steps)
        result = preview_plan(store, dispatcher.manifest, tid, steps)
        assert result["execution_authorized"] is False
        assert result["tool_calls_performed"] == 0
    with pytest.raises(PlanError):
        goal_steps("domain_admin_shell")


def test_goal_template_mcp_can_only_preview_one_goal_or_steps(tmp_path):
    store, tid, dispatcher = setup_task(tmp_path, "demo")
    result = dispatcher.call("workflow.plan_preview", {
        "task_id": tid, "goal": "demo_web_baseline",
    })
    assert result["status"] == "completed"
    assert "demo.nmap_scan=simulation_candidate" in result["summary"]
    assert "0 tools executed" in result["summary"]
    result = dispatcher.call("workflow.plan_preview", {
        "task_id": tid, "goal": "live_recon_review",
    })
    assert result["status"] == "completed"
    assert "nmap.tcp_top20=blocked" in result["summary"]
    assert dispatcher.call("workflow.plan_preview", {
        "task_id": tid, "goal": "unknown",
    })["status"] == "denied"
    assert dispatcher.call("workflow.plan_preview", {
        "task_id": tid, "goal": "demo_web_baseline",
        "steps": ["inventory.read"],
    })["status"] == "denied"
    assert dispatcher.call("workflow.plan_preview", {
        "task_id": tid,
    })["status"] == "denied"
