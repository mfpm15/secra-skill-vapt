"""Domain-only offline case: no fictional target or executable scanner grants."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from uuid import UUID

import pytest

from app.loop.agent import AgentLoop, FakeDemoModel
from app.loop.store import TaskStore, TaskError
from app.mcp.dispatcher import ToolDispatcher
from app.har_import import import_har
from app.evidence_vault import EvidenceVault
from app.workspace import WorkspaceManager

ROOT = Path(__file__).resolve().parents[2]


def test_offline_evidence_mode_never_receives_network_authority(tmp_path):
    store = TaskStore(tmp_path)
    tid = store.create("", "", mode="evidence", authorized=True)
    task = store.require(tid)
    assert task["target"] == ""
    assert task["scope"] == ""
    assert task["mode"] == "evidence"
    store.start(tid)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    for tool, args in (
        ("nmap.tcp_top20", {}),
        ("curl.http_head", {"port": 443}),
        ("local.http_head", {"port": 8765}),
        ("demo.nmap_scan", {}),
    ):
        result = dispatcher.call(tool, {"task_id": tid, **args})
        assert result["status"] == "denied", (tool, result)
    assert dispatcher.call("workflow.capabilities", {"task_id": tid})["status"] == "completed"
    assert dispatcher.call("workflow.handoff", {"task_id": tid})["status"] == "completed"
    with pytest.raises(TaskError, match="EVIDENCE_MODE"):
        AgentLoop(store, dispatcher).run(tid, model=FakeDemoModel())


def test_offline_evidence_mode_can_store_real_scope_filtered_har(tmp_path):
    store = TaskStore(tmp_path)
    tid = store.create("", "", mode="evidence", authorized=True)
    store.start(tid)
    raw = json.dumps({"log": {"entries": [{
        "request": {"url": "https://authorized.example.test/resource", "headers": []},
        "response": {"status": 200, "headers": [{"name": "X-Content-Type-Options",
                                                  "value": "nosniff"}]},
    }]}}).encode()
    imported = import_har(store, tid, raw,
                          approved_hosts=("authorized.example.test",),
                          operator_scope_confirmed=True)
    assert imported["status"] == "completed"
    assert imported["accepted_entries"] == 1
    assert "authorized.example.test" not in str(imported)
    assert imported["vulnerabilities_verified"] == 0
    assert imported["output_ref"].startswith("evidence://" + tid + "/")
    store.set_status(tid, "completed", "Offline evidence case closed by operator.")
    WorkspaceManager(tmp_path / "engagements").write_manifest(tid)


def test_no_scope_no_task_creation_and_cli_requires_operator_confirmation(tmp_path):
    store = TaskStore(tmp_path)
    with pytest.raises(TaskError):
        store.create("", "", mode="evidence", authorized=False)
    with pytest.raises(TaskError):
        store.create("203.0.113.10", "203.0.113.0/24",
                     mode="evidence", authorized=True)
    script = ROOT / "scripts" / "secra_evidence_task.py"
    missing = subprocess.run([sys.executable, str(script), "--data-dir", str(tmp_path)],
                             cwd="/tmp", capture_output=True, text=True)
    assert missing.returncode != 0
    allowed = subprocess.run([
        sys.executable, str(script), "--data-dir", str(tmp_path),
        "--confirm-authorization"
    ], cwd="/tmp", capture_output=True, text=True)
    assert allowed.returncode == 0, allowed.stderr
    result = json.loads(allowed.stdout)
    assert result["network_scope_configured"] is False
    assert result["network_execution_authorized"] is False
    assert store.require(result["task_id"])["scope"] == ""


def test_operator_can_complete_evidence_case_without_running_a_model(tmp_path):
    script = ROOT / "scripts" / "secra_evidence_task.py"
    new = subprocess.run([
        sys.executable, str(script), "--data-dir", str(tmp_path),
        "--confirm-authorization",
    ], cwd="/tmp", capture_output=True, text=True)
    assert new.returncode == 0, new.stderr
    tid = json.loads(new.stdout)["task_id"]
    denied = subprocess.run([
        sys.executable, str(script), "--data-dir", str(tmp_path),
        "--finish-task-id", tid,
    ], cwd="/tmp", capture_output=True, text=True)
    assert denied.returncode != 0
    store = TaskStore(tmp_path)
    assert store.require(tid)["status"] == "running"
    completed = subprocess.run([
        sys.executable, str(script), "--data-dir", str(tmp_path),
        "--finish-task-id", tid, "--confirm-completion",
    ], cwd="/tmp", capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["network_execution_authorized"] is False
    assert store.require(tid)["status"] == "completed"
    duplicate = subprocess.run([
        sys.executable, str(script), "--data-dir", str(tmp_path),
        "--finish-task-id", tid, "--confirm-completion",
    ], cwd="/tmp", capture_output=True, text=True)
    assert duplicate.returncode != 0
