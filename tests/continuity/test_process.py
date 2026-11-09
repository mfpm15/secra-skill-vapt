"""Offline acceptance tests for live audit, privacy-safe handoff and recovery."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from uuid import UUID

from app.loop.continuity import build_handoff, short_handoff
from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher

ROOT = Path(__file__).resolve().parents[2]


def fixture(tmp_path):
    store = TaskStore(tmp_path)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    task = store.create("127.0.0.1", "127.0.0.1/32", mode="demo", authorized=True)
    store.start(task)
    return store, dispatcher, task


def test_real_utc_audit_recorded_before_demo_execution(tmp_path, monkeypatch):
    store, dispatcher, tid = fixture(tmp_path)
    seen = []
    from app.mcp import stubs
    original = stubs.demo_nmap

    def audited_stub(task, args, backend):
        live = backend.tool_runs(tid)
        assert len(live) == 1
        assert live[0]["status"] == "requested"
        assert live[0]["finished_at"] is None
        assert live[0]["started_at"].endswith("+00:00")
        seen.append("called")
        return original(task, args, backend)

    monkeypatch.setattr(stubs, "demo_nmap", audited_stub)
    r = dispatcher.call("demo.nmap_scan", {"task_id": tid})
    assert seen == ["called"]
    assert r["status"] == "simulated"
    recorded = store.tool_runs(tid)
    assert len(recorded) == 1
    assert recorded[0]["status"] == "simulated"
    assert recorded[0]["exit_code"] == 0
    assert recorded[0]["duration_ms"] >= 0
    assert recorded[0]["finished_at"].endswith("+00:00")
    assert recorded[0]["output_ref"] == r["output_ref"]
    assert "target" not in recorded[0] and "scope" not in recorded[0]


def test_audit_creation_failure_aborts_tool_before_execution(tmp_path, monkeypatch):
    store, dispatcher, tid = fixture(tmp_path)
    from app.mcp import stubs

    def forbidden(*a):
        raise AssertionError("No tool should execute before audit write")

    monkeypatch.setattr(stubs, "demo_nmap", forbidden)

    def unavailable(*a):
        raise sqlite3.OperationalError("disk unavailable")

    monkeypatch.setattr(store, "begin_tool_run", unavailable)
    result = dispatcher.call("demo.nmap_scan", {"task_id": tid})
    assert result["status"] == "blocked"
    assert result["output_ref"] is None


def test_handoff_after_completed_task_is_sealed_and_private(tmp_path):
    store, dispatcher, tid = fixture(tmp_path)
    assert dispatcher.call("demo.nmap_scan", {"task_id": tid})["status"] == "simulated"
    assert dispatcher.call("demo.httpx_probe", {"task_id": tid, "port": 80})["status"] == "simulated"
    denied = dispatcher.call("local.http_head", {"task_id": tid, "port": 8765})
    assert denied["status"] == "denied"
    store.set_status(tid, "completed", "Demo complete; no real network testing.")
    response = dispatcher.call("workflow.handoff", {"task_id": tid})
    assert response["status"] == "completed"
    assert response["masked"] is True
    assert response["output_ref"].startswith("evidence://")
    rid = response["output_ref"].rsplit("/", 1)[-1]
    raw = dispatcher.vault.verify_and_read(UUID(tid), UUID(rid))["stdout"]
    snapshot = json.loads(raw)
    assert snapshot["task_status"] == "completed"
    assert snapshot["metrics"]["tool_invocations_in_window"] == 3
    assert snapshot["metrics"]["successful_receipts"] == 2
    assert snapshot["metrics"]["blocked_or_denied_receipts"] == 1
    assert snapshot["metrics"]["incomplete_audit_records"] == 0
    assert snapshot["metrics"]["ttfv_seconds"] is None
    assert snapshot["verified_facts"] == []
    assert snapshot["do_not_repeat_without_new_reason"] == ["local.http_head"]
    assert snapshot["cleanup"]["verified"] is False
    assert "127.0.0.1" not in raw.decode()
    assert "scope" not in json.dumps(snapshot).lower()
    assert "No findings verified" in short_handoff(snapshot)
    # Exporting a handoff itself is excluded from subsequent metrics.
    nxt = build_handoff(store, tid)
    assert nxt["metrics"]["tool_invocations_in_window"] == 3


def test_missing_invalid_tasks_do_not_create_checkpoint(tmp_path):
    store, dispatcher, tid = fixture(tmp_path)
    bogus = "00000000-0000-0000-0000-000000000000"
    assert dispatcher.call("workflow.handoff", {"task_id": bogus})["status"] == "denied"
    assert dispatcher.call("workflow.handoff", {"task_id": tid, "path": "/etc/shadow"})["status"] == "denied"
    assert not store.tool_runs(tid)


def test_handoff_cli_from_other_cwd_and_private_file(tmp_path):
    store, dispatcher, tid = fixture(tmp_path)
    dispatcher.call("demo.nmap_scan", {"task_id": tid})
    target_file = tmp_path / "HANDOFF.md"
    p = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "secra_handoff.py"),
        "--data-dir", str(tmp_path), "--task-id", tid,
        "--output", str(target_file),
    ], cwd="/tmp", capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert target_file.exists()
    assert (target_file.stat().st_mode & 0o777) == 0o600
    data = target_file.read_text()
    assert "SIMULATED" not in data  # No raw output or unreviewed claims.
    assert "127.0.0.1" not in data
    assert "evidence://" in data
    # Destination may not be silently overwritten.
    again = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "secra_handoff.py"),
        "--data-dir", str(tmp_path), "--task-id", tid,
        "--output", str(target_file),
    ], capture_output=True, text=True)
    assert again.returncode != 0


def test_legacy_event_without_live_tool_audit_marked_incomplete(tmp_path):
    store, dispatcher, tid = fixture(tmp_path)
    store.append(tid, "tool", "demo.nmap_scan", "done",
                 "Historical demo observation with no instrumented tool audit.")
    snapshot = build_handoff(store, tid)
    assert snapshot["metrics"]["tool_invocations_in_window"] == 0
    assert snapshot["metrics"]["audit_coverage"] == "incomplete_or_unknown"
    assert snapshot["metrics"]["possible_legacy_uninstrumented_tool_events"] == 1
    assert snapshot["metrics"]["ttfv_seconds"] is None
