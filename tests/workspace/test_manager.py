"""Offline acceptance tests: idempotent workspace creation, privacy and archive."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from app.loop.store import TaskError, TaskStore
from app.workspace import WorkspaceError, WorkspaceManager, DIRS, MANIFEST

ROOT = Path(__file__).resolve().parents[2]


def fixture(tmp_path):
    store = TaskStore(tmp_path)
    tid = store.create("127.0.0.1", "127.0.0.1/32",
                       mode="demo", authorized=True)
    workspace = WorkspaceManager(tmp_path / "engagements")
    return store, workspace, tid


def test_authorized_intake_creates_private_complete_workspace_and_preflight(tmp_path):
    store, work, tid = fixture(tmp_path)
    path = work.require(tid)
    assert path.name == tid
    assert all((path / folder).is_dir() for folder in DIRS)
    assert (path / "engagement.json").is_file()
    assert (path / "05-memory/leads.jsonl").is_file()
    assert (path / "05-memory/negatives.jsonl").is_file()
    assert (path / "07-follow-up/REGISTER.md").is_file()
    preflight = json.loads((path / "00-preflight/local-readiness.json").read_text())
    assert preflight["route_validation"] == "not_performed"
    assert preflight["vpn_validation"] == "not_performed"
    assert preflight["network_connections"] == 0
    assert isinstance(preflight["tool_presence_only"], dict)
    assert len(work.phases(tid)) == 2
    assert work.phases(tid)[0]["stage"] == "intake"
    assert work.phases(tid)[1]["stage"] == "preflight"
    all_text = "\n".join(
        x.read_text(encoding="utf-8")
        for x in path.rglob("*") if x.is_file()
    )
    assert "127.0.0.1" not in all_text
    assert "127.0.0.1/32" not in all_text
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(x.stat().st_mode) == 0o600
               for x in path.rglob("*") if x.is_file())


def test_unauthorized_intake_does_not_create_workspace(tmp_path):
    store = TaskStore(tmp_path)
    with pytest.raises(TaskError, match="WRITTEN_AUTHORIZATION_REQUIRED"):
        store.create("127.0.0.1", "127.0.0.1/32", authorized=False)
    assert not (tmp_path / "engagements").exists()


def test_initialize_is_idempotent_and_preserves_operator_notes(tmp_path):
    _, manager, tid = fixture(tmp_path)
    path = manager.require(tid)
    notes = path / "05-memory/state.json"
    notes.write_text('{"custom":"operator"}\n')
    previous_phases = manager.phases(tid)
    preflight = (path / "00-preflight/local-readiness.json").read_bytes()
    manager.initialize(tid)
    manager.capture_preflight(tid)
    assert notes.read_text() == '{"custom":"operator"}\n'
    assert manager.phases(tid) == previous_phases
    assert (path / "00-preflight/local-readiness.json").read_bytes() == preflight
    assert not (path / "01-recon/01-recon").exists()


def test_manifest_is_single_source_of_truth_and_flags_changes(tmp_path):
    _, manager, tid = fixture(tmp_path)
    initial = manager.write_manifest(tid)
    assert initial["file_count"] >= 10
    assert manager.verify_manifest(tid)["status"] == "verified"
    target = manager.require(tid) / "01-recon/01-summary.txt"
    target.write_text("SAFE SYNTHETIC OBSERVATION\n")
    drift = manager.verify_manifest(tid)
    assert drift["status"] == "drift"
    assert drift["added"] == ["01-recon/01-summary.txt"]
    target.write_text("MODIFIED SYNTHETIC OBSERVATION\n")
    manager.write_manifest(tid)
    assert manager.verify_manifest(tid)["status"] == "verified"
    target.write_text("MODIFIED AGAIN\n")
    assert manager.verify_manifest(tid)["changed"] == ["01-recon/01-summary.txt"]


def test_phase_events_are_actual_utc_timestamps_not_reconstruction(tmp_path):
    _, manager, tid = fixture(tmp_path)
    e = manager.record_phase(tid, "recon", "started")
    assert e["at_utc"].endswith("+00:00")
    assert manager.phases(tid)[-1] == e
    with pytest.raises(WorkspaceError):
        manager.record_phase(tid, "privilege-escalation", "completed")


def test_archive_dry_run_no_writes_and_verified_copy_no_delete(tmp_path):
    _, manager, tid = fixture(tmp_path)
    manager.write_manifest(tid)
    destination = tmp_path / "archive-1"
    before = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    preview = manager.archive(tid, destination)
    after = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    assert preview["status"] == "dry-run"
    assert before == after
    assert not destination.exists()
    copied = manager.archive(tid, destination, dry_run=False)
    assert copied["status"] == "verified-copy"
    assert copied["source_retained"] is True
    assert manager.require(tid).exists()
    assert (destination / "05-memory/state.json").is_file()
    assert (destination / MANIFEST).is_file()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert not (destination / "01-recon/01-recon").exists()


def test_symlinked_workspace_file_denied_before_hashing(tmp_path):
    _, manager, tid = fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("PRIVATE")
    ref = manager.require(tid) / "03-evidence/web/private.txt"
    ref.symlink_to(outside)
    with pytest.raises(WorkspaceError, match="SYMLINK"):
        manager.write_manifest(tid)
    assert outside.read_text() == "PRIVATE"


def test_workspace_cli_runs_from_other_directory(tmp_path):
    _, manager, tid = fixture(tmp_path)
    script = ROOT / "scripts" / "secra_workspace.py"
    common = ["--data-dir", str(tmp_path)]
    status = subprocess.run(
        [sys.executable, str(script), *common, "status", "--task-id", tid],
        cwd="/tmp", capture_output=True, text=True)
    assert status.returncode == 0, status.stderr
    data = json.loads(status.stdout)
    assert data["preflight_recorded"] and data["phase_events"] == 2
    assert "127.0.0.1" not in status.stdout
    manifest = subprocess.run(
        [sys.executable, str(script), *common, "manifest", "--task-id", tid],
        cwd="/tmp", capture_output=True, text=True)
    assert manifest.returncode == 0, manifest.stderr
    check = subprocess.run(
        [sys.executable, str(script), *common, "verify", "--task-id", tid],
        cwd="/tmp", capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    assert json.loads(check.stdout)["status"] == "verified"


def test_failed_archive_staging_is_cleaned_without_publishing(tmp_path, monkeypatch):
    from app import workspace as module
    _, manager, tid = fixture(tmp_path)
    manager.write_manifest(tid)
    target = tmp_path / "archive-should-not-exist"
    real_hash = module._hash_file

    def corrupt_on_copy(path):
        if ".secra-archive-stage-" in str(path):
            raise WorkspaceError("SIMULATED_COPY_FAILURE")
        return real_hash(path)

    monkeypatch.setattr(module, "_hash_file", corrupt_on_copy)
    with pytest.raises(WorkspaceError, match="SIMULATED_COPY_FAILURE"):
        manager.archive(tid, target, dry_run=False)
    assert not target.exists()
    assert not list(tmp_path.glob(".secra-archive-stage-*"))
    assert manager.require(tid).exists()


def test_task_lifecycle_automatically_records_testing_phase_utc(tmp_path):
    store, manager, tid = fixture(tmp_path)
    assert [x["stage"] for x in manager.phases(tid)] == ["intake", "preflight"]
    store.start(tid)
    assert manager.phases(tid)[-1]["stage"] == "testing"
    assert manager.phases(tid)[-1]["event"] == "started"
    store.set_status(tid, "completed", "Synthetic task concluded.")
    latest = manager.phases(tid)[-1]
    assert latest["stage"] == "testing"
    assert latest["event"] == "completed"
    assert latest["at_utc"].endswith("+00:00")


def test_stopped_task_records_blocked_phase_and_retains_workspace(tmp_path):
    store, manager, tid = fixture(tmp_path)
    store.start(tid)
    store.stop(tid)
    assert manager.phases(tid)[-1]["event"] == "blocked"
    assert store.require(tid)["status"] == "stopped"
    assert manager.require(tid).exists()
