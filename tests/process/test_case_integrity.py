"""Read-only case-integrity regression: DB, manifest and AES-GCM records."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

from app.evidence_vault import EvidenceVault
from app.loop.case_integrity import check_case
from app.loop.store import TaskStore
from app.workspace import WorkspaceManager

ROOT = Path(__file__).resolve().parents[2]


def prepare(tmp_path):
    store = TaskStore(tmp_path)
    tid = store.create("127.0.0.1", "127.0.0.1/32", mode="local", authorized=True)
    return store, tid


def seal(store, tid, *, tool="local.http_head"):
    vault = EvidenceVault(store.root / "evidence")
    uid = uuid4()
    writer = vault.begin(UUID(tid), uid)
    writer.append("stdout", b"synthetic local test only")
    writer.finish()
    ref = "evidence://" + tid + "/" + str(uid)
    audit = store.begin_tool_run(tid, tool)
    store.finish_tool_run(tid, audit, "completed", 0, 1, ref)
    return uid, ref


def test_empty_case_without_manifest_is_not_falsely_complete(tmp_path):
    store, tid = prepare(tmp_path)
    report = check_case(store, tid)
    assert report["status"] == "review_required"
    assert report["workspace_manifest"] == "unverified_or_missing"
    assert report["archive_includes_task_db"] is False
    assert report["archive_includes_encrypted_vault"] is False
    assert report["finding_validity_proven"] is False
    assert "127.0.0.1" not in json.dumps(report)
    assert not (tmp_path / "evidence").exists()  # read-only audit does not create vault


def test_sealed_receipt_and_manifest_pass_integrity_check(tmp_path):
    store, tid = prepare(tmp_path)
    uid, ref = seal(store, tid)
    WorkspaceManager(tmp_path / "engagements").write_manifest(tid)
    report = check_case(store, tid)
    assert report["status"] == "integrity_ok"
    assert report["evidence_references_checked"] == 1
    assert report["evidence_seals_verified"] == 1
    assert report["evidence_seals_missing_or_corrupt"] == 0
    assert report["tool_audit_unfinished"] == 0
    assert report["workspace_manifest"] == "verified"


def test_corrupt_evidence_or_workspace_drift_requires_review(tmp_path):
    store, tid = prepare(tmp_path)
    uid, ref = seal(store, tid)
    manager = WorkspaceManager(tmp_path / "engagements")
    manager.write_manifest(tid)
    path = tmp_path / "evidence" / "records" / tid / (str(uid) + ".jsonl")
    data = path.read_bytes()
    path.write_bytes(data[:-4] + b"XXX\n")
    report = check_case(store, tid)
    assert report["status"] == "review_required"
    assert report["evidence_seals_missing_or_corrupt"] == 1
    (manager.require(tid) / "01-recon" / "added.txt").write_text("synthetic")
    changed = check_case(store, tid)
    assert changed["workspace_manifest"] == "drift"
    assert changed["workspace_drift_count"] == 1


def test_incomplete_tool_audit_refuses_complete_status(tmp_path):
    store, tid = prepare(tmp_path)
    store.begin_tool_run(tid, "local.http_head")
    WorkspaceManager(tmp_path / "engagements").write_manifest(tid)
    report = check_case(store, tid)
    assert report["tool_audit_unfinished"] == 1
    assert report["status"] == "review_required"


def test_read_only_cli_from_unrelated_working_directory(tmp_path):
    store, tid = prepare(tmp_path)
    WorkspaceManager(tmp_path / "engagements").write_manifest(tid)
    command = [sys.executable, str(ROOT / "scripts" / "secra_casecheck.py"),
               "--data-dir", str(tmp_path), "--task-id", tid, "--strict"]
    run = subprocess.run(command, cwd="/tmp", capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["status"] == "integrity_ok"
    assert "127.0.0.1" not in run.stdout
    (tmp_path / "engagements" / tid / "01-recon" / "note.txt").write_text("changed")
    run = subprocess.run(command, cwd="/tmp", capture_output=True, text=True)
    assert run.returncode == 2
    assert json.loads(run.stdout)["status"] == "review_required"
